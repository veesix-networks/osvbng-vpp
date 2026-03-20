/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Dequeue node
 * INPUT polling node. Checks active schedulers, runs CAKE dequeue algorithm
 * (shaper → tin selection → flow DRR → COBALT AQM), assembles output vector.
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef struct
{
  u32 sw_if_index;
  u32 sojourn_us;
  u8 tin;
  u8 dropped;
  u8 ecn_marked;
} cake_dequeue_trace_t;

static u8 *
format_cake_dequeue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_dequeue_trace_t *t = va_arg (*args, cake_dequeue_trace_t *);

  s = format (s,
	      "CAKE-DEQUEUE: sw_if_index %u, tin %u, sojourn %u us%s%s",
	      t->sw_if_index, t->tin, t->sojourn_us,
	      t->dropped ? " DROPPED" : "",
	      t->ecn_marked ? " ECN-CE" : "");
  return s;
}

/*
 * Select the highest-priority tin that has packets and whose
 * shaper timer has expired. Returns NULL if nothing is ready.
 */
static_always_inline cake_tin_t *
cake_select_tin (cake_sched_t *cs, u64 now_ns)
{
  /* Strict priority: highest tin index = highest priority */
  for (i8 t = cs->tin_cnt - 1; t >= 0; t--)
    {
      cake_tin_t *tin = &cs->tins[t];
      if (tin->new_flow_head == ~0 && tin->old_flow_head == ~0 &&
	  tin->decaying_flow_head == ~0)
	continue; /* no flows in this tin */
      if (now_ns < tin->tin_shaper_time_ns)
	continue; /* tin shaper not ready */
      return tin;
    }
  return NULL;
}

/*
 * Select the next flow from a tin's DRR lists.
 * Priority: decaying → new → old.
 * Returns NULL if no flows have packets.
 */
static_always_inline cake_flow_t *
cake_select_flow (cake_tin_t *tin, u32 *flow_idx_out)
{
  u32 idx;

  /* Check decaying flows first */
  if (tin->decaying_flow_head != ~0)
    {
      idx = tin->decaying_flow_head;
      *flow_idx_out = idx;
      return &tin->flows[idx];
    }

  /* Then new (sparse) flows */
  if (tin->new_flow_head != ~0)
    {
      idx = tin->new_flow_head;
      *flow_idx_out = idx;
      return &tin->flows[idx];
    }

  /* Then old (bulk) flows */
  if (tin->old_flow_head != ~0)
    {
      idx = tin->old_flow_head;
      *flow_idx_out = idx;
      return &tin->flows[idx];
    }

  return NULL;
}

VLIB_NODE_FN (cake_dequeue_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cake_main_t *cm = &cake_main;
  u32 thread_index = vlib_get_thread_index ();
  u32 n_dequeued = 0;

  if (thread_index >= vec_len (cm->per_thread))
    return 0;

  cake_per_thread_t *pt = &cm->per_thread[thread_index];
  if (!pt->active_bitmap)
    return 0;

  u64 now_ns = (u64) (vlib_time_now (vm) * 1e9);
  u32 now_us = (u32) (now_ns / 1000);
  u32 budget = VLIB_FRAME_SIZE;

  u32 *to_next = 0;
  u32 next_index = 0; /* interface-output-arc-end */

  /* Iterate over active schedulers */
  uword si;
  clib_bitmap_foreach (si, pt->active_bitmap)
    {
      if (budget == 0)
	break;

      if (pool_is_free_index (pt->schedulers, si))
	{
	  clib_bitmap_set (pt->active_bitmap, si, 0);
	  continue;
	}

      cake_sched_t *cs = pool_elt_at_index (pt->schedulers, si);

      /* Global shaper check */
      if (now_ns < cs->global_shaper_time_ns)
	continue;

      u32 sched_dequeued = 0;

      while (budget > 0)
	{
	  cake_tin_t *tin = cake_select_tin (cs, now_ns);
	  if (!tin)
	    {
	      /* No ready tins — mark scheduler inactive */
	      clib_bitmap_set (pt->active_bitmap, si, 0);
	      break;
	    }

	  u32 flow_idx;
	  cake_flow_t *flow = cake_select_flow (tin, &flow_idx);
	  if (!flow)
	    break;

	  /* Check if flow has packets */
	  if (flow->head >= vec_len (flow->queue))
	    {
	      /* Flow empty — remove from DRR list, mark NONE */
	      /* TODO: proper list removal and state transition */
	      flow->flow_state = CAKE_FLOW_NONE;
	      if (tin->new_flow_head == flow_idx)
		tin->new_flow_head = flow->next;
	      if (tin->old_flow_head == flow_idx)
		tin->old_flow_head = flow->next;
	      if (flow->next != ~0)
		tin->flows[flow->next].prev = flow->prev;
	      if (flow->prev != ~0)
		tin->flows[flow->prev].next = flow->next;
	      flow->next = ~0;
	      flow->prev = ~0;
	      vec_reset_length (flow->queue);
	      flow->head = 0;
	      flow->tail = 0;
	      tin->sparse_flow_count--;
	      continue;
	    }

	  /* Dequeue one packet */
	  u32 bi = flow->queue[flow->head];
	  flow->head++;

	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);

	  /* COBALT AQM check */
	  u32 enqueue_us = vnet_buffer2 (b)->qos.bits;
	  u32 sojourn_us = now_us - enqueue_us;
	  u8 should_drop = 0;
	  u8 ecn_marked = 0;

	  /* CoDel: drop if sojourn exceeds target for longer than interval */
	  if (sojourn_us > cs->target_us)
	    {
	      if (flow->codel_dropping)
		{
		  if (now_us >= flow->codel_drop_next_us)
		    {
		      should_drop = 1;
		      flow->codel_count++;
		      /* Schedule next drop: interval / sqrt(count) */
		      /* TODO: use rec_inv_sqrt for efficient calculation */
		      flow->codel_drop_next_us =
			now_us + cs->interval_us / (flow->codel_count + 1);
		    }
		}
	      else
		{
		  /* Enter dropping state after interval */
		  flow->codel_dropping = 1;
		  flow->codel_count = 1;
		  flow->codel_drop_next_us = now_us + cs->interval_us;
		}
	    }
	  else
	    {
	      flow->codel_dropping = 0;
	      flow->codel_count = 0;
	    }

	  /* BLUE: probabilistic drop for unresponsive flows */
	  if (!should_drop && flow->blue_drop_prob > 0)
	    {
	      /* TODO: proper random number generation */
	      u16 rand = (u16) (now_us ^ bi);
	      if (rand < flow->blue_drop_prob)
		should_drop = 1;
	    }

	  /* ECN marking instead of drop for ECN-capable packets (IPv4 + IPv6) */
	  if (should_drop)
	    {
	      void *ip_hdr = vlib_buffer_get_current (b);
	      u8 version = ((u8 *) ip_hdr)[0] >> 4;
	      u8 ecn_bits = 0;

	      if (version == 4)
		ecn_bits = cake_ecn_from_ip4 ((ip4_header_t *) ip_hdr);
	      else if (version == 6)
		ecn_bits = cake_ecn_from_ip6 ((ip6_header_t *) ip_hdr);

	      if (ecn_bits == IP_ECN_ECT0 || ecn_bits == IP_ECN_ECT1)
		{
		  /* ECT(0) or ECT(1) — mark CE instead of drop */
		  if (version == 4)
		    cake_set_ecn_ce_ip4 ((ip4_header_t *) ip_hdr);
		  else
		    cake_set_ecn_ce_ip6 ((ip6_header_t *) ip_hdr);
		  ecn_marked = 1;
		  should_drop = 0;
		  tin->ecn_marks++;
		  node->errors[CAKE_ERROR_ECN_MARKED]++;
		}
	    }

	  if (should_drop)
	    {
	      vlib_buffer_free_one (vm, bi);
	      flow->backlog_bytes -= pkt_len;
	      cs->buffer_usage -= pkt_len;
	      tin->drops++;
	      node->errors[CAKE_ERROR_DROPPED_AQM]++;
	      continue;
	    }

	  /* Update shaper timestamps */
	  u32 adj_len = cake_overhead_adjust (cs, pkt_len);
	  cs->global_shaper_time_ns += (u64) adj_len * cs->rate_ns_per_byte;
	  tin->tin_shaper_time_ns +=
	    (u64) adj_len * tin->tin_rate_ns_per_byte;

	  /* Failsafe: clamp shaper to prevent drift */
	  u64 max_shaper = now_ns + (u64) cs->interval_us * 1500;
	  if (cs->global_shaper_time_ns > max_shaper)
	    cs->global_shaper_time_ns = max_shaper;

	  /* Deficit accounting */
	  flow->deficit -= (i32) adj_len;
	  if (flow->deficit <= 0)
	    {
	      flow->deficit += (i32) tin->flow_quantum;
	      /* TODO: move flow to end of DRR list */
	    }

	  /* Update bookkeeping */
	  flow->backlog_bytes -= pkt_len;
	  cs->buffer_usage -= pkt_len;
	  tin->packets++;
	  tin->bytes += pkt_len;

	  /* Update delay stats */
	  if (sojourn_us > tin->peak_queue_delay_us)
	    tin->peak_queue_delay_us = sojourn_us;
	  /* Exponential moving average */
	  tin->avg_queue_delay_us =
	    (tin->avg_queue_delay_us * 7 + sojourn_us) / 8;

	  /* Enqueue to output */
	  u32 n_left_to_next;
	  vlib_get_next_frame (vm, node, next_index, to_next,
			       n_left_to_next);
	  to_next[0] = bi;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

	  sched_dequeued++;
	  n_dequeued++;
	  budget--;
	  node->errors[CAKE_ERROR_DEQUEUED]++;

	  /* Check global shaper after each packet */
	  if (now_ns < cs->global_shaper_time_ns)
	    break;
	}

      cs->last_dequeue_time_ns = now_ns;
    }

  return n_dequeued;
}

VLIB_REGISTER_NODE (cake_dequeue_node) = {
  .name = "cake-dequeue",
  .vector_size = sizeof (u32),
  .format_trace = format_cake_dequeue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "interface-output-arc-end",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
