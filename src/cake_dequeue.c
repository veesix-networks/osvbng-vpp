/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Dequeue node
 * VLIB_NODE_TYPE_INPUT polling node.
 *
 * Phase 2: DRR scheduling across per-flow queues.
 * Three lists: new (sparse), old (bulk), decaying.
 * Sparse flows get immediate service without deficit accounting.
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef enum
{
  CAKE_DEQUEUE_NEXT_REINJECT_IP4,
  CAKE_DEQUEUE_NEXT_REINJECT_IP6,
  CAKE_DEQUEUE_N_NEXT,
} cake_dequeue_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 n_dequeued;
  u32 flow_idx;
} cake_dequeue_trace_t;

static u8 *
format_cake_dequeue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_dequeue_trace_t *t = va_arg (*args, cake_dequeue_trace_t *);

  s = format (s, "CAKE-DEQUEUE: sw_if_index %u flow %u dequeued %u",
	      t->sw_if_index, t->flow_idx, t->n_dequeued);
  return s;
}

static_always_inline u32
cake_flow_queue_len (cake_flow_t *f)
{
  if (!f->queue)
    return 0;
  u32 len = vec_len (f->queue);
  return len > f->head ? len - f->head : 0;
}

static_always_inline void
cake_flow_reclaim (cake_tin_t *tin, u32 flow_idx, u32 *list_head)
{
  cake_flow_t *f = &tin->flows[flow_idx];

  cake_flow_list_remove (list_head, tin->flows, flow_idx);

  if (f->queue)
    {
      vec_free (f->queue);
      f->queue = NULL;
    }

  if (f->flow_state == CAKE_FLOW_SPARSE)
    tin->sparse_flow_count--;
  else if (f->flow_state == CAKE_FLOW_BULK)
    tin->bulk_flow_count--;

  tin->flow_tags[flow_idx] = 0;
  f->flow_state = CAKE_FLOW_NONE;
  f->head = 0;
  f->backlog_bytes = 0;
  f->deficit = 0;
  f->next = ~0;
  f->prev = ~0;
  tin->flow_count--;
}

static_always_inline u32
cake_select_flow (cake_tin_t *tin)
{
  if (tin->new_flow_head != ~0)
    return tin->new_flow_head;
  if (tin->old_flow_head != ~0)
    return tin->old_flow_head;
  if (tin->decaying_flow_head != ~0)
    return tin->decaying_flow_head;
  return ~0;
}

VLIB_NODE_FN (cake_dequeue_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cake_main_t *cm = &cake_main;
  u32 thread_index = vm->thread_index;

  if (PREDICT_FALSE (thread_index >= vec_len (cm->per_thread)))
    return 0;

  cake_per_thread_t *pt = vec_elt_at_index (cm->per_thread, thread_index);
  if (PREDICT_FALSE (clib_bitmap_is_zero (pt->active_bitmap)))
    return 0;

  f64 now = vlib_time_now (vm);
  u64 now_ns = (u64) (now * 1e9);
  u32 budget = VLIB_FRAME_SIZE;

  u32 out_bi[VLIB_FRAME_SIZE];
  u16 out_nexts[VLIB_FRAME_SIZE];
  u32 n_out = 0;

  u32 deactivate[VLIB_FRAME_SIZE];
  u32 n_deactivate = 0;

  uword si;
  clib_bitmap_foreach (si, pt->active_bitmap)
    {
      if (budget == 0)
	break;

      if (PREDICT_FALSE (pool_is_free_index (cm->schedulers, si)))
	{
	  deactivate[n_deactivate++] = si;
	  continue;
	}

      cake_sched_t *cs = pool_elt_at_index (cm->schedulers, si);

      if (now_ns < cs->global_shaper_time_ns)
	continue;

      cake_tin_t *tin = &cs->tin;
      u32 sched_dequeued = 0;
      u32 last_flow_idx = ~0;

      while (budget > 0)
	{
	  u32 flow_idx = cake_select_flow (tin);
	  if (flow_idx == ~0)
	    {
	      deactivate[n_deactivate++] = si;
	      break;
	    }

	  cake_flow_t *flow = &tin->flows[flow_idx];
	  last_flow_idx = flow_idx;

	  if (flow->flow_state == CAKE_FLOW_SPARSE)
	    {
	      if (cake_flow_queue_len (flow) == 0)
		{
		  cake_flow_reclaim (tin, flow_idx, &tin->new_flow_head);
		  continue;
		}

	      u32 bi = flow->queue[flow->head++];
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      u32 pkt_len = vlib_buffer_length_in_chain (vm, b);
	      u32 adj_len = cake_overhead_adjust (cs, pkt_len);

	      cs->global_shaper_time_ns +=
		(u64) adj_len * cs->rate_ns_per_byte;
	      u64 max_shaper = now_ns + (u64) 150000000;
	      if (cs->global_shaper_time_ns > max_shaper)
		cs->global_shaper_time_ns = max_shaper;

	      flow->backlog_bytes -= pkt_len;
	      cs->buffer_usage -= pkt_len;
	      cs->queued_buffers--;
	      cs->dequeued_pkts++;
	      cs->dequeued_bytes += pkt_len;
	      sched_dequeued++;

	      if (cake_flow_queue_len (flow) == 0)
		cake_flow_reclaim (tin, flow_idx, &tin->new_flow_head);

	      b->flags |= CAKE_BUFFER_F_SCHEDULED;
	      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	      u32 dummy;
	      u8 *ip_hdr = vlib_buffer_get_current (b);
	      u8 is_v4 = (ip_hdr[0] >> 4) == 4;

	      if (is_v4)
		{
		  vnet_feature_arc_start (cm->ip4_output_arc_index,
					  sw_if_index, &dummy, b);
		  out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP4;
		}
	      else
		{
		  vnet_feature_arc_start (cm->ip6_output_arc_index,
					  sw_if_index, &dummy, b);
		  out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP6;
		}

	      out_bi[n_out++] = bi;
	      budget--;

	      if (now_ns < cs->global_shaper_time_ns)
		break;
	      continue;
	    }

	  /* Bulk / old / decaying flow: deficit-based dequeue */
	  flow->deficit += tin->quantum;

	  while (flow->deficit > 0 && budget > 0)
	    {
	      if (cake_flow_queue_len (flow) == 0)
		{
		  if (flow->flow_state == CAKE_FLOW_BULK)
		    {
		      flow->flow_state = CAKE_FLOW_DECAYING;
		      cake_flow_list_remove (&tin->old_flow_head, tin->flows,
					     flow_idx);
		      cake_flow_list_append (&tin->decaying_flow_head,
					     tin->flows, flow_idx);
		      tin->bulk_flow_count--;
		    }
		  else if (flow->flow_state == CAKE_FLOW_DECAYING)
		    {
		      cake_flow_reclaim (tin, flow_idx,
					 &tin->decaying_flow_head);
		    }
		  break;
		}

	      u32 bi = flow->queue[flow->head++];
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	      u32 pkt_len = vlib_buffer_length_in_chain (vm, b);
	      u32 adj_len = cake_overhead_adjust (cs, pkt_len);

	      cs->global_shaper_time_ns +=
		(u64) adj_len * cs->rate_ns_per_byte;
	      u64 max_shaper = now_ns + (u64) 150000000;
	      if (cs->global_shaper_time_ns > max_shaper)
		cs->global_shaper_time_ns = max_shaper;

	      flow->deficit -= (i32) adj_len;
	      flow->backlog_bytes -= pkt_len;
	      cs->buffer_usage -= pkt_len;
	      cs->queued_buffers--;
	      cs->dequeued_pkts++;
	      cs->dequeued_bytes += pkt_len;
	      sched_dequeued++;

	      b->flags |= CAKE_BUFFER_F_SCHEDULED;
	      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	      u32 dummy;
	      u8 *ip_hdr = vlib_buffer_get_current (b);
	      u8 is_v4 = (ip_hdr[0] >> 4) == 4;

	      if (is_v4)
		{
		  vnet_feature_arc_start (cm->ip4_output_arc_index,
					  sw_if_index, &dummy, b);
		  out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP4;
		}
	      else
		{
		  vnet_feature_arc_start (cm->ip6_output_arc_index,
					  sw_if_index, &dummy, b);
		  out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP6;
		}

	      out_bi[n_out++] = bi;
	      budget--;

	      if (now_ns < cs->global_shaper_time_ns)
		goto shaper_exhausted;
	    }

	  /* Deficit exhausted or queue empty: rotate to next flow */
	  if (flow->deficit <= 0 && flow->flow_state == CAKE_FLOW_BULK &&
	      cake_flow_queue_len (flow) > 0)
	    {
	      cake_flow_list_remove (&tin->old_flow_head, tin->flows,
				     flow_idx);
	      cake_flow_list_append (&tin->old_flow_head, tin->flows,
				     flow_idx);
	      flow->deficit = 0;
	    }

	  /* Compact drained flow queue */
	  if (flow->queue && flow->head > 0 &&
	      cake_flow_queue_len (flow) == 0)
	    {
	      vec_reset_length (flow->queue);
	      flow->head = 0;
	    }

	  continue;

	shaper_exhausted:
	  if (flow->queue && flow->head > 0 &&
	      cake_flow_queue_len (flow) == 0)
	    {
	      vec_reset_length (flow->queue);
	      flow->head = 0;
	    }
	  break;
	}

      if (sched_dequeued > 0
	  && PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, out_bi[n_out - 1]);
	  cake_dequeue_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = cs->sw_if_index;
	  t->n_dequeued = sched_dequeued;
	  t->flow_idx = last_flow_idx;
	}
    }

  for (u32 i = 0; i < n_deactivate; i++)
    pt->active_bitmap =
      clib_bitmap_set (pt->active_bitmap, deactivate[i], 0);

  if (n_out > 0)
    vlib_buffer_enqueue_to_next (vm, node, out_bi, out_nexts, n_out);

  vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_DEQUEUED,
			       n_out);

  return n_out;
}

VLIB_REGISTER_NODE (cake_dequeue_node) = {
  .name = "cake-dequeue",
  .vector_size = sizeof (u32),
  .format_trace = format_cake_dequeue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = CAKE_DEQUEUE_N_NEXT,
  .next_nodes = {
    [CAKE_DEQUEUE_NEXT_REINJECT_IP4] = "ip4-cake-enqueue",
    [CAKE_DEQUEUE_NEXT_REINJECT_IP6] = "ip6-cake-enqueue",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
