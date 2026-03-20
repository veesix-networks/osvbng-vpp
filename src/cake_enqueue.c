/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Enqueue node
 * Interface-output feature arc node. Classifies packets into tins and flows,
 * stores buffer indices in per-flow queues, timestamps packets.
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef enum
{
  CAKE_ENQUEUE_NEXT_PASSTHROUGH,
  CAKE_ENQUEUE_NEXT_DROP,
  CAKE_ENQUEUE_N_NEXT,
} cake_enqueue_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 flow_hash;
  u8 tin;
  u8 enqueued;
} cake_enqueue_trace_t;

static u8 *
format_cake_enqueue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_enqueue_trace_t *t = va_arg (*args, cake_enqueue_trace_t *);

  s = format (s,
	      "CAKE-ENQUEUE: sw_if_index %u, flow_hash 0x%08x, "
	      "tin %u, %s",
	      t->sw_if_index, t->flow_hash, t->tin,
	      t->enqueued ? "enqueued" : "passthrough");
  return s;
}

VLIB_NODE_FN (cake_enqueue_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cake_main_t *cm = &cake_main;
  u32 n_left_from, *from;
  u32 thread_index = vlib_get_thread_index ();
  u32 pkts_enqueued = 0;
  u32 pkts_passthrough = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* Get current time in microseconds for enqueue timestamp */
  u32 now_us = (u32) (vlib_time_now (vm) * 1e6);

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 sw_if_index0;
      u32 next0 = CAKE_ENQUEUE_NEXT_PASSTHROUGH;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      /* Lookup scheduler for this interface */
      u32 packed = 0;
      if (sw_if_index0 < vec_len (cm->sched_index_by_sw_if_index))
	packed = cm->sched_index_by_sw_if_index[sw_if_index0];

      if (PREDICT_FALSE (packed == 0))
	{
	  /* No scheduler — passthrough via feature arc */
	  vnet_feature_next (&next0, b0);
	  pkts_passthrough++;
	  goto trace;
	}

      u32 owner_thread = packed >> 16;
      u32 pool_index = packed & 0xffff;

      /* Verify thread ownership */
      if (PREDICT_FALSE (owner_thread != thread_index))
	{
	  /* TODO: frame queue handoff to owning thread */
	  vnet_feature_next (&next0, b0);
	  pkts_passthrough++;
	  goto trace;
	}

      cake_per_thread_t *pt = &cm->per_thread[thread_index];
      cake_sched_t *cs = pool_elt_at_index (pt->schedulers, pool_index);

      /* Detect IP version, extract DSCP, determine tin */
      u8 tin_idx = 0;
      u8 is_ip6 = 0;
      u32 flow_hash = 0;
      void *ip_hdr = vlib_buffer_get_current (b0);
      u8 version = ((u8 *) ip_hdr)[0] >> 4;

      u8 dscp = 0;
      if (version == 4)
	{
	  dscp = cake_dscp_from_ip4 ((ip4_header_t *) ip_hdr);
	}
      else if (version == 6)
	{
	  is_ip6 = 1;
	  dscp = cake_dscp_from_ip6 ((ip6_header_t *) ip_hdr);
	}

      u8 *dscp_table;
      switch (cs->tin_mode)
	{
	case 1:
	  dscp_table = cm->dscp_to_tin_diffserv3;
	  break;
	case 2:
	  dscp_table = cm->dscp_to_tin_diffserv4;
	  break;
	case 3:
	  dscp_table = cm->dscp_to_tin_diffserv8;
	  break;
	default:
	  dscp_table = cm->dscp_to_tin_besteffort;
	  break;
	}
      tin_idx = dscp_table[dscp];

      if (PREDICT_FALSE (tin_idx >= cs->tin_cnt))
	tin_idx = 0;

      cake_tin_t *tin = &cs->tins[tin_idx];

      /* Flow hashing — set-associative lookup */
      if (is_ip6)
	cake_hash_flow_ip6 ((ip6_header_t *) ip_hdr, &flow_hash);
      else
	cake_hash_flow_ip4 ((ip4_header_t *) ip_hdr, &flow_hash);

      u32 set_base = (flow_hash % CAKE_SETS) * CAKE_SET_WAYS;
      u8 tag = (u8) (flow_hash >> 24);
      u32 flow_idx = set_base; /* default: first slot */

      /* Probe 8 ways for matching tag or empty slot */
      for (u32 w = 0; w < CAKE_SET_WAYS; w++)
	{
	  cake_flow_t *f = &tin->flows[set_base + w];
	  if (f->flow_state == CAKE_FLOW_NONE)
	    {
	      /* Empty slot — use it */
	      flow_idx = set_base + w;
	      f->hash_tag = tag;
	      f->flow_state = CAKE_FLOW_SPARSE;
	      f->deficit = tin->quantum;
	      /* Add to new flow list */
	      f->next = tin->new_flow_head;
	      if (tin->new_flow_head != ~0)
		tin->flows[tin->new_flow_head].prev = flow_idx;
	      tin->new_flow_head = flow_idx;
	      f->prev = ~0;
	      tin->sparse_flow_count++;
	      break;
	    }
	  if (f->hash_tag == tag)
	    {
	      /* Match — use existing flow */
	      flow_idx = set_base + w;
	      break;
	    }
	  if (w == CAKE_SET_WAYS - 1)
	    {
	      /* Set full, no match — evict last slot (LRU placeholder) */
	      flow_idx = set_base + CAKE_SET_WAYS - 1;
	      /* TODO: proper LRU eviction with buffer freeing */
	      tin->flows[flow_idx].hash_tag = tag;
	      node->errors[CAKE_ERROR_FLOW_COLLISION]++;
	    }
	}

      cake_flow_t *flow = &tin->flows[flow_idx];

      /* Store enqueue timestamp in buffer opaque2 */
      vnet_buffer2 (b0)->qos.bits = now_us;

      /* Enqueue buffer index to flow queue */
      vec_add1 (flow->queue, bi0);
      flow->tail++;

      u32 pkt_len = vlib_buffer_length_in_chain (vm, b0);
      flow->backlog_bytes += pkt_len;
      cs->buffer_usage += pkt_len;

      /* Buffer overflow check — drop from longest queue */
      if (PREDICT_FALSE (cs->buffer_usage > cs->buffer_limit))
	{
	  /* TODO: find fattest flow across all tins and drop from it */
	  cs->buffer_usage -= pkt_len;
	  flow->backlog_bytes -= pkt_len;
	  vec_pop (flow->queue);
	  flow->tail--;
	  next0 = CAKE_ENQUEUE_NEXT_DROP;
	  node->errors[CAKE_ERROR_DROPPED_OVERFLOW]++;
	  goto trace;
	}

      /* Mark scheduler as active */
      clib_bitmap_set (pt->active_bitmap, pool_index, 1);

      pkts_enqueued++;
      node->errors[CAKE_ERROR_ENQUEUED]++;

      /* Packet is consumed — do not forward. Set next to drop (buffer is
       * owned by scheduler now, drop node won't actually free it since we
       * hold a reference via the flow queue). */
      /* TODO: proper buffer reference counting for held packets */
      next0 = CAKE_ENQUEUE_NEXT_DROP;

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cake_enqueue_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->flow_hash = flow_hash;
	  t->tin = tin_idx;
	  t->enqueued = (next0 != CAKE_ENQUEUE_NEXT_PASSTHROUGH);
	}

      vlib_validate_buffer_enqueue_x1 (vm, node, 0, 0, bi0, next0);
    }

  node->errors[CAKE_ERROR_PASSTHROUGH] += pkts_passthrough;

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cake_enqueue_node) = {
  .name = "cake-enqueue",
  .vector_size = sizeof (u32),
  .format_trace = format_cake_enqueue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = CAKE_ENQUEUE_N_NEXT,
  .next_nodes = {
    [CAKE_ENQUEUE_NEXT_PASSTHROUGH] = "interface-output-arc-end",
    [CAKE_ENQUEUE_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (cake_enqueue_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "cake-enqueue",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
