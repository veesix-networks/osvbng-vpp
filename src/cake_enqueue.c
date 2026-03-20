/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Enqueue node
 * Interface-output feature arc node.
 *
 * Two roles:
 *   1. Fresh packets (no SCHEDULED flag): look up scheduler, store buffer
 *      in FIFO, consume (do NOT forward to any next node).
 *   2. Re-injected packets (SCHEDULED flag set by dequeue): clear flag,
 *      call vnet_feature_next() to continue through remaining output
 *      features (span, ipsec, arc-end, TX).
 *
 * Buffer ownership invariant: enqueue CONSUMES the buffer. The scheduler
 * is the sole owner from that point. Buffers are freed in exactly one of:
 *   - dequeue transmit (re-injection)
 *   - buffer overflow drop (vlib_buffer_free_one here)
 *   - subscriber teardown (drain all queues in disable path)
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef struct
{
  u32 sw_if_index;
  u8 enqueued;
  u8 scheduled;
} cake_enqueue_trace_t;

static u8 *
format_cake_enqueue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_enqueue_trace_t *t = va_arg (*args, cake_enqueue_trace_t *);

  s = format (s, "CAKE-ENQUEUE: sw_if_index %u, %s", t->sw_if_index,
	      t->scheduled ? "scheduled-passthrough" :
	      t->enqueued  ? "enqueued" :
			     "passthrough");
  return s;
}

VLIB_NODE_FN (cake_enqueue_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cake_main_t *cm = &cake_main;
  u32 thread_index = vm->thread_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  /*
   * Passthrough buffers: collected here, then bulk-enqueued to their
   * feature-arc next nodes after the main loop.
   */
  u32 pass_bi[VLIB_FRAME_SIZE];
  u16 pass_nexts[VLIB_FRAME_SIZE];
  u32 n_pass = 0;

  u32 n_enqueued = 0;
  u32 n_dropped = 0;

  while (n_left > 0)
    {
      u32 bi0 = from[0];
      from++;
      n_left--;

      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

      /*
       * Re-injected packet: dequeue node set CAKE_BUFFER_F_SCHEDULED
       * and re-started the feature arc. Clear the flag and continue
       * through remaining output features.
       */
      if (PREDICT_FALSE (b0->flags & CAKE_BUFFER_F_SCHEDULED))
	{
	  b0->flags &= ~CAKE_BUFFER_F_SCHEDULED;
	  u32 next0;
	  vnet_feature_next (&next0, b0);
	  pass_bi[n_pass] = bi0;
	  pass_nexts[n_pass] = (u16) next0;
	  n_pass++;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      cake_enqueue_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->enqueued = 0;
	      t->scheduled = 1;
	    }
	  continue;
	}

      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      /* Look up scheduler for this interface */
      u32 si = ~0;
      if (sw_if_index0 < vec_len (cm->sched_index_by_sw_if_index))
	si = cm->sched_index_by_sw_if_index[sw_if_index0];

      if (PREDICT_TRUE (si == ~0))
	{
	  /* No scheduler — passthrough via feature arc */
	  u32 next0;
	  vnet_feature_next (&next0, b0);
	  pass_bi[n_pass] = bi0;
	  pass_nexts[n_pass] = (u16) next0;
	  n_pass++;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      cake_enqueue_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->enqueued = 0;
	      t->scheduled = 0;
	    }
	  continue;
	}

      cake_sched_t *cs = pool_elt_at_index (cm->schedulers, si);
      u32 pkt_len = vlib_buffer_length_in_chain (vm, b0);

      /* Admission control: tail drop if buffer limit exceeded */
      if (PREDICT_FALSE (cs->buffer_usage + pkt_len > cs->buffer_limit))
	{
	  vlib_buffer_free_one (vm, bi0);
	  cs->dropped_pkts++;
	  n_dropped++;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      cake_enqueue_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->enqueued = 0;
	      t->scheduled = 0;
	    }
	  continue;
	}

      /*
       * Consume: store buffer index in the scheduler's FIFO.
       * The buffer is NOT forwarded to any next node — the scheduler
       * is now the sole owner.
       */
      vec_add1 (cs->queue, bi0);
      cs->buffer_usage += pkt_len;
      cs->queued_buffers++;
      cs->enqueued_pkts++;
      cs->enqueued_bytes += pkt_len;
      n_enqueued++;

      /* Mark scheduler as active on this thread */
      if (thread_index < vec_len (cm->per_thread))
	{
	  cake_per_thread_t *pt =
	    vec_elt_at_index (cm->per_thread, thread_index);
	  pt->active_bitmap =
	    clib_bitmap_set (pt->active_bitmap, cs->sched_index, 1);
	}

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cake_enqueue_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->enqueued = 1;
	  t->scheduled = 0;
	}
    }

  /* Bulk-forward all passthrough buffers to their feature-arc next nodes */
  if (n_pass > 0)
    vlib_buffer_enqueue_to_next (vm, node, pass_bi, pass_nexts, n_pass);

  vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_ENQUEUED,
			       n_enqueued);
  vlib_node_increment_counter (vm, node->node_index,
			       CAKE_ERROR_DROPPED_OVERFLOW, n_dropped);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cake_enqueue_node) = {
  .name = "cake-enqueue",
  .vector_size = sizeof (u32),
  .format_trace = format_cake_enqueue_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = 0,
  /* No static next nodes — passthrough uses dynamically-added feature arc
   * next nodes via vnet_feature_next(). Consumed buffers are not forwarded
   * to any next node. */
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
