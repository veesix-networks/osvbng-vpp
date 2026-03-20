/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Dequeue node
 * VLIB_NODE_TYPE_INPUT polling node.
 *
 * Starts VLIB_NODE_STATE_DISABLED. Switched to POLLING when the first
 * scheduler is enabled, back to DISABLED when the last is removed.
 * Zero dispatch overhead when unused.
 *
 * On each dispatch:
 *   1. Iterate active schedulers (from per-thread active_bitmap).
 *   2. Check global shaper time — skip if not ready.
 *   3. Dequeue from FIFO, charge shaper, collect buffer indices.
 *   4. Set CAKE_BUFFER_F_SCHEDULED flag on each buffer.
 *   5. Re-start the interface-output feature arc on each buffer via
 *      vnet_feature_arc_start() — this sets up current_config_index
 *      so cake-enqueue can call vnet_feature_next() on the second pass.
 *   6. Bulk-enqueue all collected buffers to cake-enqueue node.
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef enum
{
  CAKE_DEQUEUE_NEXT_REINJECT, /* → cake-enqueue (for re-injection) */
  CAKE_DEQUEUE_N_NEXT,
} cake_dequeue_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 n_dequeued;
} cake_dequeue_trace_t;

static u8 *
format_cake_dequeue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_dequeue_trace_t *t = va_arg (*args, cake_dequeue_trace_t *);

  s = format (s, "CAKE-DEQUEUE: sw_if_index %u, dequeued %u", t->sw_if_index,
	      t->n_dequeued);
  return s;
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

  /* Collect dequeued buffer indices for batched re-injection */
  u32 out_bi[VLIB_FRAME_SIZE];
  u32 n_out = 0;

  /* Interface-output feature arc index for re-injection */
  vnet_interface_main_t *im = &vnet_get_main ()->interface_main;
  u8 arc = im->output_feature_arc_index;

  /* Schedulers to deactivate after iteration */
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

      /* Global shaper check: skip if not ready to transmit */
      if (now_ns < cs->global_shaper_time_ns)
	continue;

      u32 sched_dequeued = 0;

      while (budget > 0)
	{
	  /* Check if FIFO has packets */
	  if (cs->queue_head >= vec_len (cs->queue))
	    {
	      /* Queue drained — compact and deactivate */
	      vec_reset_length (cs->queue);
	      cs->queue_head = 0;
	      deactivate[n_deactivate++] = si;
	      break;
	    }

	  /* Dequeue one packet */
	  u32 bi = cs->queue[cs->queue_head];
	  cs->queue_head++;

	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);

	  /* Charge the shaper: overhead-adjusted cost in nanoseconds */
	  u32 adj_len = cake_overhead_adjust (cs, pkt_len);
	  cs->global_shaper_time_ns += (u64) adj_len * cs->rate_ns_per_byte;

	  /* Failsafe: clamp shaper to prevent runaway drift.
	   * Max 150ms into the future (1.5 × CoDel default interval). */
	  u64 max_shaper = now_ns + (u64) 150000000;
	  if (cs->global_shaper_time_ns > max_shaper)
	    cs->global_shaper_time_ns = max_shaper;

	  /* Update bookkeeping */
	  cs->buffer_usage -= pkt_len;
	  cs->queued_buffers--;
	  cs->dequeued_pkts++;
	  cs->dequeued_bytes += pkt_len;
	  sched_dequeued++;

	  /*
	   * Re-injection setup:
	   * 1. Set SCHEDULED flag so enqueue node knows to passthrough.
	   * 2. Re-start the feature arc on this buffer. This sets
	   *    feature_arc_index and current_config_index so that when
	   *    cake-enqueue calls vnet_feature_next(), it advances to
	   *    the next feature AFTER cake-enqueue (e.g., span-output,
	   *    ipsec-if-output, interface-output-arc-end).
	   *    The feature config is always live at transmission time,
	   *    not stale from the original enqueue.
	   */
	  b->flags |= CAKE_BUFFER_F_SCHEDULED;

	  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	  u32 dummy_next;
	  vnet_feature_arc_start (arc, sw_if_index, &dummy_next, b);

	  out_bi[n_out++] = bi;
	  budget--;

	  /* Shaper says stop after this packet */
	  if (now_ns < cs->global_shaper_time_ns)
	    break;
	}

      if (sched_dequeued > 0
	  && PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  /* Add a single trace entry per scheduler per dispatch */
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, out_bi[n_out - 1]);
	  cake_dequeue_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = cs->sw_if_index;
	  t->n_dequeued = sched_dequeued;
	}
    }

  /* Deactivate drained or freed schedulers */
  for (u32 i = 0; i < n_deactivate; i++)
    pt->active_bitmap =
      clib_bitmap_set (pt->active_bitmap, deactivate[i], 0);

  /*
   * Batch re-inject: send all dequeued buffers to cake-enqueue node.
   * This is a single vlib_get_next_frame / vlib_put_next_frame under
   * the hood — per-packet frame acquisition is prohibited (Decision #8).
   */
  if (n_out > 0)
    vlib_buffer_enqueue_to_single_next (vm, node, out_bi,
					CAKE_DEQUEUE_NEXT_REINJECT, n_out);

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
    [CAKE_DEQUEUE_NEXT_REINJECT] = "cake-enqueue",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
