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
 *   5. Determine IP version from packet, re-start the correct
 *      ip4-output or ip6-output feature arc via vnet_feature_arc_start().
 *   6. Bulk-enqueue buffers to ip4/ip6-cake-enqueue nodes.
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

      u32 sched_dequeued = 0;

      while (budget > 0)
	{
	  if (cs->queue_head >= vec_len (cs->queue))
	    {
	      vec_reset_length (cs->queue);
	      cs->queue_head = 0;
	      deactivate[n_deactivate++] = si;
	      break;
	    }

	  u32 bi = cs->queue[cs->queue_head];
	  cs->queue_head++;

	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);

	  u32 adj_len = cake_overhead_adjust (cs, pkt_len);
	  cs->global_shaper_time_ns += (u64) adj_len * cs->rate_ns_per_byte;

	  u64 max_shaper = now_ns + (u64) 150000000;
	  if (cs->global_shaper_time_ns > max_shaper)
	    cs->global_shaper_time_ns = max_shaper;

	  cs->buffer_usage -= pkt_len;
	  cs->queued_buffers--;
	  cs->dequeued_pkts++;
	  cs->dequeued_bytes += pkt_len;
	  sched_dequeued++;

	  b->flags |= CAKE_BUFFER_F_SCHEDULED;

	  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
	  u32 dummy_next;

	  u8 *ip_hdr = vlib_buffer_get_current (b);
	  u8 is_ip4 = (ip_hdr[0] >> 4) == 4;

	  if (is_ip4)
	    {
	      vnet_feature_arc_start (cm->ip4_output_arc_index, sw_if_index,
				      &dummy_next, b);
	      out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP4;
	    }
	  else
	    {
	      vnet_feature_arc_start (cm->ip6_output_arc_index, sw_if_index,
				      &dummy_next, b);
	      out_nexts[n_out] = CAKE_DEQUEUE_NEXT_REINJECT_IP6;
	    }

	  out_bi[n_out] = bi;
	  n_out++;
	  budget--;

	  if (now_ns < cs->global_shaper_time_ns)
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
