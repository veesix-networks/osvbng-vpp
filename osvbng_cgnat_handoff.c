/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - worker handoff nodes
 * Hash each packet to the worker that owns its session and frame-enqueue
 * via vlib_buffer_enqueue_to_thread. This is what lets the per-thread
 * session pool model work at line rate: each session lives on one
 * worker's cache, and the handoff ensures both directions of a flow
 * arrive at that worker. Cost ~50-100 cycles per packet; the alternative
 * (shared session table) burns more than that on MESI cache invalidation
 * across cores. Mirrors nat44-ed's nat44_ed_handoff.c.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>

#include <osvbng_cgnat/osvbng_cgnat.h>

typedef struct
{
  u32 next_worker_index;
  u8 in2out;
  u8 same_worker;
} cgnat_handoff_trace_t;

static u8 *
format_cgnat_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cgnat_handoff_trace_t *t = va_arg (*args, cgnat_handoff_trace_t *);

  s = format (s, "cgnat-%s-handoff: next-worker %d (%s)",
	      t->in2out ? "in2out" : "out2in", t->next_worker_index,
	      t->same_worker ? "same-worker" : "handoff");
  return s;
}

#define foreach_cgnat_handoff_error                                           \
  _ (CONGESTION_DROP, "congestion drop")                                      \
  _ (SAME_WORKER, "same worker")                                              \
  _ (DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym, str) CGNAT_HANDOFF_ERROR_##sym,
  foreach_cgnat_handoff_error
#undef _
    CGNAT_HANDOFF_N_ERROR,
} cgnat_handoff_error_t;

static char *cgnat_handoff_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_handoff_error
#undef _
};

always_inline uword
cgnat_handoff_fn_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, int is_in2out)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 n_left_from, *from;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti = thread_indices;
  u32 n_enq, same_worker = 0, do_handoff = 0;
  u32 fq_index = is_in2out ? cm->fq_in2out_index : cm->fq_out2in_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0)
    {
      ip4_header_t *ip0 = vlib_buffer_get_current (b[0]);
      u32 sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u32 fib_index0 =
	vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index0);

      if (is_in2out)
	ti[0] = cgnat_get_in2out_worker_index (ip0, fib_index0);
      else
	ti[0] = cgnat_get_out2in_worker_index (
	  ip0, vnet_buffer (b[0])->ip.reass.l4_dst_port);

      if (ti[0] == thread_index)
	same_worker++;
      else
	do_handoff++;

      b += 1;
      ti += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;
      b = bufs;
      ti = thread_indices;
      for (i = 0; i < frame->n_vectors; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cgnat_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_worker_index = ti[0];
	      t->in2out = is_in2out;
	      t->same_worker = (ti[0] == thread_index);
	    }
	  b += 1;
	  ti += 1;
	}
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);
  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 CGNAT_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_HANDOFF_ERROR_SAME_WORKER, same_worker);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_HANDOFF_ERROR_DO_HANDOFF, do_handoff);
  return frame->n_vectors;
}

VLIB_NODE_FN (cgnat_in2out_worker_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cgnat_handoff_fn_inline (vm, node, frame, 1);
}

VLIB_NODE_FN (cgnat_out2in_worker_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cgnat_handoff_fn_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (cgnat_in2out_worker_handoff_node) = {
  .name = "cgnat-in2out-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_handoff_error_strings),
  .error_strings = cgnat_handoff_error_strings,
};

VLIB_REGISTER_NODE (cgnat_out2in_worker_handoff_node) = {
  .name = "cgnat-out2in-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_handoff_error_strings),
  .error_strings = cgnat_handoff_error_strings,
};

/* Replace the in2out feature on the ip4-unicast arc — the handoff runs
 * BEFORE cgnat-in2out, dispatches to the owning worker, and that worker's
 * cgnat-in2out picks up from the frame queue. sv-reass must have already
 * populated reass.* metadata so the handoff's out2in-style hash on
 * l4_dst_port can read it. */
VNET_FEATURE_INIT (cgnat_in2out_handoff_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-in2out-worker-handoff",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
