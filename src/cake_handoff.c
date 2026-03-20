/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Worker handoff nodes
 *
 * When a packet arrives on a worker that does not own the target
 * subscriber's scheduler, the enqueue node routes to the handoff node.
 * The handoff node looks up the owner thread and uses
 * vlib_buffer_enqueue_to_thread() to redirect the packet.
 * The owner thread then processes it through the enqueue node locally.
 */

#include <vnet/vnet.h>
#include <osvbng_qos_sched/osvbng_qos_sched.h>

static_always_inline uword
cake_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, u32 fq_index)
{
  cake_main_t *cm = &cake_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 thread_indices[VLIB_FRAME_SIZE];

  for (u32 i = 0; i < n_left; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      u32 si = ~0;

      if (sw_if_index < vec_len (cm->sched_index_by_sw_if_index))
	si = cm->sched_index_by_sw_if_index[sw_if_index];

      if (PREDICT_TRUE (si != ~0))
	{
	  cake_sched_t *cs = pool_elt_at_index (cm->schedulers, si);
	  thread_indices[i] = cs->owner_thread;
	}
      else
	thread_indices[i] = vm->thread_index;
    }

  u32 n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					     thread_indices, n_left, 1);

  if (n_enq < n_left)
    vlib_node_increment_counter (vm, node->node_index,
				 CAKE_ERROR_HANDOFF_CONGESTION,
				 n_left - n_enq);

  return n_left;
}

VLIB_NODE_FN (ip4_cake_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cake_handoff_inline (vm, node, frame, cake_main.fq_ip4_index);
}

VLIB_NODE_FN (ip6_cake_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cake_handoff_inline (vm, node, frame, cake_main.fq_ip6_index);
}

VLIB_REGISTER_NODE (ip4_cake_handoff_node) = {
  .name = "ip4-cake-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (ip6_cake_handoff_node) = {
  .name = "ip6-cake-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = 0,
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
