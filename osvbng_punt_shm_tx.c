/*
 * Copyright (c) 2026 Veesix Networks
 * Licensed under the Apache License, Version 2.0
 */

/*
 * osvbng-punt-shm-tx — a protocol-agnostic SHM punt service node.
 *
 * Caller plugins (osvbng_pppoe non-IP control, osvbng_l2tp T=1 control,
 * etc.) enqueue buffers into this node via a graph-node next-arc
 * resolved by name at plugin init. The buffer must already be rewound
 * to the full L2 frame (the SHM consumer in userspace parses that
 * shape), and `vnet_buffer_punt_protocol(b)` must carry the
 * `osvbng_punt_protocol_t` enum so this node knows which SHM channel
 * to use.
 *
 * Existence of this node is what lets sibling plugins talk to the
 * punt SHM service without direct symbol references — fixing the
 * cross-plugin dlopen-time symbol-resolution problem and keeping
 * plugin isolation idiomatic for VPP.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
  u8 protocol;
  u8 punted;
} osvbng_punt_shm_tx_trace_t;

static u8 *
format_osvbng_punt_shm_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_shm_tx_trace_t *t = va_arg (*args, osvbng_punt_shm_tx_trace_t *);
  s = format (s, "OSVBNG-PUNT-SHM-TX: sw_if_index %d protocol %d %s",
	      t->sw_if_index, t->protocol,
	      t->punted ? "punted" : "dropped");
  return s;
}

#define foreach_osvbng_punt_shm_tx_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) OSVBNG_PUNT_SHM_TX_NEXT_##s,
  foreach_osvbng_punt_shm_tx_next
#undef _
    OSVBNG_PUNT_SHM_TX_N_NEXT,
} osvbng_punt_shm_tx_next_t;

VLIB_NODE_FN (osvbng_punt_shm_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = OSVBNG_PUNT_SHM_TX_NEXT_DROP;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  osvbng_punt_protocol_t proto0 =
	    (osvbng_punt_protocol_t) vnet_buffer_punt_protocol (b0);
	  u8 punted0 = 0;

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  if (osvbng_punt_send_packet (vm, b0, sw_if_index0, proto0) == 0)
	    punted0 = 1;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_shm_tx_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->protocol = (u8) proto0;
	      t->punted = punted0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0,
					   OSVBNG_PUNT_SHM_TX_NEXT_DROP);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_punt_shm_tx_node) = {
  .name = "osvbng-punt-shm-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_shm_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = OSVBNG_PUNT_SHM_TX_N_NEXT,
  .next_nodes = {
#define _(s, n) [OSVBNG_PUNT_SHM_TX_NEXT_##s] = n,
    foreach_osvbng_punt_shm_tx_next
#undef _
  },
};
