/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin - pseudowire headend
 *
 * osvbng-pw-input is the decap next for transport tunnels bound to a
 * headend: it rewrites VLIB_RX to the headend loopback and enters
 * ethernet-input, so VLAN subinterfaces on the headend classify as if
 * the frame arrived on a physical port.
 *
 * osvbng-pw-output replaces the headend's hw output node. Subif TX
 * funnels through the sup hw output node, so every frame leaving the
 * headend (or any of its subinterfaces) lands here; VLIB_TX is
 * rewritten to the transport tunnel and the frame is handed to the
 * tunnel's own output node for encap.
 *
 * Both nodes are stateless per packet and lock-free; the binding
 * vectors are written only under the API barrier.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <osvbng_tunnel/osvbng_tunnel.h>

typedef struct
{
  u32 tunnel_sw_if_index;
  u32 headend_sw_if_index;
} osvbng_pw_trace_t;

static u8 *
format_osvbng_pw_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  vlib_node_t *node = va_arg (*args, vlib_node_t *);
  osvbng_pw_trace_t *t = va_arg (*args, osvbng_pw_trace_t *);

  s = format (s, "%v: tunnel sw_if_index %d headend sw_if_index %d",
	      node->name, t->tunnel_sw_if_index, t->headend_sw_if_index);
  return s;
}

#define foreach_osvbng_pw_input_error                                        \
  _ (DISPATCHED, "pw frames dispatched to headend")                          \
  _ (UNBOUND, "tunnel has no headend binding (drop)")

typedef enum
{
#define _(sym, str) OSVBNG_PW_INPUT_ERROR_##sym,
  foreach_osvbng_pw_input_error
#undef _
    OSVBNG_PW_INPUT_N_ERROR,
} osvbng_pw_input_error_t;

static char *osvbng_pw_input_error_strings[] = {
#define _(sym, str) str,
  foreach_osvbng_pw_input_error
#undef _
};

#define OSVBNG_PW_INPUT_NEXT_DROP     0
#define OSVBNG_PW_INPUT_NEXT_ETHERNET 1

VLIB_NODE_FN (osvbng_pw_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_unbound = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, tunnel0, headend0 = ~0u;
	  u32 next0 = OSVBNG_PW_INPUT_NEXT_DROP;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  tunnel0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_TRUE (tunnel0 < vec_len (tm->pw_headend_by_tunnel)))
	    headend0 = tm->pw_headend_by_tunnel[tunnel0];

	  if (PREDICT_TRUE (headend0 != ~0u))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = headend0;
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
	      next0 = OSVBNG_PW_INPUT_NEXT_ETHERNET;
	    }
	  else
	    pkts_unbound++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_pw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->tunnel_sw_if_index = tunnel0;
	      t->headend_sw_if_index = headend0;
	    }

	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PW_INPUT_ERROR_DISPATCHED,
			       frame->n_vectors - pkts_unbound);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PW_INPUT_ERROR_UNBOUND, pkts_unbound);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_pw_input_node) = {
  .name = "osvbng-pw-input",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_pw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OSVBNG_PW_INPUT_N_ERROR,
  .error_strings = osvbng_pw_input_error_strings,
  .n_next_nodes = 2,
  .next_nodes = {
    [OSVBNG_PW_INPUT_NEXT_DROP] = "error-drop",
    [OSVBNG_PW_INPUT_NEXT_ETHERNET] = "ethernet-input",
  },
};

#define foreach_osvbng_pw_output_error                                       \
  _ (TX, "pw frames sent to transport tunnel")                               \
  _ (UNBOUND, "headend has no transport binding (drop)")

typedef enum
{
#define _(sym, str) OSVBNG_PW_OUTPUT_ERROR_##sym,
  foreach_osvbng_pw_output_error
#undef _
    OSVBNG_PW_OUTPUT_N_ERROR,
} osvbng_pw_output_error_t;

static char *osvbng_pw_output_error_strings[] = {
#define _(sym, str) str,
  foreach_osvbng_pw_output_error
#undef _
};

#define OSVBNG_PW_OUTPUT_NEXT_DROP 0

VLIB_NODE_FN (osvbng_pw_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;
  vnet_main_t *vnm = tm->vnet_main;
  u32 n_left_from, *from;
  u32 pkts_tx = 0, pkts_unbound = 0;

  u32 cached_out_node = ~0u;
  vlib_frame_t *out_frame = NULL;
  u32 *out_to_next = NULL;
  u32 out_n = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0, tx0, sup0, tunnel0 = ~0u;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      tx0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      sup0 = vnet_get_sup_sw_interface (vnm, tx0)->sw_if_index;
      if (PREDICT_TRUE (sup0 < vec_len (tm->pw_tunnel_by_headend)))
	tunnel0 = tm->pw_tunnel_by_headend[sup0];

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  osvbng_pw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->tunnel_sw_if_index = tunnel0;
	  t->headend_sw_if_index = sup0;
	}

      if (PREDICT_FALSE (tunnel0 == ~0u))
	{
	  vlib_frame_t *df =
	    vlib_get_frame_to_node (vm, tm->error_drop_node_index);
	  u32 *dn = vlib_frame_vector_args (df);
	  dn[0] = bi0;
	  df->n_vectors = 1;
	  vlib_put_frame_to_node (vm, tm->error_drop_node_index, df);
	  pkts_unbound++;
	  continue;
	}

      vnet_buffer (b0)->sw_if_index[VLIB_TX] = tunnel0;

      vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, tunnel0);
      u32 out_node = hw->output_node_index;

      if (PREDICT_FALSE (out_node != cached_out_node))
	{
	  if (out_frame)
	    {
	      out_frame->n_vectors = out_n;
	      vlib_put_frame_to_node (vm, cached_out_node, out_frame);
	    }
	  cached_out_node = out_node;
	  out_frame = vlib_get_frame_to_node (vm, out_node);
	  out_to_next = vlib_frame_vector_args (out_frame);
	  out_n = 0;
	}

      out_to_next[out_n++] = bi0;
      pkts_tx++;

      if (PREDICT_FALSE (out_n >= VLIB_FRAME_SIZE))
	{
	  out_frame->n_vectors = out_n;
	  vlib_put_frame_to_node (vm, cached_out_node, out_frame);
	  cached_out_node = ~0u;
	  out_frame = NULL;
	  out_n = 0;
	}
    }

  if (out_frame)
    {
      out_frame->n_vectors = out_n;
      vlib_put_frame_to_node (vm, cached_out_node, out_frame);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PW_OUTPUT_ERROR_TX, pkts_tx);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PW_OUTPUT_ERROR_UNBOUND, pkts_unbound);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_pw_output_node) = {
  .name = "osvbng-pw-output",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_pw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OSVBNG_PW_OUTPUT_N_ERROR,
  .error_strings = osvbng_pw_output_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [OSVBNG_PW_OUTPUT_NEXT_DROP] = "error-drop",
  },
};

int
osvbng_tunnel_pw_bind (u32 tunnel_sw_if_index, u32 headend_sw_if_index,
		       u8 is_bind)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;
  vnet_main_t *vnm = tm->vnet_main;

  if (!vnet_sw_interface_is_api_valid (vnm, tunnel_sw_if_index) ||
      !vnet_sw_interface_is_api_valid (vnm, headend_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vec_validate_init_empty (tm->pw_headend_by_tunnel, tunnel_sw_if_index, ~0u);
  vec_validate_init_empty (tm->pw_tunnel_by_headend, headend_sw_if_index,
			   ~0u);
  vec_validate_init_empty (tm->pw_saved_output_node, headend_sw_if_index,
			   ~0u);

  vnet_hw_interface_t *headend_hw =
    vnet_get_sup_hw_interface (vnm, headend_sw_if_index);

  if (is_bind)
    {
      u32 cur = tm->pw_headend_by_tunnel[tunnel_sw_if_index];
      if (cur == headend_sw_if_index &&
	  tm->pw_tunnel_by_headend[headend_sw_if_index] == tunnel_sw_if_index)
	return 0;
      if (cur != ~0u || tm->pw_tunnel_by_headend[headend_sw_if_index] != ~0u)
	return VNET_API_ERROR_VALUE_EXIST;

      tm->pw_saved_output_node[headend_sw_if_index] =
	headend_hw->output_node_index;
      vnet_set_interface_output_node (vnm, headend_hw->hw_if_index,
				      osvbng_pw_output_node.index);

      tm->pw_headend_by_tunnel[tunnel_sw_if_index] = headend_sw_if_index;
      tm->pw_tunnel_by_headend[headend_sw_if_index] = tunnel_sw_if_index;
      return 0;
    }

  if (tm->pw_headend_by_tunnel[tunnel_sw_if_index] != headend_sw_if_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (tm->pw_saved_output_node[headend_sw_if_index] != ~0u)
    vnet_set_interface_output_node (
      vnm, headend_hw->hw_if_index,
      tm->pw_saved_output_node[headend_sw_if_index]);

  tm->pw_headend_by_tunnel[tunnel_sw_if_index] = ~0u;
  tm->pw_tunnel_by_headend[headend_sw_if_index] = ~0u;
  tm->pw_saved_output_node[headend_sw_if_index] = ~0u;
  return 0;
}

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
