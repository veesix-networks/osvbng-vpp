/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin - tunnel RX dispatch node
 *
 * Registered as a sibling of the device-input placeholder node so it
 * shares the arc's next space, exactly like a driver RX node. Tunnel
 * decap nodes (vxlan4-input / vxlan6-input) dispatch here with the
 * buffer at the inner ethernet header and VLIB_RX set to the tunnel
 * sw_if_index; each buffer then re-enters the device-input feature arc
 * for that interface, falling through to ethernet-input when no
 * features are armed. Stateless and lock-free: buffers stay on their
 * RX worker.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>

#include <osvbng_tunnel/osvbng_tunnel.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} osvbng_tunnel_input_trace_t;

static u8 *
format_osvbng_tunnel_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_tunnel_input_trace_t *t =
    va_arg (*args, osvbng_tunnel_input_trace_t *);

  s = format (s, "osvbng-tunnel-input: sw_if_index %d next %d",
	      t->sw_if_index, t->next_index);
  return s;
}

#define foreach_osvbng_tunnel_input_error                                     \
  _ (DISPATCHED, "tunnel frames dispatched")

typedef enum
{
#define _(sym, str) OSVBNG_TUNNEL_INPUT_ERROR_##sym,
  foreach_osvbng_tunnel_input_error
#undef _
    OSVBNG_TUNNEL_INPUT_N_ERROR,
} osvbng_tunnel_input_error_t;

static char *osvbng_tunnel_input_error_strings[] = {
#define _(sym, str) str,
  foreach_osvbng_tunnel_input_error
#undef _
};

VLIB_NODE_FN (osvbng_tunnel_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;

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
	  u32 bi0, sw_if_index0;
	  u32 next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

	  vnet_feature_start_device_input (sw_if_index0, &next0, b0);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_tunnel_input_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
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
			       OSVBNG_TUNNEL_INPUT_ERROR_DISPATCHED,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_tunnel_input_node) = {
  .name = "osvbng-tunnel-input",
  .sibling_of = "device-input",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_tunnel_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OSVBNG_TUNNEL_INPUT_N_ERROR,
  .error_strings = osvbng_tunnel_input_error_strings,
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
