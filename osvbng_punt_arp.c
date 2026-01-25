/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
  u8 punted;
  u8 not_enabled;
} osvbng_punt_arp_trace_t;

#define foreach_osvbng_punt_arp_error \
  _(PUNTED, "ARP packets punted")  \
  _(DROPPED, "ARP packets dropped (socket error)") \
  _(NOT_ENABLED, "ARP packets dropped (punt not enabled)")

typedef enum
{
#define _(sym,str) OSVBNG_PUNT_ARP_ERROR_##sym,
  foreach_osvbng_punt_arp_error
#undef _
    OSVBNG_PUNT_ARP_N_ERROR,
} osvbng_punt_arp_error_t;

static char *osvbng_punt_arp_error_strings[] = {
#define _(sym,string) string,
  foreach_osvbng_punt_arp_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_ARP_NEXT_DROP,
  OSVBNG_PUNT_ARP_N_NEXT,
} osvbng_punt_arp_next_t;

static u8 *
format_osvbng_punt_arp_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_arp_trace_t *t = va_arg (*args, osvbng_punt_arp_trace_t *);

  s = format (s, "OSVBNG-PUNT-ARP: sw_if_index %d %s", t->sw_if_index,
	      t->not_enabled ? "not-enabled" : (t->punted ? "punted" :
						"dropped"));
  return s;
}

static_always_inline uword
osvbng_punt_arp_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 n_left_from, *from, *to_next;
  osvbng_punt_arp_next_t next_index;
  u32 pkts_punted = 0, pkts_dropped = 0, pkts_not_enabled = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = OSVBNG_PUNT_ARP_NEXT_DROP;
	  u32 sw_if_index0;
	  u8 punted = 0;
	  u8 not_enabled = 0;
	  uword *p;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  p = hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_ARP],
			sw_if_index0);

	  if (p)
	    {
	      /* Reset buffer to ethernet header for full L2 frame punt */
	      vlib_buffer_reset (b0);
	      if (osvbng_punt_send_packet
		  (b0, sw_if_index0, OSVBNG_PUNT_PROTO_ARP) == 0)
		{
		  pkts_punted++;
		  punted = 1;
		}
	      else
		{
		  pkts_dropped++;
		}
	    }
	  else
	    {
	      pkts_not_enabled++;
	      not_enabled = 1;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_arp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->punted = punted;
	      t->not_enabled = not_enabled;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_ARP_ERROR_PUNTED, pkts_punted);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_ARP_ERROR_DROPPED, pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_ARP_ERROR_NOT_ENABLED,
			       pkts_not_enabled);

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_arp_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  return osvbng_punt_arp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_arp_node) = {
  .name = "osvbng-punt-arp",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_punt_arp_error_strings),
  .error_strings = osvbng_punt_arp_error_strings,
  .n_next_nodes = OSVBNG_PUNT_ARP_N_NEXT,
  .next_nodes = {
    [OSVBNG_PUNT_ARP_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
