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
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ethernet/ethernet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
  u8 punted;
  u8 not_enabled;
} osvbng_punt_ipv6_nd_trace_t;

#define foreach_osvbng_punt_ipv6_nd_error \
  _(PUNTED, "IPv6-ND packets punted")  \
  _(DROPPED, "IPv6-ND packets dropped (socket error)") \
  _(NOT_ENABLED, "IPv6-ND packets passed through (punt not enabled)")

typedef enum
{
#define _(sym,str) OSVBNG_PUNT_IPV6_ND_ERROR_##sym,
  foreach_osvbng_punt_ipv6_nd_error
#undef _
    OSVBNG_PUNT_IPV6_ND_N_ERROR,
} osvbng_punt_ipv6_nd_error_t;

static char *osvbng_punt_ipv6_nd_error_strings[] = {
#define _(sym,string) string,
  foreach_osvbng_punt_ipv6_nd_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_IPV6_ND_NEXT_DROP,
  OSVBNG_PUNT_IPV6_ND_NEXT_PASSTHROUGH_RS,
  OSVBNG_PUNT_IPV6_ND_N_NEXT,
} osvbng_punt_ipv6_nd_next_t;

static u8 *
format_osvbng_punt_ipv6_nd_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_ipv6_nd_trace_t *t =
    va_arg (*args, osvbng_punt_ipv6_nd_trace_t *);

  s = format (s, "OSVBNG-PUNT-IPV6-ND: sw_if_index %d %s", t->sw_if_index,
	      t->not_enabled ? "not-enabled" : (t->punted ? "punted" :
						"dropped"));
  return s;
}

static_always_inline uword
osvbng_punt_ipv6_nd_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 n_left_from, *from, *to_next;
  osvbng_punt_ipv6_nd_next_t next_index;
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
	  u32 next0 = OSVBNG_PUNT_IPV6_ND_NEXT_DROP;
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

	  p = hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_IPV6_ND],
			sw_if_index0);

	  if (p)
	    {
	      /* Buffer points to ICMPv6 header after ip6-icmp-input dispatch.
	       * Rewind to include IPv6 + Ethernet headers for full L2 frame punt.
	       * Cannot use vlib_buffer_reset() here — unlike ARP which sits right
	       * after ethernet-input, ICMPv6 arrives after ip6-input has advanced
	       * the buffer, so offset 0 lands in pre-data space, not Ethernet. */
	      i16 rewind = sizeof (icmp46_header_t) + sizeof (ip6_header_t) +
		sizeof (ethernet_header_t);

	      if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
		rewind += 2 * sizeof (ethernet_vlan_header_t);
	      else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
		rewind += sizeof (ethernet_vlan_header_t);

	      vlib_buffer_advance (b0, -rewind);
	      if (osvbng_punt_send_packet
		  (vm, b0, sw_if_index0, OSVBNG_PUNT_PROTO_IPV6_ND) == 0)
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
	      /* Not enabled for punt — pass to VPP's default RS handler */
	      next0 = OSVBNG_PUNT_IPV6_ND_NEXT_PASSTHROUGH_RS;
	      pkts_not_enabled++;
	      not_enabled = 1;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_ipv6_nd_trace_t *t =
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
			       OSVBNG_PUNT_IPV6_ND_ERROR_PUNTED, pkts_punted);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_IPV6_ND_ERROR_DROPPED,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_IPV6_ND_ERROR_NOT_ENABLED,
			       pkts_not_enabled);

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_ipv6_nd_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return osvbng_punt_ipv6_nd_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_ipv6_nd_node) = {
  .name = "osvbng-punt-ipv6-nd",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_ipv6_nd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_punt_ipv6_nd_error_strings),
  .error_strings = osvbng_punt_ipv6_nd_error_strings,
  .n_next_nodes = OSVBNG_PUNT_IPV6_ND_N_NEXT,
  .next_nodes = {
    [OSVBNG_PUNT_IPV6_ND_NEXT_DROP] = "error-drop",
    [OSVBNG_PUNT_IPV6_ND_NEXT_PASSTHROUGH_RS] = "icmp6-router-solicitation",
  },
};

int
osvbng_punt_enable_ipv6_nd (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;
  u32 node_index;

  node_index = osvbng_punt_ipv6_nd_node.index;

  /* Only register Router Solicitation — we only need to punt RS */
  icmp6_register_type (vm, ICMP6_router_solicitation, node_index);

  hash_set (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_IPV6_ND], sw_if_index,
	    1);

  return 0;
}

int
osvbng_punt_disable_ipv6_nd (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  hash_unset (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_IPV6_ND],
	      sw_if_index);

  /* Note: We don't unregister ICMPv6 types as other interfaces may still need them */
  /* VPP's icmp6_register_type doesn't provide per-interface granularity */

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
