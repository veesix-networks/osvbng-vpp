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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_local.h>
#include <vnet/ip/ip6_packet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
  u16 src_port;
  u16 dst_port;
} osvbng_punt_dhcp6_trace_t;

static u8 *
format_osvbng_punt_dhcp6_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_dhcp6_trace_t *t = va_arg (*args, osvbng_punt_dhcp6_trace_t *);

  s = format (s, "DHCPv6 punt: sw_if_index %d, %d -> %d",
	      t->sw_if_index, t->src_port, t->dst_port);
  return s;
}

#define foreach_osvbng_punt_dhcp6_next \
  _(DROP, "error-drop")

typedef enum
{
#define _(s, n) OSVBNG_PUNT_DHCP6_NEXT_##s,
  foreach_osvbng_punt_dhcp6_next
#undef _
    OSVBNG_PUNT_DHCP6_N_NEXT,
} osvbng_punt_dhcp6_next_t;

static_always_inline uword
osvbng_punt_dhcp6_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  osvbng_punt_dhcp6_next_t next_index;
  osvbng_punt_main_t *pm = &osvbng_punt_main;

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
	  u32 next0 = OSVBNG_PUNT_DHCP6_NEXT_DROP;
	  u32 sw_if_index0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Buffer points to UDP payload, rewind to include UDP + IPv6 + Ethernet */
	  i16 rewind = sizeof (udp_header_t) + sizeof (ip6_header_t) +
	    sizeof (ethernet_header_t);

	  if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
	    rewind += 2 * sizeof (ethernet_vlan_header_t);
	  else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
	    rewind += sizeof (ethernet_vlan_header_t);

	  vlib_buffer_advance (b0, -rewind);

	  /* Send packet to userspace */
	  osvbng_punt_send_packet (vm, b0, sw_if_index0,
				   OSVBNG_PUNT_PROTO_DHCPV6);
	  pm->packets_punted[OSVBNG_PUNT_PROTO_DHCPV6]++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_dhcp6_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      /* Advance past Ethernet + VLANs + IPv6 to get UDP header */
	      i16 eth_len = sizeof (ethernet_header_t);
	      if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
		eth_len += 2 * sizeof (ethernet_vlan_header_t);
	      else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
		eth_len += sizeof (ethernet_vlan_header_t);

	      u8 *data = vlib_buffer_get_current (b0);
	      udp_header_t *udp0 = (udp_header_t *) (data + eth_len +
						     sizeof (ip6_header_t));
	      t->sw_if_index = sw_if_index0;
	      t->src_port = clib_net_to_host_u16 (udp0->src_port);
	      t->dst_port = clib_net_to_host_u16 (udp0->dst_port);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_dhcp6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return osvbng_punt_dhcp6_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_dhcp6_node) = {
  .name = "osvbng-punt-dhcp6",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_dhcp6_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = OSVBNG_PUNT_DHCP6_N_NEXT,
  .next_nodes = {
#define _(s, n) [OSVBNG_PUNT_DHCP6_NEXT_##s] = n,
    foreach_osvbng_punt_dhcp6_next
#undef _
  },
};

int
osvbng_punt_enable_dhcpv6 (u32 sw_if_index, u8 *socket_path)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;
  u32 node_index;

  if (socket_path && !pm->socket_path)
    osvbng_punt_socket_init (socket_path);

  node_index = osvbng_punt_dhcp6_node.index;

  /* DHCPv6 uses UDP port 546 (client) and 547 (server)
   * The '0' parameter indicates IPv6 (vs '1' for IPv4 in DHCPv4) */
  udp_register_dst_port (vm, 546, node_index, 0);
  udp_register_dst_port (vm, 547, node_index, 0);

  hash_set (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV6], sw_if_index, 1);

  return 0;
}

int
osvbng_punt_disable_dhcpv6 (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;

  hash_unset (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV6], sw_if_index);

  if (hash_elts (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV6]) == 0)
    {
      udp_unregister_dst_port (vm, 546, 0);
      udp_unregister_dst_port (vm, 547, 0);
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
