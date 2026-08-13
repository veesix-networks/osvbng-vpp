/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_local.h>
#include <vnet/ip/ip4_packet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
  u16 src_port;
  u16 dst_port;
} osvbng_punt_dhcp_trace_t;

static u8 *
format_osvbng_punt_dhcp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_dhcp_trace_t *t = va_arg (*args, osvbng_punt_dhcp_trace_t *);

  s = format (s, "DHCP punt: sw_if_index %d, %d -> %d",
	      t->sw_if_index, t->src_port, t->dst_port);
  return s;
}

#define foreach_osvbng_punt_dhcp_next \
  _(DROP, "error-drop")

#define foreach_osvbng_punt_dhcp_error                                        \
  _ (PUNTED, "DHCP packets punted")                                           \
  _ (NOT_ENABLED, "DHCP packets dropped (punt not enabled on interface)")

typedef enum
{
#define _(s, n) OSVBNG_PUNT_DHCP_ERROR_##s,
  foreach_osvbng_punt_dhcp_error
#undef _
    OSVBNG_PUNT_DHCP_N_ERROR,
} osvbng_punt_dhcp_error_t;

static char *osvbng_punt_dhcp_error_strings[] = {
#define _(s, n) n,
  foreach_osvbng_punt_dhcp_error
#undef _
};

typedef enum
{
#define _(s, n) OSVBNG_PUNT_DHCP_NEXT_##s,
  foreach_osvbng_punt_dhcp_next
#undef _
    OSVBNG_PUNT_DHCP_N_NEXT,
} osvbng_punt_dhcp_next_t;

static_always_inline uword
osvbng_punt_dhcp_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  osvbng_punt_dhcp_next_t next_index;
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
	  u32 next0 = OSVBNG_PUNT_DHCP_NEXT_DROP;
	  u32 sw_if_index0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* The UDP port registration is global, so frames reach this
	   * node from every interface; punt only from interfaces the
	   * control plane enabled, or a DHCP relay elsewhere on the box
	   * would be punted to us.
	   *
	   * Broadcast (discover, request) arrives with RX naming the
	   * encap sub-interface the control plane enabled. A routed
	   * unicast (renew, release) was decapped by a session plugin
	   * first, so RX names the per-session interface instead; its
	   * sup is its encap (the session parenting contract), so one
	   * hop resolves the enablement. Dropping these silently held
	   * every QinQ IPoE subscriber's lease forever. */
	  if (!hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV4],
			 sw_if_index0))
	    {
	      vnet_sw_interface_t *sw0 = vnet_get_sw_interface_or_null (
		vnet_get_main (), sw_if_index0);
	      if (!sw0 || sw0->sup_sw_if_index == sw_if_index0 ||
		  !hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV4],
			     sw0->sup_sw_if_index))
		{
		  b0->error =
		    node->errors[OSVBNG_PUNT_DHCP_ERROR_NOT_ENABLED];
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi0, next0);
		  continue;
		}
	    }

	  i16 rewind = sizeof (udp_header_t) + sizeof (ip4_header_t) + sizeof (ethernet_header_t);

	  if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
	    rewind += 2 * sizeof (ethernet_vlan_header_t);
	  else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
	    rewind += sizeof (ethernet_vlan_header_t);

	  vlib_buffer_advance (b0, -rewind);

	  osvbng_punt_send_packet (vm, b0, sw_if_index0,
				   OSVBNG_PUNT_PROTO_DHCPV4);
	  b0->error = node->errors[OSVBNG_PUNT_DHCP_ERROR_PUNTED];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_dhcp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      ip4_header_t *ip0 = vlib_buffer_get_current (b0);
	      udp_header_t *udp0 = ip4_next_header (ip0);
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

VLIB_NODE_FN (osvbng_punt_dhcp_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return osvbng_punt_dhcp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_dhcp_node) = {
  .name = "osvbng-punt-dhcp",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_dhcp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OSVBNG_PUNT_DHCP_N_ERROR,
  .error_strings = osvbng_punt_dhcp_error_strings,
  .n_next_nodes = OSVBNG_PUNT_DHCP_N_NEXT,
  .next_nodes = {
#define _(s, n) [OSVBNG_PUNT_DHCP_NEXT_##s] = n,
    foreach_osvbng_punt_dhcp_next
#undef _
  },
};

int
osvbng_punt_enable_dhcpv4 (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;
  u32 node_index;

  node_index = osvbng_punt_dhcp_node.index;

  /* udp_register_dst_port and hash_set both mutate structures workers
   * read per packet (the dst-port table, the enabled hash) and can
   * realloc them. The binapi path already holds VPP's API barrier; the
   * CLI path holds nothing, so take it here (nested is a refcount). */
  vlib_worker_thread_barrier_sync (vm);

  udp_register_dst_port (vm, 67, node_index, 1);
  udp_register_dst_port (vm, 68, node_index, 1);

  hash_set (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV4], sw_if_index, 1);

  /* A discover is addressed to 255.255.255.255; without a receive
   * route it dies in ip4-lookup before this node ever sees it. */
  osvbng_punt_dhcp_bcast_route (sw_if_index, 1);

  vlib_worker_thread_barrier_release (vm);

  return 0;
}

int
osvbng_punt_disable_dhcpv4 (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;

  vlib_worker_thread_barrier_sync (vm);

  hash_unset (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV4], sw_if_index);
  osvbng_punt_dhcp_bcast_route (sw_if_index, 0);

  if (hash_elts (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_DHCPV4]) == 0)
    {
      udp_unregister_dst_port (vm, 67, 1);
      udp_unregister_dst_port (vm, 68, 1);
    }

  vlib_worker_thread_barrier_release (vm);

  return 0;
}
