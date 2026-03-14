/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - out2in node
 * Outside-to-inside packet processing on ip4-unicast feature arc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>

#include <osvbng_cgnat/osvbng_cgnat.h>

typedef struct
{
  u32 sw_if_index;
  ip4_address_t src_ip;
  ip4_address_t dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 proto;
  u8 found;
} cgnat_out2in_trace_t;

static u8 *
format_cgnat_out2in_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cgnat_out2in_trace_t *t = va_arg (*args, cgnat_out2in_trace_t *);

  s = format (s, "cgnat-out2in: sw_if %u %U:%u → %U:%u proto %u %s",
	      t->sw_if_index, format_ip4_address, &t->src_ip, t->src_port,
	      format_ip4_address, &t->dst_ip, t->dst_port, t->proto,
	      t->found ? "translated" : "dropped");
  return s;
}

always_inline void
cgnat_out2in_ip4_checksum_update (ip4_header_t *ip, ip4_address_t old_addr,
				  ip4_address_t new_addr)
{
  ip_csum_t sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr.as_u32, new_addr.as_u32, ip4_header_t,
			dst_address);
  ip->checksum = ip_csum_fold (sum);
}

VLIB_NODE_FN (cgnat_out2in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 n_left_from, *from, *to_next;
  cgnat_out2in_next_t next_index;
  u32 pkts_translated = 0;
  u32 pkts_dropped = 0;
  f64 now = vlib_time_now (vm);

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
	  u32 bi0;
	  u32 next0 = CGNAT_OUT2IN_NEXT_LOOKUP;
	  ip4_header_t *ip0;
	  u32 sw_if_index0;
	  u16 src_port0 = 0, dst_port0 = 0;
	  u8 proto0;
	  cgnat_session_t *s0 = NULL;
	  u8 found = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  proto0 = ip0->protocol;

	  /* Extract L4 ports */
	  if (proto0 == IP_PROTOCOL_TCP || proto0 == IP_PROTOCOL_UDP)
	    {
	      udp_header_t *udp0 =
		(udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	      src_port0 = udp0->src_port;
	      dst_port0 = udp0->dst_port;
	    }
	  else if (proto0 == IP_PROTOCOL_ICMP)
	    {
	      icmp46_header_t *icmp0 =
		(icmp46_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	      u16 *id0 = (u16 *) (icmp0 + 1);
	      if (icmp0->type == ICMP4_echo_request ||
		  icmp0->type == ICMP4_echo_reply)
		{
		  dst_port0 = *id0;
		  src_port0 = 0;
		}
	    }

	  u32 fib_index0 =
	    vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index0);

	  /* Lookup session by outside 5-tuple */
	  s0 = cgnat_session_lookup_out2in (&ip0->dst_address,
					    &ip0->src_address, dst_port0,
					    src_port0, proto0, fib_index0);

	  if (PREDICT_FALSE (!s0))
	    {
	      /* For endpoint-independent filtering: check if any mapping
	       * exists for this outside IP:port and create session */
	      /* TODO: EIF session creation for new outside→inside flows */

	      next0 = CGNAT_OUT2IN_NEXT_DROP;
	      pkts_dropped++;
	      b0->error = node->errors[CGNAT_ERROR_NO_SESSION];
	      goto trace;
	    }

	  found = 1;
	  s0->last_active = now;
	  s0->total_pkts++;
	  s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);

	  /* Rewrite dst_ip and dst_port */
	  {
	    ip4_address_t old_dst = ip0->dst_address;
	    u16 old_port = dst_port0;

	    ip0->dst_address.as_u32 = s0->inside_ip.as_u32;
	    cgnat_out2in_ip4_checksum_update (ip0, old_dst,
					      ip0->dst_address);

	    if (proto0 == IP_PROTOCOL_TCP)
	      {
		tcp_header_t *tcp0 =
		  (tcp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
		ip_csum_t sum = tcp0->checksum;
		sum = ip_csum_update (sum, old_dst.as_u32,
				      ip0->dst_address.as_u32, ip4_header_t,
				      dst_address);
		sum = ip_csum_update (sum, old_port, s0->inside_port,
				      tcp_header_t, dst_port);
		tcp0->dst_port = s0->inside_port;
		tcp0->checksum = ip_csum_fold (sum);
	      }
	    else if (proto0 == IP_PROTOCOL_UDP)
	      {
		udp_header_t *udp0 =
		  (udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
		if (udp0->checksum != 0)
		  {
		    ip_csum_t sum = udp0->checksum;
		    sum = ip_csum_update (sum, old_dst.as_u32,
					  ip0->dst_address.as_u32,
					  ip4_header_t, dst_address);
		    sum = ip_csum_update (sum, old_port, s0->inside_port,
					  tcp_header_t, dst_port);
		    udp0->checksum = ip_csum_fold (sum);
		    if (udp0->checksum == 0)
		      udp0->checksum = 0xFFFF;
		  }
		udp0->dst_port = s0->inside_port;
	      }
	    else if (proto0 == IP_PROTOCOL_ICMP)
	      {
		icmp46_header_t *icmp0 =
		  (icmp46_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
		u16 *id0 = (u16 *) (icmp0 + 1);
		if (icmp0->type == ICMP4_echo_request ||
		    icmp0->type == ICMP4_echo_reply)
		  {
		    ip_csum_t sum = icmp0->checksum;
		    sum = ip_csum_update (sum, old_port, s0->inside_port,
					  tcp_header_t, dst_port);
		    *id0 = s0->inside_port;
		    icmp0->checksum = ip_csum_fold (sum);
		  }
	      }
	  }

	  /* Route back to subscriber via inside FIB */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->inside_fib_index;

	  pkts_translated++;

	trace:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      cgnat_out2in_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->src_ip = ip0->src_address;
	      t->dst_ip = ip0->dst_address;
	      t->src_port = src_port0;
	      t->dst_port = dst_port0;
	      t->proto = proto0;
	      t->found = found;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_TRANSLATED, pkts_translated);
  vlib_node_increment_counter (vm, node->node_index, CGNAT_ERROR_DROP,
			       pkts_dropped);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cgnat_out2in_node) = {
  .name = "cgnat-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_N_ERROR,
  .error_strings = cgnat_error_strings,
  .n_next_nodes = CGNAT_OUT2IN_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_NEXT_DROP] = "error-drop",
    [CGNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VNET_FEATURE_INIT (cgnat_out2in_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-out2in",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
