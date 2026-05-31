/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - out2in nodes
 * Fast/slow split reached via DPO steering (outside addresses registered as
 * FIB entries that dispatch to cgnat-out2in). The fast node translates
 * existing-session traffic. The slow node is the hook for ICMP-error
 * inner-rewrite and endpoint-independent filtering origination, both filled
 * in by later phases; for now it preserves the current behaviour by dropping
 * with CGNAT_ERROR_NO_SESSION.
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

  s = format (s, "cgnat-out2in: sw_if %u %U:%u -> %U:%u proto %u %s",
	      t->sw_if_index, format_ip4_address, &t->src_ip, t->src_port,
	      format_ip4_address, &t->dst_ip, t->dst_port, t->proto,
	      t->found ? "translated" : "slowpath");
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

/* Pull L4 ports from the sv-reass-populated buffer metadata.
 * Mirror of cgnat_in2out_ports_from_reass; the only difference is that for
 * out2in the ICMP echo identifier is the *destination* identifier from our
 * point of view (it's the outside-port we allocated). */
always_inline int
cgnat_out2in_ports_from_reass (vlib_buffer_t *b0, ip4_header_t *ip0,
			       u8 proto0, u16 *src_port, u16 *dst_port)
{
  *src_port = 0;
  *dst_port = 0;

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.ip_proto != proto0))
    return CGNAT_ERROR_NO_REASS_METADATA;

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.l4_hdr_truncated))
    return CGNAT_ERROR_NO_REASS_METADATA;

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.is_non_first_fragment))
    return CGNAT_ERROR_FRAGMENT_DROP;  /* sentinel — caller routes to slow */

  if (proto0 == IP_PROTOCOL_TCP || proto0 == IP_PROTOCOL_UDP)
    {
      *src_port = vnet_buffer (b0)->ip.reass.l4_src_port;
      *dst_port = vnet_buffer (b0)->ip.reass.l4_dst_port;
    }
  else if (proto0 == IP_PROTOCOL_ICMP)
    {
      u8 icmp_type = vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags;
      if (icmp_type == ICMP4_echo_request || icmp_type == ICMP4_echo_reply)
	*dst_port = vnet_buffer (b0)->ip.reass.l4_src_port;
    }
  return 0;
}

/* Apply the o2i flow's rewrite: replace ip0->dst + L4 dport using the flow's
 * precomputed L3/L4 checksum deltas. Mirror of cgnat_in2out_translate. */
always_inline void
cgnat_out2in_translate (vlib_main_t *vm, vlib_buffer_t *b0, ip4_header_t *ip0,
			cgnat_session_t *s0, u8 proto0, f64 now)
{
  cgnat_flow_t *f = &s0->o2i;
  cgnat_main_t *cm = &cgnat_main;

  s0->last_active = now;
  s0->total_pkts++;
  s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);

  ip0->dst_address = f->rewrite_daddr;
  ip0->checksum =
    ip_csum_fold (ip_csum_add_even (ip0->checksum, f->l3_csum_delta));

  if (proto0 == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp0 =
	(tcp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
      tcp0->dst_port = f->rewrite_dport;
      tcp0->checksum =
	ip_csum_fold (ip_csum_add_even (tcp0->checksum, f->l4_csum_delta));
      cgnat_pool_t *pool0 = pool_elt_at_index (cm->pools, s0->pool_index);
      cgnat_set_tcp_session_state (s0, pool0, tcp0->flags, CGNAT_TCP_DIR_O2I,
				   now);
    }
  else if (proto0 == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp0 =
	(udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
      udp_header_t old_udp = *udp0;
      udp0->dst_port = f->rewrite_dport;
      if (old_udp.checksum != 0)
	{
	  udp0->checksum = ip_csum_fold (
	    ip_csum_add_even (old_udp.checksum, f->l4_csum_delta));
	  if (udp0->checksum == 0)
	    udp0->checksum = 0xFFFF;
	}
    }
  else if (proto0 == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp0 =
	(icmp46_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
      u16 *id0 = (u16 *) (icmp0 + 1);
      u8 itype = icmp0->type;
      if (itype == ICMP4_echo_request || itype == ICMP4_echo_reply)
	{
	  *id0 = f->rewrite_dport;
	  icmp0->checksum = ip_csum_fold (
	    ip_csum_add_even (icmp0->checksum, f->l4_csum_delta));
	}
    }
}

VLIB_NODE_FN (cgnat_out2in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  cgnat_out2in_next_t next_index;
  u32 pkts_translated = 0;
  u32 pkts_slowpath = 0;
  u32 pkts_dropped = 0;
  u32 pkts_no_reass = 0;
  u32 pkts_frag_drop = 0;
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

	  {
	    int rerr = cgnat_out2in_ports_from_reass (b0, ip0, proto0,
						      &src_port0, &dst_port0);
	    if (PREDICT_FALSE (rerr))
	      {
		if (rerr == CGNAT_ERROR_FRAGMENT_DROP)
		  {
		    next0 = CGNAT_OUT2IN_NEXT_SLOWPATH;
		    pkts_slowpath++;
		    goto trace;
		  }
		next0 = CGNAT_OUT2IN_NEXT_DROP;
		pkts_no_reass++;
		pkts_dropped++;
		b0->error = node->errors[rerr];
		goto trace;
	      }
	  }

	  u32 fib_index0 =
	    vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index0);

	  s0 = cgnat_session_lookup_out2in (&ip0->dst_address,
					    &ip0->src_address, dst_port0,
					    src_port0, proto0, fib_index0);

	  if (PREDICT_FALSE (!s0))
	    {
	      /* Hand off to slow node. Today it drops; later phases install
	       * ICMP-error inner-rewrite and EIF session origination there. */
	      next0 = CGNAT_OUT2IN_NEXT_SLOWPATH;
	      pkts_slowpath++;
	      goto trace;
	    }

	  found = 1;
	  cgnat_out2in_translate (vm, b0, ip0, s0, proto0, now);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->o2i.rewrite_fib_index;

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
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_NO_REASS_METADATA, pkts_no_reass);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_FRAGMENT_DROP, pkts_frag_drop);
  (void) pkts_slowpath;

  return frame->n_vectors;
}

VLIB_NODE_FN (cgnat_out2in_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  cgnat_out2in_next_t next_index;
  u32 pkts_dropped = 0;
  u32 pkts_no_reass = 0;
  u32 pkts_frag_drop = 0;
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
	  u32 next0 = CGNAT_OUT2IN_NEXT_DROP;
	  ip4_header_t *ip0;
	  u32 sw_if_index0;
	  u16 src_port0 = 0, dst_port0 = 0;
	  u8 proto0;

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

	  /* Non-first fragment: IP-only rewrite via aux fragment record.
	   * Out2in packet has src=remote, dst=outside_ip; the aux key was
	   * installed under (remote, outside, proto, outside_fib). */
	  if (PREDICT_FALSE (
		vnet_buffer (b0)->ip.reass.is_non_first_fragment))
	    {
	      u32 fib_index0 = vec_elt (ip4_main.fib_index_by_sw_if_index,
					sw_if_index0);
	      cgnat_frag_rewrite_t *fr = cgnat_frag_rewrite_lookup (
		ip0->src_address, ip0->dst_address, proto0, fib_index0);
	      if (PREDICT_FALSE (!fr))
		{
		  next0 = CGNAT_OUT2IN_NEXT_DROP;
		  pkts_frag_drop++;
		  pkts_dropped++;
		  b0->error = node->errors[CGNAT_ERROR_FRAGMENT_DROP];
		  goto enqueue;
		}
	      ip0->dst_address = fr->inside_ip;
	      ip0->checksum = ip_csum_fold (
		ip_csum_add_even (ip0->checksum, fr->l3_csum_delta_o2i));
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = fr->inside_fib_index;
	      next0 = CGNAT_OUT2IN_NEXT_LOOKUP;
	      goto enqueue;
	    }

	  /* ICMP error inner-rewrite (D4). The packet's outer header carries
	   * router_that_sent_error → outside_ip; the inner header (echoed in
	   * the ICMP payload) is the original outbound that triggered the
	   * error and carries outside_ip → remote. Look up by the inner tuple
	   * and rewrite outer dst + inner src + inner sport so the inside
	   * subscriber sees an ICMP error with proper inside addressing. */
	  if (PREDICT_FALSE (
		proto0 == IP_PROTOCOL_ICMP &&
		icmp_type_is_error_message (
		  vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags)))
	    {
	      u32 fib_index0 = vec_elt (ip4_main.fib_index_by_sw_if_index,
					sw_if_index0);
	      icmp46_header_t *icmp0 =
		(icmp46_header_t *) ip4_next_header (ip0);
	      nat_icmp_echo_header_t *echo0 =
		(nat_icmp_echo_header_t *) (icmp0 + 1);
	      ip4_header_t *inner_ip = (ip4_header_t *) (echo0 + 1);
	      void *inner_l4 = ip4_next_header (inner_ip);

	      ip4_address_t lookup_dst = inner_ip->src_address;
	      ip4_address_t lookup_src = inner_ip->dst_address;
	      u16 lookup_dport = 0, lookup_sport = 0;
	      u8 inner_proto = inner_ip->protocol;

	      if (inner_proto == IP_PROTOCOL_TCP ||
		  inner_proto == IP_PROTOCOL_UDP)
		{
		  nat_tcp_udp_header_t *th = inner_l4;
		  lookup_dport = th->src_port;
		  lookup_sport = th->dst_port;
		}
	      else if (inner_proto == IP_PROTOCOL_ICMP)
		{
		  icmp46_header_t *inner_icmp = inner_l4;
		  nat_icmp_echo_header_t *inner_echo =
		    (nat_icmp_echo_header_t *) (inner_icmp + 1);
		  lookup_dport = inner_echo->identifier;
		  lookup_sport = inner_echo->identifier;
		}
	      else
		{
		  next0 = CGNAT_OUT2IN_NEXT_DROP;
		  pkts_dropped++;
		  b0->error = node->errors[CGNAT_ERROR_NO_SESSION];
		  goto enqueue;
		}

	      cgnat_session_t *s0 = cgnat_session_lookup_out2in (
		&lookup_dst, &lookup_src, lookup_dport, lookup_sport,
		inner_proto, fib_index0);
	      if (PREDICT_FALSE (!s0))
		{
		  next0 = CGNAT_OUT2IN_NEXT_DROP;
		  pkts_dropped++;
		  b0->error = node->errors[CGNAT_ERROR_NO_SESSION];
		  goto enqueue;
		}

	      /* Rewrite outer dst (outside_ip → inside_ip) — same address
	       * change as s->o2i so we can reuse its precomputed delta. */
	      ip0->dst_address = s0->o2i.rewrite_daddr;
	      ip0->checksum = ip_csum_fold (
		ip_csum_add_even (ip0->checksum, s0->o2i.l3_csum_delta));

	      /* Rewrite inner src (outside_ip → inside_ip) — the inner IP
	       * src was our outside_ip; flip it to the subscriber's inside_ip
	       * so the application sees a well-formed inner. Same delta. */
	      inner_ip->src_address = s0->o2i.rewrite_daddr;
	      inner_ip->checksum = ip_csum_fold (
		ip_csum_add_even (inner_ip->checksum, s0->o2i.l3_csum_delta));

	      /* Rewrite inner sport (outside_port → inside_port). */
	      if (inner_proto == IP_PROTOCOL_TCP ||
		  inner_proto == IP_PROTOCOL_UDP)
		((nat_tcp_udp_header_t *) inner_l4)->dst_port =
		  s0->o2i.rewrite_dport;
	      else if (inner_proto == IP_PROTOCOL_ICMP)
		{
		  icmp46_header_t *inner_icmp = inner_l4;
		  nat_icmp_echo_header_t *inner_echo =
		    (nat_icmp_echo_header_t *) (inner_icmp + 1);
		  inner_echo->identifier = s0->o2i.rewrite_dport;
		}

	      /* Outer ICMP checksum: covers ICMP header + payload (inner IP +
	       * 8 bytes of inner L4). Recompute from scratch — slow path
	       * cost is fine, simpler than tracking every byte that changed. */
	      icmp0->checksum = 0;
	      ip_csum_t sum = ip_incremental_checksum_buffer (
		vm, b0, (u8 *) icmp0 - (u8 *) vlib_buffer_get_current (b0),
		ntohs (ip0->length) - ip4_header_bytes (ip0), 0);
	      icmp0->checksum = ~ip_csum_fold (sum);

	      s0->last_active = now;
	      s0->total_pkts++;
	      s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = s0->o2i.rewrite_fib_index;
	      next0 = CGNAT_OUT2IN_NEXT_LOOKUP;
	      goto enqueue;
	    }

	  {
	    int rerr = cgnat_out2in_ports_from_reass (b0, ip0, proto0,
						      &src_port0, &dst_port0);
	    if (PREDICT_FALSE (rerr))
	      {
		pkts_no_reass++;
		pkts_dropped++;
		b0->error = node->errors[rerr];
		goto enqueue;
	      }
	  }

	  b0->error = node->errors[CGNAT_ERROR_NO_SESSION];
	  pkts_dropped++;

	enqueue:
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
	      t->found = 0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, CGNAT_ERROR_DROP,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_NO_REASS_METADATA, pkts_no_reass);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_FRAGMENT_DROP, pkts_frag_drop);

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
    [CGNAT_OUT2IN_NEXT_SLOWPATH] = "cgnat-out2in-slowpath",
  },
};

VLIB_REGISTER_NODE (cgnat_out2in_slowpath_node) = {
  .name = "cgnat-out2in-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_N_ERROR,
  .error_strings = cgnat_error_strings,
  .n_next_nodes = CGNAT_OUT2IN_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_NEXT_DROP] = "error-drop",
    [CGNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_OUT2IN_NEXT_SLOWPATH] = "error-drop",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
