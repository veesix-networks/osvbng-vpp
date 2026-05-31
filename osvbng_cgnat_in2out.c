/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - in2out nodes
 * Fast/slow split on the ip4-unicast feature arc. The fast node translates
 * existing-session traffic and hands new flows off to the slow node, which
 * owns mapping lookup + port allocation + cgnat_session_create + first-packet
 * translation. Both nodes share the rewrite helper inline below; the slow
 * node carries the cost of new-session creation while the fast node stays
 * tight on the per-packet established-session path.
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
  u8 action;
} cgnat_in2out_trace_t;

#define CGNAT_TRACE_TRANSLATED 0
#define CGNAT_TRACE_BYPASSED   1
#define CGNAT_TRACE_DROPPED    2
#define CGNAT_TRACE_HAIRPINNED 3
#define CGNAT_TRACE_CREATED    4
#define CGNAT_TRACE_SLOWPATH   5

static u8 *
format_cgnat_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cgnat_in2out_trace_t *t = va_arg (*args, cgnat_in2out_trace_t *);

  char *actions[] = { "translated", "bypassed", "dropped", "hairpinned",
		      "session-created", "slowpath" };

  s = format (s, "cgnat-in2out: sw_if %u %U:%u -> %U:%u proto %u action %s",
	      t->sw_if_index, format_ip4_address, &t->src_ip, t->src_port,
	      format_ip4_address, &t->dst_ip, t->dst_port, t->proto,
	      actions[t->action]);
  return s;
}

always_inline void
cgnat_ip4_checksum_update (ip4_header_t *ip, ip4_address_t old_addr,
			   ip4_address_t new_addr)
{
  ip_csum_t sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr.as_u32, new_addr.as_u32, ip4_header_t,
			src_address);
  ip->checksum = ip_csum_fold (sum);
}

always_inline void
cgnat_l4_checksum_update_ip (ip_csum_t *sum, ip4_address_t old_addr,
			     ip4_address_t new_addr)
{
  *sum = ip_csum_update (*sum, old_addr.as_u32, new_addr.as_u32,
			 ip4_header_t, src_address);
}

always_inline void
cgnat_l4_checksum_update_port (ip_csum_t *sum, u16 old_port, u16 new_port)
{
  *sum = ip_csum_update (*sum, old_port, new_port, tcp_header_t, src_port);
}

always_inline int
cgnat_is_hairpin (cgnat_main_t *cm, ip4_address_t *dst_ip)
{
  clib_bihash_kv_8_8_t kv;
  cgnat_inside_key_t key;

  key.ip.as_u32 = dst_ip->as_u32;
  key.fib_index = 0;
  kv.key = key.as_u64;

  if (clib_bihash_search_inline_8_8 (&cm->inside_lookup, &kv) == 0)
    return 1;

  return 0;
}

/* Pull L4 ports from the sv-reass-populated buffer metadata.
 * Returns 0 on success, non-zero error code if sv-reass didn't populate
 * (operator disabled it, refcnt-enable failed, etc.) — caller drops with
 * CGNAT_ERROR_NO_REASS_METADATA or CGNAT_ERROR_FRAGMENT_DROP. */
always_inline int
cgnat_in2out_ports_from_reass (vlib_buffer_t *b0, ip4_header_t *ip0, u8 proto0,
			       u16 *src_port, u16 *dst_port)
{
  *src_port = 0;
  *dst_port = 0;

  /* sv-reass populates reass.ip_proto from the IP header it parsed.
   * Mismatch => sv-reass didn't run on this packet (recycled buffer
   * metadata) — fail closed rather than rewrite from garbage ports. */
  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.ip_proto != proto0))
    return CGNAT_ERROR_NO_REASS_METADATA;

  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.l4_hdr_truncated))
    return CGNAT_ERROR_NO_REASS_METADATA;

  /* Non-first fragments have no L4 header. Phase 4 replaces this drop with
   * a refcounted aux-key lookup. */
  if (PREDICT_FALSE (vnet_buffer (b0)->ip.reass.is_non_first_fragment))
    return CGNAT_ERROR_FRAGMENT_DROP;

  if (proto0 == IP_PROTOCOL_TCP || proto0 == IP_PROTOCOL_UDP)
    {
      *src_port = vnet_buffer (b0)->ip.reass.l4_src_port;
      *dst_port = vnet_buffer (b0)->ip.reass.l4_dst_port;
    }
  else if (proto0 == IP_PROTOCOL_ICMP)
    {
      /* sv-reass stashes the ICMP echo identifier in l4_src_port for echo
       * request/reply; other ICMP types (errors, query types we don't
       * translate) are handled by phase 5's slowpath inner-rewrite. */
      u8 icmp_type = vnet_buffer (b0)->ip.reass.icmp_type_or_tcp_flags;
      if (icmp_type == ICMP4_echo_request || icmp_type == ICMP4_echo_reply)
	*src_port = vnet_buffer (b0)->ip.reass.l4_src_port;
    }
  return 0;
}

/* Rewrite src_ip and src_port (or ICMP echo id) on a matched in2out session.
 * Shared by both fast and slow nodes — slow uses it on the first packet
 * after session_create, fast uses it on every subsequent packet. */
always_inline void
cgnat_in2out_translate (vlib_main_t *vm, vlib_buffer_t *b0, ip4_header_t *ip0,
			cgnat_session_t *s0, u8 proto0, u16 src_port0, f64 now)
{
  s0->last_active = now;
  s0->total_pkts++;
  s0->total_bytes += vlib_buffer_length_in_chain (vm, b0);

  ip4_address_t old_src = ip0->src_address;
  u16 old_port = src_port0;

  ip0->src_address.as_u32 = s0->outside_ip.as_u32;
  cgnat_ip4_checksum_update (ip0, old_src, ip0->src_address);

  if (proto0 == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp0 =
	(tcp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
      ip_csum_t sum = tcp0->checksum;
      cgnat_l4_checksum_update_ip (&sum, old_src, ip0->src_address);
      cgnat_l4_checksum_update_port (&sum, old_port, s0->outside_port);
      tcp0->src_port = s0->outside_port;
      tcp0->checksum = ip_csum_fold (sum);
    }
  else if (proto0 == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp0 =
	(udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
      if (udp0->checksum != 0)
	{
	  ip_csum_t sum = udp0->checksum;
	  cgnat_l4_checksum_update_ip (&sum, old_src, ip0->src_address);
	  cgnat_l4_checksum_update_port (&sum, old_port, s0->outside_port);
	  udp0->checksum = ip_csum_fold (sum);
	  if (udp0->checksum == 0)
	    udp0->checksum = 0xFFFF;
	}
      udp0->src_port = s0->outside_port;
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
	  cgnat_l4_checksum_update_port (&sum, old_port, s0->outside_port);
	  *id0 = s0->outside_port;
	  icmp0->checksum = ip_csum_fold (sum);
	}
    }
}

VLIB_NODE_FN (cgnat_in2out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 n_left_from, *from, *to_next;
  cgnat_in2out_next_t next_index;
  u32 pkts_translated = 0;
  u32 pkts_bypassed = 0;
  u32 pkts_dropped = 0;
  u32 pkts_hairpinned = 0;
  u32 pkts_slowpath = 0;
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
	  u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP;
	  ip4_header_t *ip0;
	  u32 sw_if_index0;
	  u16 src_port0 = 0, dst_port0 = 0;
	  u8 proto0;
	  u8 trace_action = CGNAT_TRACE_TRANSLATED;
	  cgnat_mapping_t *m0 = NULL;
	  cgnat_session_t *s0 = NULL;

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
	    int rerr = cgnat_in2out_ports_from_reass (b0, ip0, proto0,
						      &src_port0, &dst_port0);
	    if (PREDICT_FALSE (rerr))
	      {
		trace_action = CGNAT_TRACE_DROPPED;
		next0 = CGNAT_IN2OUT_NEXT_DROP;
		if (rerr == CGNAT_ERROR_FRAGMENT_DROP)
		  pkts_frag_drop++;
		else
		  pkts_no_reass++;
		b0->error = node->errors[rerr];
		goto trace;
	      }
	  }

	  u32 fib_index0 =
	    vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index0);

	  if (cgnat_bypass_check (&ip0->src_address, fib_index0))
	    {
	      trace_action = CGNAT_TRACE_BYPASSED;
	      vnet_feature_next (&next0, b0);
	      pkts_bypassed++;
	      goto trace;
	    }

	  /* Skip translation when dst is a local-receive address in this FIB
	   * (subscriber default gateway, BNG loopback, broadcast). Let
	   * ip4-lookup deliver to the receive DPO so LCP punts to Linux. */
	  if (PREDICT_FALSE (
		cgnat_is_local_receive (fib_index0, &ip0->dst_address)))
	    {
	      trace_action = CGNAT_TRACE_BYPASSED;
	      vnet_feature_next (&next0, b0);
	      pkts_bypassed++;
	      goto trace;
	    }

	  m0 = cgnat_mapping_lookup (&ip0->src_address, fib_index0);
	  if (PREDICT_FALSE (!m0))
	    {
	      trace_action = CGNAT_TRACE_DROPPED;
	      next0 = CGNAT_IN2OUT_NEXT_DROP;
	      pkts_dropped++;
	      b0->error = node->errors[CGNAT_ERROR_NO_MAPPING];
	      goto trace;
	    }

	  cgnat_pool_t *pool0 =
	    pool_elt_at_index (cm->pools, m0->pool_index);

	  if (PREDICT_FALSE (!pool0->outside_fib_valid))
	    {
	      trace_action = CGNAT_TRACE_DROPPED;
	      next0 = CGNAT_IN2OUT_NEXT_DROP;
	      pkts_dropped++;
	      b0->error = node->errors[CGNAT_ERROR_NO_POOL];
	      goto trace;
	    }

	  s0 = cgnat_session_lookup_in2out (&ip0->src_address,
					    &ip0->dst_address, src_port0,
					    dst_port0, proto0, fib_index0);

	  if (PREDICT_FALSE (!s0))
	    {
	      /* New flow: defer session create to the slow node. */
	      next0 = CGNAT_IN2OUT_NEXT_SLOWPATH;
	      trace_action = CGNAT_TRACE_SLOWPATH;
	      pkts_slowpath++;
	      goto trace;
	    }

	  cgnat_in2out_translate (vm, b0, ip0, s0, proto0, src_port0, now);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = pool0->outside_fib_index;

	  if (PREDICT_FALSE (cgnat_is_hairpin (cm, &ip0->dst_address)))
	    {
	      next0 = CGNAT_IN2OUT_NEXT_HAIRPIN;
	      trace_action = CGNAT_TRACE_HAIRPINNED;
	      pkts_hairpinned++;
	    }
	  else
	    {
	      pkts_translated++;
	    }

	trace:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      cgnat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->src_ip = ip0->src_address;
	      t->dst_ip = ip0->dst_address;
	      t->src_port = src_port0;
	      t->dst_port = dst_port0;
	      t->proto = proto0;
	      t->action = trace_action;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_TRANSLATED, pkts_translated);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_BYPASSED, pkts_bypassed);
  vlib_node_increment_counter (vm, node->node_index, CGNAT_ERROR_DROP,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_HAIRPINNED, pkts_hairpinned);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_NO_REASS_METADATA, pkts_no_reass);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_FRAGMENT_DROP, pkts_frag_drop);
  /* pkts_slowpath flows through to the slow node which owns the
   * SESSION_CREATE counter; we don't double-count here. */
  (void) pkts_slowpath;

  return frame->n_vectors;
}

VLIB_NODE_FN (cgnat_in2out_slowpath_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 n_left_from, *from, *to_next;
  cgnat_in2out_next_t next_index;
  u32 pkts_translated = 0;
  u32 pkts_created = 0;
  u32 pkts_dropped = 0;
  u32 pkts_hairpinned = 0;
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
	  u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP;
	  ip4_header_t *ip0;
	  u32 sw_if_index0;
	  u16 src_port0 = 0, dst_port0 = 0;
	  u8 proto0;
	  u8 trace_action = CGNAT_TRACE_CREATED;
	  cgnat_mapping_t *m0 = NULL;
	  cgnat_session_t *s0 = NULL;

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
	    int rerr = cgnat_in2out_ports_from_reass (b0, ip0, proto0,
						      &src_port0, &dst_port0);
	    if (PREDICT_FALSE (rerr))
	      {
		trace_action = CGNAT_TRACE_DROPPED;
		next0 = CGNAT_IN2OUT_NEXT_DROP;
		if (rerr == CGNAT_ERROR_FRAGMENT_DROP)
		  pkts_frag_drop++;
		else
		  pkts_no_reass++;
		b0->error = node->errors[rerr];
		goto trace;
	      }
	  }

	  u32 fib_index0 =
	    vec_elt (ip4_main.fib_index_by_sw_if_index, sw_if_index0);

	  /* Re-lookup the mapping. The fast path already verified it existed,
	   * but mappings can be deleted between the fast-path lookup and the
	   * slow-path arrival (concurrent control-plane reconfig). Cheap
	   * bihash hit on the new-session path only. */
	  m0 = cgnat_mapping_lookup (&ip0->src_address, fib_index0);
	  if (PREDICT_FALSE (!m0))
	    {
	      trace_action = CGNAT_TRACE_DROPPED;
	      next0 = CGNAT_IN2OUT_NEXT_DROP;
	      pkts_dropped++;
	      b0->error = node->errors[CGNAT_ERROR_NO_MAPPING];
	      goto trace;
	    }

	  cgnat_pool_t *pool0 =
	    pool_elt_at_index (cm->pools, m0->pool_index);

	  if (PREDICT_FALSE (!pool0->outside_fib_valid))
	    {
	      trace_action = CGNAT_TRACE_DROPPED;
	      next0 = CGNAT_IN2OUT_NEXT_DROP;
	      pkts_dropped++;
	      b0->error = node->errors[CGNAT_ERROR_NO_POOL];
	      goto trace;
	    }

	  /* A packet for an existing session may end up here if it raced
	   * a concurrent create from another flow's first packet. Re-check
	   * the session table before allocating a fresh port. */
	  s0 = cgnat_session_lookup_in2out (&ip0->src_address,
					    &ip0->dst_address, src_port0,
					    dst_port0, proto0, fib_index0);

	  if (!s0)
	    {
	      u16 outside_port0 = cgnat_port_alloc (m0, now);
	      if (PREDICT_FALSE (outside_port0 == 0))
		{
		  trace_action = CGNAT_TRACE_DROPPED;
		  next0 = CGNAT_IN2OUT_NEXT_DROP;
		  pkts_dropped++;
		  b0->error = node->errors[CGNAT_ERROR_PORT_EXHAUSTED];
		  goto trace;
		}

	      s0 = cgnat_session_create (m0, &ip0->dst_address, dst_port0,
					 proto0, outside_port0, src_port0,
					 now);
	      if (PREDICT_FALSE (!s0))
		{
		  cgnat_port_free (m0, outside_port0);
		  trace_action = CGNAT_TRACE_DROPPED;
		  next0 = CGNAT_IN2OUT_NEXT_DROP;
		  pkts_dropped++;
		  b0->error = node->errors[CGNAT_ERROR_SESSION_LIMIT];
		  goto trace;
		}

	      pkts_created++;
	    }
	  else
	    {
	      trace_action = CGNAT_TRACE_TRANSLATED;
	    }

	  cgnat_in2out_translate (vm, b0, ip0, s0, proto0, src_port0, now);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = pool0->outside_fib_index;

	  if (PREDICT_FALSE (cgnat_is_hairpin (cm, &ip0->dst_address)))
	    {
	      next0 = CGNAT_IN2OUT_NEXT_HAIRPIN;
	      trace_action = CGNAT_TRACE_HAIRPINNED;
	      pkts_hairpinned++;
	    }
	  else
	    {
	      pkts_translated++;
	    }

	trace:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      cgnat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->src_ip = ip0->src_address;
	      t->dst_ip = ip0->dst_address;
	      t->src_port = src_port0;
	      t->dst_port = dst_port0;
	      t->proto = proto0;
	      t->action = trace_action;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_TRANSLATED, pkts_translated);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_SESSION_CREATE, pkts_created);
  vlib_node_increment_counter (vm, node->node_index, CGNAT_ERROR_DROP,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_HAIRPINNED, pkts_hairpinned);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_NO_REASS_METADATA, pkts_no_reass);
  vlib_node_increment_counter (vm, node->node_index,
			       CGNAT_ERROR_FRAGMENT_DROP, pkts_frag_drop);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cgnat_in2out_node) = {
  .name = "cgnat-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_N_ERROR,
  .error_strings = cgnat_error_strings,
  .n_next_nodes = CGNAT_IN2OUT_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [CGNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_IN2OUT_NEXT_HAIRPIN] = "cgnat-out2in",
    [CGNAT_IN2OUT_NEXT_SLOWPATH] = "cgnat-in2out-slowpath",
  },
};

VLIB_REGISTER_NODE (cgnat_in2out_slowpath_node) = {
  .name = "cgnat-in2out-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_N_ERROR,
  .error_strings = cgnat_error_strings,
  .n_next_nodes = CGNAT_IN2OUT_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [CGNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_IN2OUT_NEXT_HAIRPIN] = "cgnat-out2in",
    [CGNAT_IN2OUT_NEXT_SLOWPATH] = "error-drop",
  },
};

VNET_FEATURE_INIT (cgnat_in2out_feat, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-in2out",
  .runs_after = VNET_FEATURES ("ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
