/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng L2GW Plugin - input node
 *
 * Registered on the device-input feature arc (before ethernet-input) so it
 * sees every frame on armed ports regardless of ethertype. Matched frames
 * are tag-rewritten in place and enqueued directly to the egress
 * interface's output node; misses continue down the arc into
 * ethernet-input and the normal (trunk / punt) path.
 *
 * Deliberate consequence: switched frames bypass the interface-output
 * feature arc on the egress port. L2GW circuits carry their own counters.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>

#include <osvbng_l2gw/osvbng_l2gw.h>
#include <osvbng_punt/osvbng_punt.h>

#define L2GW_MAX_TX_OUTPUTS 8
#define L2GW_INPUT_NEXT_DROP_INDEX 0

typedef struct
{
  u32 output_node_index;
  vlib_frame_t *f;
  u32 *to_next;
  u32 n_vectors;
} l2gw_tx_pending_t;

typedef struct
{
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u16 rx_svlan;
  u16 rx_cvlan;
  u16 tx_svlan;
  u16 tx_cvlan;
  u8 matched;
  u8 wildcard;
} l2gw_input_trace_t;

static u8 *
format_l2gw_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2gw_input_trace_t *t = va_arg (*args, l2gw_input_trace_t *);

  if (t->matched)
    s = format (s,
		"l2gw-input: rx sw_if_index %d svlan %d cvlan %d %s-> tx "
		"sw_if_index %d svlan %d cvlan %d",
		t->rx_sw_if_index, t->rx_svlan, t->rx_cvlan,
		t->wildcard ? "(wildcard) " : "", t->tx_sw_if_index,
		t->tx_svlan, t->tx_cvlan);
  else
    s = format (s, "l2gw-input: rx sw_if_index %d svlan %d cvlan %d -> "
		"pass-through",
		t->rx_sw_if_index, t->rx_svlan, t->rx_cvlan);
  return s;
}

always_inline int
l2gw_is_tag_tpid (u16 ethertype)
{
  return ethertype == ETHERNET_TYPE_VLAN || ethertype == ETHERNET_TYPE_DOT1AD ||
	 ethertype == ETHERNET_TYPE_VLAN_9100;
}

/* Parse up to two VLAN tags at b->current (ethernet header).
 * Returns number of tags; fills VIDs and the outer/inner TCI
 * priority bits (PCP/DEI, TCI & 0xF000). */
always_inline u8
l2gw_parse_tags (ethernet_header_t *eth, u16 *svlan, u16 *cvlan,
		 u16 *outer_prio, u16 *inner_prio)
{
  u16 type = clib_net_to_host_u16 (eth->type);
  u8 *p = (u8 *) (eth + 1);
  u8 n_tags = 0;

  *svlan = 0;
  *cvlan = 0;
  *outer_prio = 0;
  *inner_prio = 0;

  if (l2gw_is_tag_tpid (type))
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) p;
      u16 tci = clib_net_to_host_u16 (vlan->priority_cfi_and_id);
      *svlan = tci & 0xFFF;
      *outer_prio = tci & 0xF000;
      type = clib_net_to_host_u16 (vlan->type);
      p += sizeof (ethernet_vlan_header_t);
      n_tags = 1;

      if (l2gw_is_tag_tpid (type))
	{
	  vlan = (ethernet_vlan_header_t *) p;
	  tci = clib_net_to_host_u16 (vlan->priority_cfi_and_id);
	  *cvlan = tci & 0xFFF;
	  *inner_prio = tci & 0xF000;
	  n_tags = 2;
	}
    }

  return n_tags;
}

always_inline int
l2gw_trigger_armed (l2gw_main_t *lm, u32 sw_if_index, u16 svlan)
{
  if (svlan == 0 || sw_if_index >= vec_len (lm->trigger_svlans))
    return 0;
  uword *bm = lm->trigger_svlans[sw_if_index];
  return bm && clib_bitmap_get (bm, svlan);
}

always_inline int
l2gw_trigger_any_armed (l2gw_main_t *lm, u32 sw_if_index, u16 svlan)
{
  if (svlan == 0 || sw_if_index >= vec_len (lm->trigger_any_svlans))
    return 0;
  uword *bm = lm->trigger_any_svlans[sw_if_index];
  return bm && clib_bitmap_get (bm, svlan);
}

/* Per-tuple punt suppression for the any-protocol trigger. Unlike the
 * DHCP snoop, this path is not paced by client retransmit timers: an
 * unknown line sending line-rate traffic would otherwise punt every
 * frame. Overwrite-on-punt keeps the table bounded by the armed tuple
 * count; racing workers may double-punt once, which the control-plane
 * dedup absorbs. */
always_inline int
l2gw_trigger_dampen_allow (l2gw_main_t *lm, vlib_main_t *vm, u32 sw_if_index,
			   u16 svlan, u16 cvlan)
{
  clib_bihash_kv_8_8_t kv, result;
  f64 now = vlib_time_now (vm);
  f64 last;

  kv.key = ((u64) sw_if_index << 32) | ((u64) svlan << 16) | (u64) cvlan;

  if (clib_bihash_search_8_8 (&lm->trigger_dampener, &kv, &result) == 0)
    {
      clib_memcpy_fast (&last, &result.value, sizeof (last));
      if (now - last < lm->trigger_dampen_interval)
	return 0;
    }

  clib_memcpy_fast (&kv.value, &now, sizeof (kv.value));
  clib_bihash_add_del_8_8 (&lm->trigger_dampener, &kv, 1);
  return 1;
}

/* DHCP trigger recognition on the circuit-miss path: fixed-offset
 * compares only. IPv6 extension headers are deliberately not walked —
 * a SOLICIT behind an extension chain falls through untouched and the
 * client retransmits plainly. */
always_inline int
l2gw_frame_is_dhcp_trigger (vlib_buffer_t *b, ethernet_header_t *eth,
			    u8 n_tags, u8 *punt_proto)
{
  u8 *p = (u8 *) (eth + 1) + n_tags * sizeof (ethernet_vlan_header_t);
  u16 type = n_tags ? clib_net_to_host_u16 (((u16 *) p)[-1]) :
		      clib_net_to_host_u16 (eth->type);
  u32 l2_len = (u32) (p - (u8 *) eth);

  if (PREDICT_FALSE (b->current_length < l2_len))
    return 0;
  u32 avail = b->current_length - l2_len;

  if (type == ETHERNET_TYPE_IP4)
    {
      if (avail < sizeof (ip4_header_t) + sizeof (udp_header_t))
	return 0;
      ip4_header_t *ip = (ip4_header_t *) p;
      if (ip->protocol != IP_PROTOCOL_UDP)
	return 0;
      u32 ihl = ip4_header_bytes (ip);
      if (avail < ihl + sizeof (udp_header_t))
	return 0;
      udp_header_t *udp = (udp_header_t *) (p + ihl);
      if (udp->dst_port != clib_host_to_net_u16 (67))
	return 0;
      *punt_proto = OSVBNG_PUNT_PROTO_DHCPV4;
      return 1;
    }

  if (type == ETHERNET_TYPE_IP6)
    {
      if (avail < sizeof (ip6_header_t) + sizeof (udp_header_t))
	return 0;
      ip6_header_t *ip6 = (ip6_header_t *) p;
      if (ip6->protocol != IP_PROTOCOL_UDP)
	return 0;
      udp_header_t *udp = (udp_header_t *) (p + sizeof (ip6_header_t));
      if (udp->dst_port != clib_host_to_net_u16 (547))
	return 0;
      *punt_proto = OSVBNG_PUNT_PROTO_DHCPV6;
      return 1;
    }

  return 0;
}

/* Rebuild the tag stack in place to the entry's TX form. The payload
 * (from the final ethertype onward) never moves; only the DA/SA block
 * shifts when the tag count changes. */
always_inline void
l2gw_rewrite (vlib_buffer_t *b, l2gw_entry_t *e, u8 n_rx_tags,
	      u16 outer_prio, u16 inner_prio)
{
  ethernet_header_t *eth;
  u8 n_tx_tags;

  if (e->flags & L2GW_ENTRY_F_TRANSPARENT)
    return;

  if (e->flags & L2GW_ENTRY_F_WILDCARD)
    {
      /* Outer-tag translate only; inner tags untouched. Wildcard match
       * guarantees at least one RX tag. */
      eth = vlib_buffer_get_current (b);
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eth + 1);
      eth->type = clib_host_to_net_u16 (e->tx_outer_tpid);
      vlan->priority_cfi_and_id =
	clib_host_to_net_u16 (outer_prio | e->tx_svlan);
      return;
    }

  n_tx_tags = (e->tx_svlan ? 1 : 0) + (e->tx_cvlan ? 1 : 0);

  if (n_tx_tags != n_rx_tags)
    {
      u8 mac_block[12];
      i16 delta_bytes =
	((i16) n_tx_tags - (i16) n_rx_tags) * sizeof (ethernet_vlan_header_t);

      eth = vlib_buffer_get_current (b);
      clib_memcpy_fast (mac_block, eth, 12);
      vlib_buffer_advance (b, -delta_bytes);
      eth = vlib_buffer_get_current (b);
      clib_memcpy_fast (eth, mac_block, 12);
    }
  else
    {
      eth = vlib_buffer_get_current (b);
    }

  u8 *p = (u8 *) (eth + 1);

  if (n_tx_tags == 0)
    return;

  eth->type = clib_host_to_net_u16 (e->tx_outer_tpid);
  ethernet_vlan_header_t *outer = (ethernet_vlan_header_t *) p;
  outer->priority_cfi_and_id = clib_host_to_net_u16 (outer_prio | e->tx_svlan);

  if (n_tx_tags == 2)
    {
      outer->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      ethernet_vlan_header_t *inner = outer + 1;
      inner->priority_cfi_and_id =
	clib_host_to_net_u16 (inner_prio | e->tx_cvlan);
      /* inner->type is the payload ethertype, already in place when
       * shrinking/equal; when growing from 0/1 tags it now sits exactly
       * where the pre-move ethertype landed — also already correct. */
    }
  /* single tag: outer->type is the payload ethertype, already in place */
}

VLIB_NODE_FN (l2gw_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  l2gw_main_t *lm = &l2gw_main;
  vnet_main_t *vnm = lm->vnet_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 thread_index = vm->thread_index;
  u32 pkts_switched = 0, pkts_no_circuit = 0, pkts_disabled = 0;
  u32 pkts_tx_unresolved = 0, pkts_trigger_punted = 0;
  u32 pkts_trigger_dampened = 0;

  l2gw_tx_pending_t pending[L2GW_MAX_TX_OUTPUTS];
  u32 n_pending = 0;

  l2gw_key_t cached_exact_key, cached_wild_key;
  l2gw_result_t cached_exact_result, cached_wild_result;
  cached_exact_key.as_u64[0] = ~0ULL;
  cached_exact_key.as_u64[1] = ~0ULL;
  cached_wild_key.as_u64[0] = ~0ULL;
  cached_wild_key.as_u64[1] = ~0ULL;
  cached_exact_result.raw = ~0ULL;
  cached_wild_result.raw = ~0ULL;

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
	  u32 sw_if_index0;
	  u16 svlan0, cvlan0, outer_prio0, inner_prio0;
	  u8 n_tags0;
	  l2gw_entry_t *e0 = NULL;
	  l2gw_result_t result0;
	  u8 matched0 = 0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  ethernet_header_t *eth0 = vlib_buffer_get_current (b0);
	  n_tags0 =
	    l2gw_parse_tags (eth0, &svlan0, &cvlan0, &outer_prio0,
			     &inner_prio0);

	  l2gw_lookup_1 (&lm->circuit_table, &cached_exact_key,
			 &cached_exact_result, sw_if_index0, svlan0, cvlan0,
			 &result0);

	  if (result0.raw == ~0ULL && svlan0 != 0)
	    l2gw_lookup_1 (&lm->circuit_table, &cached_wild_key,
			   &cached_wild_result, sw_if_index0, svlan0,
			   L2GW_CVLAN_ANY, &result0);

	  if (PREDICT_TRUE (result0.raw != ~0ULL))
	    {
	      e0 = pool_elt_at_index (lm->entries, result0.fields.entry_index);

	      if (PREDICT_FALSE (!(e0->flags & L2GW_ENTRY_F_ENABLED)))
		{
		  pkts_disabled++;
		  e0 = NULL;
		}
	      else
		matched0 = 1;
	    }
	  else
	    pkts_no_circuit++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2gw_input_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = sw_if_index0;
	      t->rx_svlan = svlan0;
	      t->rx_cvlan = cvlan0;
	      t->matched = matched0;
	      t->wildcard = e0 ? !!(e0->flags & L2GW_ENTRY_F_WILDCARD) : 0;
	      t->tx_sw_if_index = e0 ? e0->tx_sw_if_index : ~0;
	      t->tx_svlan = e0 ? e0->tx_svlan : 0;
	      t->tx_cvlan = e0 ? e0->tx_cvlan : 0;
	    }

	  if (!matched0)
	    {
	      u32 next0;
	      u8 punt_proto0 = 0;
	      u8 do_punt0 = 0;

	      if (PREDICT_FALSE (lm->punt_shm_tx_next_arc != ~0u))
		{
		  if (PREDICT_FALSE (
			l2gw_trigger_any_armed (lm, sw_if_index0, svlan0)))
		    {
		      if (l2gw_trigger_dampen_allow (lm, vm, sw_if_index0,
						     svlan0, cvlan0))
			{
			  punt_proto0 = OSVBNG_PUNT_PROTO_L2GW_TRIGGER;
			  do_punt0 = 1;
			}
		      else
			pkts_trigger_dampened++;
		    }
		  else if (PREDICT_FALSE (
			     l2gw_trigger_armed (lm, sw_if_index0, svlan0) &&
			     l2gw_frame_is_dhcp_trigger (b0, eth0, n_tags0,
							 &punt_proto0)))
		    do_punt0 = 1;
		}

	      if (PREDICT_FALSE (do_punt0))
		{
		  vnet_buffer_punt_protocol (b0) = punt_proto0;
		  next0 = lm->punt_shm_tx_next_arc;
		  pkts_trigger_punted++;
		}
	      else
		vnet_feature_next (&next0, b0);
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi0, next0);
	      continue;
	    }

	  if (PREDICT_FALSE (
		pool_is_free_index (vnm->interface_main.sw_interfaces,
				    e0->tx_sw_if_index)))
	    {
	      pkts_tx_unresolved++;
	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	      vlib_validate_buffer_enqueue_x1 (
		vm, node, next_index, to_next, n_left_to_next, bi0,
		L2GW_INPUT_NEXT_DROP_INDEX);
	      continue;
	    }

	  vlib_increment_combined_counter (
	    &lm->counters, thread_index, result0.fields.entry_index, 1,
	    vlib_buffer_length_in_chain (vm, b0));

	  l2gw_rewrite (b0, e0, n_tags0, outer_prio0, inner_prio0);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = e0->tx_sw_if_index;

	  vnet_hw_interface_t *hw =
	    vnet_get_sup_hw_interface (vnm, e0->tx_sw_if_index);
	  u32 out_node = hw->output_node_index;

	  l2gw_tx_pending_t *p = NULL;
	  for (u32 i = 0; i < n_pending; i++)
	    if (pending[i].output_node_index == out_node)
	      {
		p = &pending[i];
		break;
	      }

	  if (!p)
	    {
	      if (PREDICT_FALSE (n_pending >= L2GW_MAX_TX_OUTPUTS))
		{
		  vlib_frame_t *f = vlib_get_frame_to_node (vm, out_node);
		  u32 *tn = vlib_frame_vector_args (f);
		  tn[0] = bi0;
		  f->n_vectors = 1;
		  vlib_put_frame_to_node (vm, out_node, f);
		  pkts_switched++;
		  continue;
		}
	      p = &pending[n_pending++];
	      p->output_node_index = out_node;
	      p->f = vlib_get_frame_to_node (vm, out_node);
	      p->to_next = vlib_frame_vector_args (p->f);
	      p->n_vectors = 0;
	    }

	  p->to_next[p->n_vectors++] = bi0;
	  pkts_switched++;

	  if (PREDICT_FALSE (p->n_vectors >= VLIB_FRAME_SIZE))
	    {
	      p->f->n_vectors = p->n_vectors;
	      vlib_put_frame_to_node (vm, p->output_node_index, p->f);
	      *p = pending[--n_pending];
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  for (u32 i = 0; i < n_pending; i++)
    {
      pending[i].f->n_vectors = pending[i].n_vectors;
      vlib_put_frame_to_node (vm, pending[i].output_node_index, pending[i].f);
    }

  vlib_node_increment_counter (vm, l2gw_input_node.index, L2GW_ERROR_SWITCHED,
			       pkts_switched);
  vlib_node_increment_counter (vm, l2gw_input_node.index,
			       L2GW_ERROR_NO_CIRCUIT, pkts_no_circuit);
  vlib_node_increment_counter (vm, l2gw_input_node.index, L2GW_ERROR_DISABLED,
			       pkts_disabled);
  vlib_node_increment_counter (vm, l2gw_input_node.index,
			       L2GW_ERROR_TX_UNRESOLVED, pkts_tx_unresolved);
  vlib_node_increment_counter (vm, l2gw_input_node.index,
			       L2GW_ERROR_TRIGGER_PUNTED, pkts_trigger_punted);
  vlib_node_increment_counter (vm, l2gw_input_node.index,
			       L2GW_ERROR_TRIGGER_DAMPENED,
			       pkts_trigger_dampened);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (l2gw_input_node) = {
  .name = "l2gw-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2gw_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = L2GW_N_ERROR,
  .error_strings = l2gw_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/* After bond-input so VLIB_RX is the bond sw_if_index on LAG members
 * (circuit keys reference the bond, not individual members). */
VNET_FEATURE_INIT (l2gw_input_feat, static) = {
  .arc_name = "device-input",
  .node_name = "l2gw-input",
  .runs_after = VNET_FEATURES ("bond-input"),
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
