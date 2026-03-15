/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 veesix ::networks
 *
 * osvbng IPoE Plugin - Input node
 *
 * Registered via ethernet_register_input_type() for IPv4/IPv6 ethertypes.
 * Runs after ethernet-input (VLAN classification complete, buffer at L3).
 * Recovers L2 header via ethernet_buffer_get_header() for session lookup.
 *
 * BNG interfaces: session lookup → rewrite sw_if_index → ip4/ip6-input
 * Non-BNG interfaces: bitmap miss → ip4/ip6-input (pass-through)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>

#include <osvbng_ipoe/osvbng_ipoe.h>

typedef struct
{
  u32 sw_if_index;
  u32 session_sw_if_index;
  u16 inner_vlan;
  u8 src_mac[6];
  u8 session_found;
  u8 is_ip4;
} ipoe_input_trace_t;

static u8 *
format_ipoe_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipoe_input_trace_t *t = va_arg (*args, ipoe_input_trace_t *);

  s = format (s, "ipoe-input: sw_if_index %d inner_vlan %d src_mac %U %s",
	      t->sw_if_index, t->inner_vlan, format_ethernet_address,
	      t->src_mac, t->is_ip4 ? "ip4" : "ip6");

  if (t->session_found)
    s = format (s, " -> session sw_if_index %d", t->session_sw_if_index);
  else
    s = format (s, " -> pass-through");

  return s;
}

always_inline u16
ipoe_recover_inner_vlan (ethernet_header_t *eth)
{
  u16 ethertype = clib_net_to_host_u16 (eth->type);
  u8 *p = (u8 *) (eth + 1);

  if (ethertype == ETHERNET_TYPE_DOT1AD || ethertype == ETHERNET_TYPE_VLAN)
    {
      ethernet_vlan_header_t *vlan1 = (ethernet_vlan_header_t *) p;
      u16 vlan1_id =
	clib_net_to_host_u16 (vlan1->priority_cfi_and_id) & 0xFFF;
      ethertype = clib_net_to_host_u16 (vlan1->type);
      p += sizeof (ethernet_vlan_header_t);

      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  ethernet_vlan_header_t *vlan2 = (ethernet_vlan_header_t *) p;
	  return clib_net_to_host_u16 (vlan2->priority_cfi_and_id) & 0xFFF;
	}
      else
	{
	  return vlan1_id;
	}
    }

  return 0;
}

VLIB_NODE_FN (ipoe_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ipoe_main_t *im = &ipoe_main;
  vnet_main_t *vnm = im->vnet_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  u32 pkts_passthrough = 0;
  u32 pkts_no_session = 0;

  ipoe_entry_key_t cached_key;
  ipoe_entry_result_t cached_result;
  cached_key.as_u64[0] = ~0ULL;
  cached_key.as_u64[1] = ~0ULL;
  cached_result.raw = ~0ULL;

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
	  u32 next0;
	  u32 sw_if_index0;
	  ip4_header_t *ip0;
	  u8 is_ip4;
	  ipoe_session_t *s0 = NULL;
	  u16 inner_vlan0 = 0;
	  u8 src_mac0[6] = { 0 };

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  ip0 = vlib_buffer_get_current (b0);
	  is_ip4 = (ip0->ip_version_and_header_length >> 4) == 4;
	  next0 = is_ip4 ? im->original_next_ip4 : im->original_next_ip6;

	  if (PREDICT_FALSE (
		!clib_bitmap_get (im->enabled_by_sw_if_index, sw_if_index0)))
	    {
	      pkts_passthrough++;
	      goto trace;
	    }

	  {
	    ethernet_header_t *eth0 =
	      ethernet_buffer_get_header (b0);
	    inner_vlan0 = ipoe_recover_inner_vlan (eth0);
	    clib_memcpy_fast (src_mac0, eth0->src_address, 6);
	  }

	  {
	    ipoe_entry_key_t key0;
	    ipoe_entry_result_t result0;

	    ipoe_lookup_1 (&im->session_table, &cached_key, &cached_result,
			   sw_if_index0, inner_vlan0, src_mac0, &key0,
			   &result0);

	    if (PREDICT_TRUE (result0.raw != ~0ULL))
	      {
		s0 = pool_elt_at_index (im->sessions,
					result0.fields.session_index);

		vnet_buffer (b0)->sw_if_index[VLIB_RX] = s0->sw_if_index;

		vlib_increment_combined_counter (
		  &vnm->interface_main
		     .combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
		  vm->thread_index, s0->sw_if_index, 1,
		  vlib_buffer_length_in_chain (vm, b0));

		pkts_processed++;
	      }
	    else
	      {
		pkts_no_session++;
	      }
	  }

	trace:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ipoe_input_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->inner_vlan = inner_vlan0;
	      clib_memcpy_fast (t->src_mac, src_mac0, 6);
	      t->session_found = (s0 != NULL);
	      t->session_sw_if_index = s0 ? s0->sw_if_index : ~0;
	      t->is_ip4 = is_ip4;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipoe_input_node.index,
			       IPOE_ERROR_DECAPSULATED, pkts_processed);
  vlib_node_increment_counter (vm, ipoe_input_node.index,
			       IPOE_ERROR_NO_SUCH_SESSION, pkts_no_session);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_input_node) = {
  .name = "ipoe-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipoe_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPOE_N_ERROR,
  .error_strings = ipoe_error_strings,
  .n_next_nodes = IPOE_INPUT_N_NEXT,
  .next_nodes = {
    [IPOE_INPUT_NEXT_DROP] = "error-drop",
    [IPOE_INPUT_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [IPOE_INPUT_NEXT_IP4_INPUT] = "ip4-input",
    [IPOE_INPUT_NEXT_IP6_INPUT] = "ip6-input",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
