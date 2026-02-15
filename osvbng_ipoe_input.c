/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 veesix ::networks
 *
 * osvbng IPoE Plugin - Input node
 * Processes incoming packets, performs session lookup, sets RX counters.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>

#include <osvbng_ipoe/osvbng_ipoe.h>

typedef struct
{
  u32 sw_if_index;
  u32 session_sw_if_index;
  u16 inner_vlan;
  u8 src_mac[6];
  u8 session_found;
} ipoe_input_trace_t;

static u8 *
format_ipoe_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipoe_input_trace_t *t = va_arg (*args, ipoe_input_trace_t *);

  s = format (s, "ipoe-input: sw_if_index %d inner_vlan %d src_mac %U",
              t->sw_if_index, t->inner_vlan, format_ethernet_address,
              t->src_mac);

  if (t->session_found)
    s = format (s, " -> session sw_if_index %d", t->session_sw_if_index);
  else
    s = format (s, " -> no session");

  return s;
}

/*
 * Parse C-VLAN from packet header
 *
 * Traffic arrives on S-VLAN sub-interface (sw_if_index encodes S-VLAN).
 * C-VLAN may still be in the packet header if no C-VLAN sub-interface exists.
 *
 * Returns the C-VLAN ID (0 if no C-VLAN tag present).
 */
always_inline u16
ipoe_parse_inner_vlan (ethernet_header_t *eth, u16 *ethertype_out)
{
  u16 ethertype = clib_net_to_host_u16 (eth->type);
  u8 *p = (u8 *) (eth + 1);
  u16 inner_vlan = 0;

  /* Check for VLAN tags */
  if (ethertype == ETHERNET_TYPE_DOT1AD || ethertype == ETHERNET_TYPE_VLAN)
    {
      /* First tag present (could be S-VLAN or C-VLAN depending on sub-if) */
      ethernet_vlan_header_t *vlan1 = (ethernet_vlan_header_t *) p;
      u16 vlan1_id =
        clib_net_to_host_u16 (vlan1->priority_cfi_and_id) & 0xFFF;
      ethertype = clib_net_to_host_u16 (vlan1->type);
      p += sizeof (ethernet_vlan_header_t);

      if (ethertype == ETHERNET_TYPE_VLAN)
        {
          /* Second tag present - this is the C-VLAN */
          ethernet_vlan_header_t *vlan2 = (ethernet_vlan_header_t *) p;
          inner_vlan =
            clib_net_to_host_u16 (vlan2->priority_cfi_and_id) & 0xFFF;
          ethertype = clib_net_to_host_u16 (vlan2->type);
        }
      else
        {
          /* Only one tag - treat as C-VLAN if arrived on S-VLAN sub-if */
          inner_vlan = vlan1_id;
        }
    }

  *ethertype_out = ethertype;
  return inner_vlan;
}

VLIB_NODE_FN (ipoe_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ipoe_main_t *im = &ipoe_main;
  vnet_main_t *vnm = im->vnet_main;
  u32 n_left_from, *from, *to_next;
  ipoe_input_next_t next_index;
  u32 pkts_processed = 0;
  u32 pkts_no_session = 0;

  /* One-entry cache for back-to-back packets from same subscriber */
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
          u32 next0 = IPOE_INPUT_NEXT_ETHERNET_INPUT;
          u32 sw_if_index0;
          ethernet_header_t *eth0;
          u16 ethertype0;
          u16 inner_vlan0;
          ipoe_entry_key_t key0;
          ipoe_entry_result_t result0;
          ipoe_session_t *s0 = NULL;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
          eth0 = vlib_buffer_get_current (b0);

          /* Parse C-VLAN from packet header */
          inner_vlan0 = ipoe_parse_inner_vlan (eth0, &ethertype0);

          /* Only process IP packets - let others pass through */
          if (PREDICT_TRUE (ethertype0 == ETHERNET_TYPE_IP4 ||
                            ethertype0 == ETHERNET_TYPE_IP6))
            {
              /* Lookup session by (sw_if_index + inner_vlan + src_mac) */
              ipoe_lookup_1 (&im->session_table, &cached_key, &cached_result,
                             sw_if_index0, inner_vlan0, eth0->src_address,
                             &key0, &result0);

              if (PREDICT_TRUE (result0.raw != ~0ULL))
                {
                  /* Session found */
                  s0 = pool_elt_at_index (im->sessions,
                                          result0.fields.session_index);

                  /* Set RX interface to ipoe_session for counters + FIB */
                  vnet_buffer (b0)->sw_if_index[VLIB_RX] = s0->sw_if_index;

                  /* Increment RX counters on ipoe_session */
                  vlib_increment_combined_counter (
                    &vnm->interface_main
                       .combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
                    vm->thread_index, s0->sw_if_index, 1,
                    vlib_buffer_length_in_chain (vm, b0));

                  /* Strip L2 headers (Eth + VLANs) to expose IP header */
                  {
                    u32 l2_len = sizeof (ethernet_header_t);
                    if (s0->outer_vlan != 0 && s0->inner_vlan != 0)
                      l2_len += 2 * sizeof (ethernet_vlan_header_t);
                    else if (s0->outer_vlan != 0 || s0->inner_vlan != 0)
                      l2_len += sizeof (ethernet_vlan_header_t);
                    vlib_buffer_advance (b0, l2_len);
                  }

                  /* Dispatch directly to IP input */
                  next0 = (ethertype0 == ETHERNET_TYPE_IP4) ?
                    IPOE_INPUT_NEXT_IP4_INPUT : IPOE_INPUT_NEXT_IP6_INPUT;

                  pkts_processed++;
                }
              else
                {
                  /* No session - pass to ethernet-input (punt handles DHCP) */
                  pkts_no_session++;
                }
            }

          /* Non-IP and unmatched packets: next0 stays ETHERNET_INPUT (default) */

          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                             (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              ipoe_input_trace_t *t =
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
              t->inner_vlan = inner_vlan0;
              clib_memcpy_fast (t->src_mac, eth0->src_address, 6);
              t->session_found = (s0 != NULL);
              t->session_sw_if_index = s0 ? s0->sw_if_index : ~0;
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
 * Feature arc registration - runs on device-input before ethernet-input
 */
VNET_FEATURE_INIT (ipoe_input_feat, static) = {
  .arc_name = "device-input",
  .node_name = "ipoe-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
