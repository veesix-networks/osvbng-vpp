/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Copyright (c) 2025 veesix ::networks
 *
 * Based on VPP pppoe plugin decap node, adapted for osvbng_pppoe.
 *
 * This node is called by osvbng_punt for PPPoE session IP traffic.
 * Buffer position: points at PPPoE header (ethernet-input already parsed L2).
 * We reset buffer to get full L2 header for MAC address lookup.
 */

#include <vlib/vlib.h>
#include <ppp/packet.h>
#include <osvbng_pppoe/osvbng_pppoe.h>
#include <osvbng_punt/osvbng_punt.h>

/* Lazily resolve the dynamic next-arcs into sibling plugins. Called on
 * first need; idempotent. Lookups happen by graph-node name, so no
 * cross-plugin symbol reference is required at link time. */
static_always_inline void
pppoe_input_resolve_arcs (vlib_main_t *vm, u32 this_node_index,
			  osvbng_pppoe_main_t *pem)
{
  if (PREDICT_TRUE (pem->l2tpv2_output_next_arc != ~0u
		    && pem->punt_shm_tx_next_arc != ~0u))
    return;
  if (pem->l2tpv2_output_next_arc == ~0u)
    {
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "l2tpv2-output");
      if (n)
	pem->l2tpv2_output_next_arc =
	  vlib_node_add_next (vm, this_node_index, n->index);
    }
  if (pem->punt_shm_tx_next_arc == ~0u)
    {
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "osvbng-punt-shm-tx");
      if (n)
	pem->punt_shm_tx_next_arc =
	  vlib_node_add_next (vm, this_node_index, n->index);
    }
}

typedef struct {
  u32 next_index;
  u32 session_index;
  u32 session_id;
  u32 error;
} pppoe_rx_trace_t;

static u8 * format_pppoe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_rx_trace_t * t = va_arg (*args, pppoe_rx_trace_t *);

  if (t->session_index != ~0)
    {
      s = format (s, "osvbng-pppoe decap from pppoe_session%d session_id %d next %d error %d",
                  t->session_index, t->session_id, t->next_index, t->error);
    }
  else
    {
      s = format (s, "osvbng-pppoe decap error - session for session_id %d does not exist",
                  t->session_id);
    }
  return s;
}

VLIB_NODE_FN (osvbng_pppoe_input_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  osvbng_pppoe_main_t * pem = &osvbng_pppoe_main;
  vnet_main_t * vnm = pem->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;

  /* Resolve dynamic next-arcs (l2tpv2-output, osvbng-punt-shm-tx) at
   * first frame so sibling plugin nodes are guaranteed to be
   * registered. Cheap to call repeatedly — early-out once both are
   * resolved. */
  pppoe_input_resolve_arcs (vm, osvbng_pppoe_input_node.index, pem);

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          ethernet_header_t *h0;
          ethernet_vlan_header_t *vlan0 = 0;
          pppoe_header_t * pppoe0;
          u16 ppp_proto0 = 0;
          osvbng_pppoe_session_t * t0;
          u32 error0;
          u32 sw_if_index0, len0;
          pppoe_entry_key_t key0;
          pppoe_entry_result_t result0;
          u32 bucket0;
          u32 type0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          error0 = 0;

          /* Reset buffer to ethernet header to get client MAC */
          vlib_buffer_reset (b0);
          h0 = vlib_buffer_get_current (b0);

          /* Parse through VLAN tags to get to PPPoE header */
          type0 = clib_net_to_host_u16 (h0->type);

          if (type0 == ETHERNET_TYPE_VLAN)
            {
              vlan0 = (ethernet_vlan_header_t *) (h0 + 1);
              type0 = clib_net_to_host_u16 (vlan0->type);

              /* Handle Q-in-Q: check for second VLAN tag */
              if (type0 == ETHERNET_TYPE_VLAN)
                {
                  ethernet_vlan_header_t *inner_vlan = (ethernet_vlan_header_t *) (vlan0 + 1);
                  type0 = clib_net_to_host_u16 (inner_vlan->type);
                  pppoe0 = (pppoe_header_t *) (inner_vlan + 1);
                }
              else
                {
                  pppoe0 = (pppoe_header_t *) (vlan0 + 1);
                }

              if (type0 != ETHERNET_TYPE_PPPOE_SESSION)
                {
                  error0 = PPPOE_ERROR_BAD_VER_TYPE;
                  result0.fields.session_index = ~0;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
                }
            }
          else if (type0 == ETHERNET_TYPE_DOT1AD)
            {
              /* Q-in-Q with 0x88a8 outer */
              vlan0 = (ethernet_vlan_header_t *) (h0 + 1);
              type0 = clib_net_to_host_u16 (vlan0->type);

              if (type0 == ETHERNET_TYPE_VLAN)
                {
                  ethernet_vlan_header_t *inner_vlan = (ethernet_vlan_header_t *) (vlan0 + 1);
                  type0 = clib_net_to_host_u16 (inner_vlan->type);
                  pppoe0 = (pppoe_header_t *) (inner_vlan + 1);
                }
              else
                {
                  pppoe0 = (pppoe_header_t *) (vlan0 + 1);
                }

              if (type0 != ETHERNET_TYPE_PPPOE_SESSION)
                {
                  error0 = PPPOE_ERROR_BAD_VER_TYPE;
                  result0.fields.session_index = ~0;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
                }
            }
          else
            {
              pppoe0 = (pppoe_header_t *) (h0 + 1);
            }

          ppp_proto0 = clib_net_to_host_u16 (pppoe0->ppp_proto);

          /* Look up the session first. Both IP traffic and non-IP control
           * traffic (LCP/NCP/Echo) are dispatched per-session: IP frames
           * decap to ip4/ip6-input, LAC-tunneled frames go to
           * l2tpv2-output, the rest punt to userspace via the shared
           * osvbng-punt-shm-tx graph node. */
          pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
                          h0->src_address, pppoe0->session_id,
                          &key0, &bucket0, &result0);

          if (PREDICT_FALSE (result0.fields.session_index == ~0))
            {
              error0 = PPPOE_ERROR_NO_SUCH_SESSION;
              next0 = PPPOE_INPUT_NEXT_DROP;
              goto trace00;
            }

          t0 = pool_elt_at_index (pem->sessions, result0.fields.session_index);

          /* LAC bridge: forward the FULL PPP frame (Eth+VLAN+PPPoE+PPP)
           * to l2tpv2-output. No header strip — the L2TPv2 plugin's
           * encap-raw node consumes the buffer with PPP intact and
           * prepends Eth+IP+UDP+L2TP+PPP via midchain rewrite. The opaque
           * carries the L2TPv2 session pool index for fast session
           * lookup at the encap node. Caught here covers IP and non-IP
           * (LCP/NCP/Echo) frames uniformly so all PPP control bridges
           * through to the LNS. */
          if (PREDICT_FALSE (t0->is_lac_tunneled))
            {
              if (PREDICT_FALSE (pem->l2tpv2_output_next_arc == ~0u))
                {
                  error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
                }
              /* Stash the L2TPv2 session pool index in opaque2[0] —
               * l2tpv2-encap-raw consumes this slot to look up the
               * session pool entry. Slot convention is defined in
               * osvbng-vpp-plugin-l2tp/l2tpv2.h:vnet_buffer_l2tpv2_opaque
               * (kept in sync by code review, not by header include —
               * we deliberately avoid coupling to that header). */
              b0->opaque2[0] = t0->lac_l2tp_session_index;
              next0 = pem->l2tpv2_output_next_arc;
              goto trace00;
            }

          /* Non-IP PPP (LCP/NCP/Echo) on a terminating PPPoE session:
           * punt to the userspace control plane via the shared SHM
           * service node. Buffer stays at the eth header — SHM consumer
           * parses the full L2 frame. */
          if ((ppp_proto0 != PPP_PROTOCOL_ip4) &&
              (ppp_proto0 != PPP_PROTOCOL_ip6))
            {
              if (PREDICT_FALSE (pem->punt_shm_tx_next_arc == ~0u))
                {
                  error0 = PPPOE_ERROR_BAD_VER_TYPE;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
                }
              vnet_buffer_punt_protocol (b0) = OSVBNG_PUNT_PROTO_PPPOE_SESSION;
              next0 = pem->punt_shm_tx_next_arc;
              goto trace00;
            }

          /* IP traffic on a terminating session: pop headers, hand off
           * to ip4/ip6-input for normal forwarding. */
          {
            u32 advance = sizeof (*h0) + sizeof (*pppoe0);
            if (t0->outer_vlan != 0 && t0->inner_vlan != 0)
              advance += 2 * sizeof (ethernet_vlan_header_t);
            else if (t0->outer_vlan != 0)
              advance += sizeof (ethernet_vlan_header_t);

            vlib_buffer_advance (b0, advance);
          }

          next0 = (ppp_proto0 == PPP_PROTOCOL_ip4) ?
            PPPOE_INPUT_NEXT_IP4_INPUT : PPPOE_INPUT_NEXT_IP6_INPUT;

          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain (vm, b0);
          vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

          pkts_decapsulated++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

          /* Batch stats increment on the same pppoe session */
          if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
            {
              stats_n_packets -= 1;
              stats_n_bytes -= len0;
              if (stats_n_packets)
                vlib_increment_combined_counter
                  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
                   thread_index, stats_sw_if_index,
                   stats_n_packets, stats_n_bytes);
              stats_n_packets = 1;
              stats_n_bytes = len0;
              stats_sw_if_index = sw_if_index0;
            }

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                             && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              pppoe_rx_trace_t *tr =
                vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->session_index = result0.fields.session_index;
              tr->session_id = clib_net_to_host_u16 (pppoe0->session_id);
            }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, osvbng_pppoe_input_node.index,
                               PPPOE_ERROR_DECAPSULATED,
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
        (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
         thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
char * pppoe_error_strings[] = {
#define pppoe_error(n,s) s,
#include <osvbng_pppoe/osvbng_pppoe_error.def>
#undef pppoe_error
};
#endif /* CLIB_MARCH_VARIANT */

VLIB_REGISTER_NODE (osvbng_pppoe_input_node) = {
  .name = "osvbng-pppoe-input",
  .vector_size = sizeof (u32),
  .n_errors = PPPOE_N_ERROR,
  .error_strings = pppoe_error_strings,
  .n_next_nodes = PPPOE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_INPUT_NEXT_##s] = n,
    foreach_pppoe_input_next
#undef _
  },
  .format_trace = format_pppoe_rx_trace,
};
