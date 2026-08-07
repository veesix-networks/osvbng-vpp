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

/* Dynamic next-arcs (l2tpv2-encap-raw, osvbng-punt-shm-tx) are resolved
 * once at plugin init in osvbng_pppoe_init (osvbng_pppoe.c) — must run
 * on the main thread per vlib_node_add_next's thread-0 assertion. */

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

/* Mirrors the VLAN walk below to build the lookahead packet's key and warm
 * its session-table bucket. The L2 header of the CURRENT frame starts at
 * l2_hdr_offset (which is b->data on physical ports but sits past the
 * encapsulation on tunnel paths); read the same bytes without touching
 * the buffer. */
static_always_inline void
pppoe_prefetch_bucket (osvbng_pppoe_main_t * pem, vlib_buffer_t * b)
{
  ethernet_header_t *h;
  if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
    h = (ethernet_header_t *) (b->data + vnet_buffer (b)->l2_hdr_offset);
  else
    h = (ethernet_header_t *) b->data;
  u16 type = clib_net_to_host_u16 (h->type);
  pppoe_header_t *pppoe;

  if (type == ETHERNET_TYPE_VLAN || type == ETHERNET_TYPE_DOT1AD)
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (h + 1);
      if (clib_net_to_host_u16 (vlan->type) == ETHERNET_TYPE_VLAN)
        pppoe = (pppoe_header_t *) ((ethernet_vlan_header_t *) (vlan + 1) + 1);
      else
        pppoe = (pppoe_header_t *) (vlan + 1);
    }
  else
    pppoe = (pppoe_header_t *) (h + 1);

  BVT (clib_bihash_kv) kv;
  kv.key = pppoe_make_key (h->src_address, pppoe->session_id);

  BV (clib_bihash_prefetch_bucket) (&pem->session_table,
                                    BV (clib_bihash_hash) (&kv));
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

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_get_buffers (vm, from, bufs, n_left_from);

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
          b0 = b[0];

          if (PREDICT_TRUE (n_left_from >= 5))
            vlib_prefetch_buffer_header (b[4], LOAD);

          if (PREDICT_TRUE (n_left_from >= 3))
            pppoe_prefetch_bucket (pem, b[2]);

          to_next[0] = bi0;
          from += 1;
          b += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;
          error0 = 0;

          /* Rewind to the L2 header of the CURRENT frame to get the
           * client MAC; on tunnel paths the inner frame sits deep in
           * the buffer, so a reset to data start would parse the outer
           * encapsulation. */
          if (b0->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
            vlib_buffer_advance (b0, vnet_buffer (b0)->l2_hdr_offset -
                                       b0->current_data);
          else
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

          /* Non-IP PPP (LCP/NCP/CHAP/Echo) always punts to userspace —
           * the Go control plane drives PPP negotiation. This branch
           * is taken BEFORE the session is in the bihash (LCP frames
           * arrive between PADS-sent and AAA-success) AND for non-LAC
           * sessions in steady state. LAC sessions take the bridge path
           * below regardless of ppp_proto, so check is_lac_tunneled
           * before punting non-IP. */
          int is_ip0 = (ppp_proto0 == PPP_PROTOCOL_ip4) ||
                       (ppp_proto0 == PPP_PROTOCOL_ip6);

          pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
                          h0->src_address, pppoe0->session_id,
                          &key0, &bucket0, &result0);

          /* LAC bridge: covers all PPP protocols (LCP/NCP/IP/Echo) so
           * subscriber control plane bridges transparently to the LNS.
           * Only triggered if the session is in the bihash and tagged
           * is_lac_tunneled — which means AAA completed and Go enabled
           * the bridge flag via osvbng_pppoe_set_lac_tunnel. */
          if (PREDICT_FALSE (result0.fields.session_index != ~0))
            {
              t0 = pool_elt_at_index (pem->sessions,
                                      result0.fields.session_index);
              if (PREDICT_FALSE (t0->is_lac_tunneled))
                {
                  if (PREDICT_FALSE (pem->l2tpv2_encap_raw_next_arc == ~0u))
                    {
                      error0 = PPPOE_ERROR_NO_SUCH_SESSION;
                      next0 = PPPOE_INPUT_NEXT_DROP;
                      goto trace00;
                    }
                  /* Strip Ethernet + VLAN(s) + PPPoE-only header so
                   * the buffer is positioned at the PPP frame's
                   * ppp_proto field. L2TP carries the full PPP frame
                   * (ppp_proto + payload) per RFC 2661 §3.3, so we
                   * intentionally do NOT advance past ppp_proto —
                   * unlike the IP-decap branch below which advances
                   * past it to land on the IP header.
                   *
                   * pppoe_header_t includes ppp_proto (8 bytes total),
                   * so subtract sizeof(u16) to keep it. */
                  u32 advance = sizeof (*h0) + sizeof (*pppoe0) - sizeof (u16);
                  if (t0->outer_vlan != 0 && t0->inner_vlan != 0)
                    advance += 2 * sizeof (ethernet_vlan_header_t);
                  else if (t0->outer_vlan != 0)
                    advance += sizeof (ethernet_vlan_header_t);
                  vlib_buffer_advance (b0, advance);

                  /* Stash the L2TPv2 session pool index in opaque2[0] —
                   * l2tpv2-encap-raw reads this slot to look up the
                   * session. Slot convention defined in
                   * osvbng-vpp-plugin-l2tp/l2tpv2.h:vnet_buffer_l2tpv2_opaque
                   * — deliberately not coupled by include. */
                  b0->opaque2[0] = t0->lac_l2tp_session_index;
                  next0 = pem->l2tpv2_encap_raw_next_arc;
                  goto trace00;
                }
            }
          else
            {
              t0 = 0;
            }

          /* Non-IP PPP frame: punt to userspace via the shared SHM
           * service. Works whether or not the session is in the bihash
           * (covers the pre-PADS-complete window for both LAC and local
           * termination flows). */
          if (!is_ip0)
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

          /* IP frame without a session: cannot decap. Drop. */
          if (PREDICT_FALSE (t0 == 0))
            {
              error0 = PPPOE_ERROR_NO_SUCH_SESSION;
              next0 = PPPOE_INPUT_NEXT_DROP;
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
