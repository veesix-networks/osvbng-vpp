/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng-pppoe-lac-tx — LNS-to-subscriber bridge node.
 *
 * Consumes raw PPP frames decapsulated by the L2TPv2 plugin in
 * DECAP_RAW mode. Reads the partner PPPoE session's sw_if_index from
 * vnet_buffer_l2tpv2_opaque, prepends Eth+VLAN+PPPoE+ppp_proto per
 * the session's MAC / VLAN / session-id state, and forwards to
 * interface-output for TX out the access interface.
 *
 * Buffer at entry: positioned at the PPP frame, which starts with the
 * 2-byte PPP protocol field. We strip those 2 bytes from the buffer
 * before prepending the full PPPoE header (which carries the
 * ppp_proto inside it), so the inner payload position lines up with
 * what subscribers expect on the wire.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <osvbng_pppoe/osvbng_pppoe.h>
#include <l2tpv2/l2tpv2.h>

typedef struct
{
  u32 pppoe_sw_if_index;
  u32 pppoe_session_id;
  u16 ppp_proto;
  u32 error;
} osvbng_pppoe_lac_tx_trace_t;

static u8 *
format_osvbng_pppoe_lac_tx_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_pppoe_lac_tx_trace_t *t =
    va_arg (*args, osvbng_pppoe_lac_tx_trace_t *);
  s = format (s,
	      "osvbng-pppoe-lac-tx sw_if_index %d session_id %d "
	      "ppp_proto 0x%04x error %d",
	      t->pppoe_sw_if_index, t->pppoe_session_id, t->ppp_proto,
	      t->error);
  return s;
}

#define foreach_osvbng_pppoe_lac_tx_error                                      \
  _ (TXED, "PPP frames bridged to subscriber via PPPoE")                       \
  _ (NO_SUCH_SESSION, "PPP frames dropped (no PPPoE session)")                 \
  _ (TRUNCATED, "PPP frames dropped (no headroom for encap)")

typedef enum
{
#define _(sym, str) OSVBNG_PPPOE_LAC_TX_ERROR_##sym,
  foreach_osvbng_pppoe_lac_tx_error
#undef _
    OSVBNG_PPPOE_LAC_TX_N_ERROR,
} osvbng_pppoe_lac_tx_error_t;

static char *osvbng_pppoe_lac_tx_error_strings[] = {
#define _(sym, string) string,
  foreach_osvbng_pppoe_lac_tx_error
#undef _
};

typedef enum
{
  OSVBNG_PPPOE_LAC_TX_NEXT_DROP,
  OSVBNG_PPPOE_LAC_TX_NEXT_INTERFACE_OUTPUT,
  OSVBNG_PPPOE_LAC_TX_N_NEXT,
} osvbng_pppoe_lac_tx_next_t;

VLIB_NODE_FN (osvbng_pppoe_lac_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_txed = 0, pkts_no_session = 0, pkts_truncated = 0;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = OSVBNG_PPPOE_LAC_TX_NEXT_DROP;
	  u32 pppoe_sw_if_index = ~0;
	  u32 session_id_trace = 0;
	  u16 ppp_proto = 0;
	  u32 error0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  pppoe_sw_if_index = vnet_buffer_l2tpv2_opaque (b0);
	  if (PREDICT_FALSE (
		pppoe_sw_if_index >= vec_len (pem->session_index_by_sw_if_index)
		|| pem->session_index_by_sw_if_index[pppoe_sw_if_index]
		     == ~0u))
	    {
	      error0 = OSVBNG_PPPOE_LAC_TX_ERROR_NO_SUCH_SESSION;
	      pkts_no_session++;
	      goto trace00;
	    }

	  u32 sess_index =
	    pem->session_index_by_sw_if_index[pppoe_sw_if_index];
	  osvbng_pppoe_session_t *s =
	    pool_elt_at_index (pem->sessions, sess_index);
	  session_id_trace = s->session_id;

	  if (PREDICT_FALSE (b0->current_length < 2))
	    {
	      error0 = OSVBNG_PPPOE_LAC_TX_ERROR_TRUNCATED;
	      pkts_truncated++;
	      goto trace00;
	    }

	  ppp_proto = clib_net_to_host_u16 (*(u16 *) vlib_buffer_get_current (b0));

	  /* Strip the leading 2-byte PPP protocol field from the buffer;
	   * we re-insert it inside the PPPoE header. */
	  vlib_buffer_advance (b0, 2);

	  /* Make room for Eth + VLANs + PPPoE. */
	  u32 vlan_bytes = 0;
	  if (s->outer_vlan != 0 && s->inner_vlan != 0)
	    vlan_bytes = 2 * sizeof (ethernet_vlan_header_t);
	  else if (s->outer_vlan != 0)
	    vlan_bytes = sizeof (ethernet_vlan_header_t);
	  u32 encap_len = sizeof (ethernet_header_t) + vlan_bytes
			  + sizeof (pppoe_header_t);

	  if (PREDICT_FALSE (vlib_buffer_advance (b0, -(i32) encap_len) < 0))
	    {
	      error0 = OSVBNG_PPPOE_LAC_TX_ERROR_TRUNCATED;
	      pkts_truncated++;
	      goto trace00;
	    }

	  ethernet_header_t *eth = vlib_buffer_get_current (b0);
	  clib_memcpy (eth->dst_address, s->client_mac, 6);
	  clib_memcpy (eth->src_address, s->local_mac, 6);

	  u8 *p = (u8 *) (eth + 1);
	  if (s->outer_vlan != 0 && s->inner_vlan != 0)
	    {
	      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);
	      ethernet_vlan_header_t *o = (ethernet_vlan_header_t *) p;
	      o->priority_cfi_and_id = clib_host_to_net_u16 (s->outer_vlan);
	      o->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	      p += sizeof (*o);
	      ethernet_vlan_header_t *i = (ethernet_vlan_header_t *) p;
	      i->priority_cfi_and_id = clib_host_to_net_u16 (s->inner_vlan);
	      i->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
	      p += sizeof (*i);
	    }
	  else if (s->outer_vlan != 0)
	    {
	      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	      ethernet_vlan_header_t *v = (ethernet_vlan_header_t *) p;
	      v->priority_cfi_and_id = clib_host_to_net_u16 (s->outer_vlan);
	      v->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
	      p += sizeof (*v);
	    }
	  else
	    {
	      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
	    }

	  pppoe_header_t *pppoe = (pppoe_header_t *) p;
	  pppoe->ver_type = PPPOE_VER_TYPE;
	  pppoe->code = 0;
	  pppoe->session_id = clib_host_to_net_u16 (s->session_id);
	  /* PPPoE length covers ppp_proto + payload. */
	  pppoe->length = clib_host_to_net_u16 (
	    vlib_buffer_length_in_chain (vm, b0) -
	    (sizeof (ethernet_header_t) + vlan_bytes
	     + sizeof (pppoe_header_t) - sizeof (pppoe->ppp_proto)));
	  pppoe->ppp_proto = clib_host_to_net_u16 (ppp_proto);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = s->encap_if_index;
	  next0 = OSVBNG_PPPOE_LAC_TX_NEXT_INTERFACE_OUTPUT;
	  pkts_txed++;

	trace00:
	  b0->error = error0 ? node->errors[error0] : 0;
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_pppoe_lac_tx_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->pppoe_sw_if_index = pppoe_sw_if_index;
	      tr->pppoe_session_id = session_id_trace;
	      tr->ppp_proto = ppp_proto;
	      tr->error = error0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PPPOE_LAC_TX_ERROR_TXED, pkts_txed);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PPPOE_LAC_TX_ERROR_NO_SUCH_SESSION,
			       pkts_no_session);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PPPOE_LAC_TX_ERROR_TRUNCATED,
			       pkts_truncated);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_pppoe_lac_tx_node) = {
  .name = "osvbng-pppoe-lac-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_pppoe_lac_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_pppoe_lac_tx_error_strings),
  .error_strings = osvbng_pppoe_lac_tx_error_strings,
  .n_next_nodes = OSVBNG_PPPOE_LAC_TX_N_NEXT,
  .next_nodes = {
    [OSVBNG_PPPOE_LAC_TX_NEXT_DROP] = "error-drop",
    [OSVBNG_PPPOE_LAC_TX_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};
