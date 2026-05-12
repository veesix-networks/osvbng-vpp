/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * PPPoE Session (0x8864) handler.
 *
 * Three dispositions for an inbound PPPoE-session frame:
 *
 *   1. LAC-bridged session (is_lac_tunneled on the matched PPPoE
 *      session): forward the full PPP frame to `l2tpv2-output` with
 *      `vnet_buffer_l2tpv2_opaque(b)` set to the L2TPv2 session index.
 *      Catches IP and non-IP PPP frames uniformly so LCP/NCP/Echo
 *      bridge through to the LNS.
 *
 *   2. Non-LAC IP frame: forward to `osvbng-pppoe-input` for the data
 *      plane decap path (existing behaviour).
 *
 *   3. Non-LAC non-IP frame: punt to userspace via the punt SHM, or
 *      drop if the interface is not enabled (existing behaviour).
 *
 * The LAC lookup is gated on `osvbng_pppoe_main.lac_session_count` so
 * the common case (no LAC sessions configured) pays no extra cost.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <osvbng_punt/osvbng_punt.h>
#include <osvbng_pppoe/osvbng_pppoe.h>
#include <l2tpv2/l2tpv2.h>

#define PPP_PROTOCOL_ip4    0x0021
#define PPP_PROTOCOL_ip6    0x0057

typedef struct
{
  u32 sw_if_index;
  u16 ppp_proto;
  u8 disposition; /* 0=drop, 1=pppoe-input, 2=punt, 3=l2tpv2-output */
} osvbng_punt_pppoe_sess_trace_t;

#define foreach_osvbng_punt_pppoe_sess_error                                   \
  _ (PUNTED, "PPPoE control plane packets punted")                             \
  _ (PASSED_IP, "PPPoE IP packets passed to pppoe-input")                      \
  _ (DROPPED, "PPPoE packets dropped (socket error)")                          \
  _ (NOT_ENABLED, "PPPoE control plane dropped (punt not enabled)")            \
  _ (LAC_BRIDGED, "PPPoE frames bridged to l2tpv2-output (LAC)")               \
  _ (LAC_NO_PLUGIN, "LAC-tunneled PPPoE frames dropped (L2TPv2 plugin absent)")

typedef enum
{
#define _(sym, str) OSVBNG_PUNT_PPPOE_SESS_ERROR_##sym,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
    OSVBNG_PUNT_PPPOE_SESS_N_ERROR,
} osvbng_punt_pppoe_sess_error_t;

static char *osvbng_punt_pppoe_sess_error_strings[] = {
#define _(sym, string) string,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP,
  OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT,
  OSVBNG_PUNT_PPPOE_SESS_N_NEXT,
} osvbng_punt_pppoe_sess_next_t;

#define DISP_DROP	0
#define DISP_PPPOE_IN	1
#define DISP_PUNT	2
#define DISP_L2TPV2	3

static u8 *
format_osvbng_punt_pppoe_sess_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_pppoe_sess_trace_t *t =
    va_arg (*args, osvbng_punt_pppoe_sess_trace_t *);
  const char *disp = "drop";
  switch (t->disposition)
    {
    case DISP_PPPOE_IN:
      disp = "-> pppoe-input";
      break;
    case DISP_PUNT:
      disp = "punted";
      break;
    case DISP_L2TPV2:
      disp = "-> l2tpv2-output (LAC)";
      break;
    }
  s = format (s, "OSVBNG-PUNT-PPPOE-SESS: sw_if_index %d ppp_proto 0x%04x %s",
	      t->sw_if_index, t->ppp_proto, disp);
  return s;
}

always_inline int
ppp_proto_is_ip (u16 ppp_proto)
{
  return (ppp_proto == PPP_PROTOCOL_ip4 || ppp_proto == PPP_PROTOCOL_ip6);
}

/* Step back from current buffer position (PPPoE header) to the ethernet
 * header. Reads VLAN depth from the buffer flags set by ethernet-input. */
static_always_inline ethernet_header_t *
osvbng_punt_pppoe_sess_eth (vlib_buffer_t *b)
{
  u8 *cur = vlib_buffer_get_current (b);
  i32 eth_step = (i32) sizeof (ethernet_header_t);
  if (b->flags & VNET_BUFFER_F_VLAN_2_DEEP)
    eth_step += 2 * sizeof (ethernet_vlan_header_t);
  else if (b->flags & VNET_BUFFER_F_VLAN_1_DEEP)
    eth_step += sizeof (ethernet_vlan_header_t);
  return (ethernet_header_t *) (cur - eth_step);
}

/* Fall back to the original punt-to-userspace / drop path. Shared by
 * the non-LAC non-IP control plane disposition and the "LAC set but
 * L2TPv2 plugin not loaded" misconfiguration case — punting in the
 * latter lets the userspace control plane log and tear the session
 * down instead of dropping silently. */
static_always_inline u32
osvbng_punt_pppoe_sess_punt_or_drop (vlib_main_t *vm, vlib_buffer_t *b,
				     u32 sw_if_index, u8 *disp_out,
				     u32 *cnt_punted, u32 *cnt_drop,
				     u32 *cnt_not_enabled)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_PPPOE_SESSION],
		sw_if_index))
    {
      vlib_buffer_reset (b);
      if (osvbng_punt_send_packet (vm, b, sw_if_index,
				   OSVBNG_PUNT_PROTO_PPPOE_SESSION) == 0)
	{
	  *disp_out = DISP_PUNT;
	  (*cnt_punted)++;
	}
      else
	{
	  *disp_out = DISP_DROP;
	  (*cnt_drop)++;
	}
    }
  else
    {
      *disp_out = DISP_DROP;
      (*cnt_not_enabled)++;
    }
  return OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP;
}

/* Decide the next-arc for a single packet. Sets `*disp` for tracing.
 * The `cached_key` / `cached_result` pair carries the PPPoE single-
 * entry lookup cache across packets within one node call (mirrors the
 * pattern in osvbng-pppoe-input), so consecutive frames belonging to
 * the same subscriber skip the bihash search. */
static_always_inline u32
osvbng_punt_pppoe_sess_classify (vlib_main_t *vm, vlib_buffer_t *b,
				 u32 sw_if_index, u32 lac_session_count,
				 u32 l2tpv2_output_next,
				 pppoe_entry_key_t *cached_key,
				 pppoe_entry_result_t *cached_result,
				 u16 *ppp_proto_out, u8 *disp_out,
				 u32 *cnt_punted, u32 *cnt_ip, u32 *cnt_drop,
				 u32 *cnt_not_enabled, u32 *cnt_lac,
				 u32 *cnt_lac_no_plugin)
{
  pppoe_header_t *pppoe0 = vlib_buffer_get_current (b);
  u16 ppp_proto0 = 0;

  if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
    {
      *ppp_proto_out = 0;
      *disp_out = DISP_PPPOE_IN;
      (*cnt_ip)++;
      return OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT;
    }

  ppp_proto0 = clib_net_to_host_u16 (pppoe0->ppp_proto);
  *ppp_proto_out = ppp_proto0;

  /* LAC bridge check. Skipped entirely when there are no LAC-tunneled
   * sessions globally — the common case for terminating BNGs. */
  if (PREDICT_FALSE (lac_session_count > 0))
    {
      ethernet_header_t *eth = osvbng_punt_pppoe_sess_eth (b);
      pppoe_entry_key_t key0;
      pppoe_entry_result_t result0;
      u32 bucket0;
      pppoe_lookup_1 (&osvbng_pppoe_main.session_table, cached_key,
		      cached_result, eth->src_address, pppoe0->session_id,
		      &key0, &bucket0, &result0);

      if (result0.fields.session_index != ~0)
	{
	  osvbng_pppoe_session_t *sess = pool_elt_at_index (
	    osvbng_pppoe_main.sessions, result0.fields.session_index);
	  if (sess->is_lac_tunneled)
	    {
	      if (l2tpv2_output_next != ~0u)
		{
		  vnet_buffer_l2tpv2_opaque (b) = sess->lac_l2tp_session_index;
		  *disp_out = DISP_L2TPV2;
		  (*cnt_lac)++;
		  return l2tpv2_output_next;
		}
	      /* LAC flag set but L2TPv2 plugin not loaded — punt to
	       * userspace so the control plane can log this
	       * misconfiguration and tear the session down. Falling
	       * back silently to the IP / drop path would mis-handle
	       * the frame and hide the configuration error. */
	      (*cnt_lac_no_plugin)++;
	      return osvbng_punt_pppoe_sess_punt_or_drop (
		vm, b, sw_if_index, disp_out, cnt_punted, cnt_drop,
		cnt_not_enabled);
	    }
	}
    }

  if (ppp_proto_is_ip (ppp_proto0))
    {
      *disp_out = DISP_PPPOE_IN;
      (*cnt_ip)++;
      return OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT;
    }

  /* Non-IP control plane: punt to userspace if enabled, else drop. */
  return osvbng_punt_pppoe_sess_punt_or_drop (vm, b, sw_if_index, disp_out,
					      cnt_punted, cnt_drop,
					      cnt_not_enabled);
}

static_always_inline uword
osvbng_punt_pppoe_sess_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_punted = 0, pkts_ip = 0, pkts_dropped = 0, pkts_not_enabled = 0;
  u32 pkts_lac = 0, pkts_lac_no_plugin = 0;
  const u32 lac_count = osvbng_pppoe_main.lac_session_count;
  const u32 l2tpv2_out = pm->l2tpv2_output_next_arc;

  /* PPPoE single-entry lookup cache, lifetime = this node call. The
   * LAC dispatch path looks up the same session repeatedly under load
   * (one subscriber → many consecutive frames in a vector); keeping
   * the cache across the inner loop is what makes the lookup cheap. */
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;
  cached_key.raw = ~0;
  cached_result.raw = ~0;

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
	  u32 next0;
	  u32 sw_if_index0;
	  u16 ppp_proto0 = 0;
	  u8 disp0 = DISP_DROP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  next0 = osvbng_punt_pppoe_sess_classify (
	    vm, b0, sw_if_index0, lac_count, l2tpv2_out, &cached_key,
	    &cached_result, &ppp_proto0, &disp0, &pkts_punted, &pkts_ip,
	    &pkts_dropped, &pkts_not_enabled, &pkts_lac, &pkts_lac_no_plugin);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_pppoe_sess_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->ppp_proto = ppp_proto0;
	      t->disposition = disp0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_PUNTED, pkts_punted);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_PASSED_IP, pkts_ip);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_DROPPED,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_NOT_ENABLED,
			       pkts_not_enabled);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_LAC_BRIDGED,
			       pkts_lac);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_LAC_NO_PLUGIN,
			       pkts_lac_no_plugin);
  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_pppoe_sess_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return osvbng_punt_pppoe_sess_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_pppoe_sess_node) = {
  .name = "osvbng-punt-pppoe-sess",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_pppoe_sess_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_punt_pppoe_sess_error_strings),
  .error_strings = osvbng_punt_pppoe_sess_error_strings,
  .n_next_nodes = OSVBNG_PUNT_PPPOE_SESS_N_NEXT,
  .next_nodes = {
    [OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP] = "error-drop",
    [OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT] = "osvbng-pppoe-input",
  },
};

/* Resolve the dynamic next-arc to `l2tpv2-output`. Called from
 * `osvbng_pppoe_set_lac_tunnel()` (in the PPPoE plugin) on the first
 * LAC binding, by which point the L2TPv2 plugin's graph nodes are
 * guaranteed to exist if it is loaded. Idempotent. Exposed via
 * osvbng_punt.h for the PPPoE plugin to call. */
void
osvbng_punt_pppoe_sess_resolve_l2tpv2_arc (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  if (pm->l2tpv2_output_next_arc != ~0u)
    return;
  vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "l2tpv2-output");
  if (n)
    pm->l2tpv2_output_next_arc =
      vlib_node_add_next (vm, osvbng_punt_pppoe_sess_node.index, n->index);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
