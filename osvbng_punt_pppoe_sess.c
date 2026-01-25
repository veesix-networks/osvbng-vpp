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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/feature/feature.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
  u16 ppp_proto;
} pppoe_header_t;

#define PPPOE_VER_TYPE 0x11

#define PPP_PROTOCOL_ip4    0x0021
#define PPP_PROTOCOL_ip6    0x0057
#define PPP_PROTOCOL_lcp    0xc021
#define PPP_PROTOCOL_pap    0xc023
#define PPP_PROTOCOL_chap   0xc223
#define PPP_PROTOCOL_ipcp   0x8021
#define PPP_PROTOCOL_ipv6cp 0x8057

#define ETHERNET_TYPE_PPPOE_SESSION 0x8864
#define ETHERNET_TYPE_VLAN          0x8100
#define ETHERNET_TYPE_DOT1AD        0x88a8

typedef struct
{
  u32 sw_if_index;
  u16 ppp_proto;
  u8 punted;
  u8 is_ip;
} osvbng_punt_pppoe_sess_trace_t;

#define foreach_osvbng_punt_pppoe_sess_error \
  _(PUNTED, "PPPoE control plane packets punted") \
  _(PASSED, "PPPoE IP packets passed to fast path") \
  _(DROPPED, "PPPoE packets dropped (socket error)")

typedef enum
{
#define _(sym,str) OSVBNG_PUNT_PPPOE_SESS_ERROR_##sym,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
    OSVBNG_PUNT_PPPOE_SESS_N_ERROR,
} osvbng_punt_pppoe_sess_error_t;

static char *osvbng_punt_pppoe_sess_error_strings[] = {
#define _(sym,string) string,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP,
  OSVBNG_PUNT_PPPOE_SESS_N_NEXT,
} osvbng_punt_pppoe_sess_next_t;

static u8 *
format_osvbng_punt_pppoe_sess_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_pppoe_sess_trace_t *t =
    va_arg (*args, osvbng_punt_pppoe_sess_trace_t *);

  s = format (s, "sw_if_index %d ppp_proto 0x%04x %s",
	      t->sw_if_index, t->ppp_proto,
	      t->is_ip ? "-> fast-path" : (t->punted ? "-> punted" : "-> dropped"));
  return s;
}

always_inline int
ppp_proto_is_ip (u16 ppp_proto)
{
  return (ppp_proto == PPP_PROTOCOL_ip4 || ppp_proto == PPP_PROTOCOL_ip6);
}

always_inline pppoe_header_t *
get_pppoe_header (vlib_buffer_t * b0, u16 * ethertype_out)
{
  ethernet_header_t *eth0;
  u16 ethertype;
  u32 offset = sizeof (ethernet_header_t);

  eth0 = vlib_buffer_get_current (b0);
  ethertype = clib_net_to_host_u16 (eth0->type);

  if (ethertype == ETHERNET_TYPE_VLAN || ethertype == ETHERNET_TYPE_DOT1AD)
    {
      ethernet_vlan_header_t *vlan0 = (ethernet_vlan_header_t *) (eth0 + 1);
      ethertype = clib_net_to_host_u16 (vlan0->type);
      offset += sizeof (ethernet_vlan_header_t);

      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vlan0 = (ethernet_vlan_header_t *) ((u8 *) eth0 + offset);
	  ethertype = clib_net_to_host_u16 (vlan0->type);
	  offset += sizeof (ethernet_vlan_header_t);
	}
    }

  if (ethertype_out)
    *ethertype_out = ethertype;

  if (PREDICT_FALSE (ethertype != ETHERNET_TYPE_PPPOE_SESSION))
    return NULL;

  pppoe_header_t *pppoe0 = (pppoe_header_t *) ((u8 *) eth0 + offset);

  if (PREDICT_FALSE (pppoe0->ver_type != PPPOE_VER_TYPE))
    return NULL;

  return pppoe0;
}

static_always_inline uword
osvbng_punt_pppoe_sess_inline (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_punted = 0, pkts_passed = 0, pkts_dropped = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  pppoe_header_t *pppoe0, *pppoe1;
	  u16 ppp_proto0 = 0, ppp_proto1 = 0;
	  u16 ethertype0, ethertype1;
	  u8 punted0 = 0, punted1 = 0;
	  u8 is_ip0 = 0, is_ip1 = 0;

	  {
	    vlib_buffer_t *p2, *p3;
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  pppoe0 = get_pppoe_header (b0, &ethertype0);
	  pppoe1 = get_pppoe_header (b1, &ethertype1);

	  if (pppoe0)
	    {
	      ppp_proto0 = clib_net_to_host_u16 (pppoe0->ppp_proto);
	      if (ppp_proto_is_ip (ppp_proto0))
		{
		  is_ip0 = 1;
		  pkts_passed++;
		}
	      else
		{
		  if (osvbng_punt_send_packet (b0, sw_if_index0,
					       OSVBNG_PUNT_PROTO_PPPOE_SESSION) == 0)
		    {
		      pkts_punted++;
		      punted0 = 1;
		    }
		  else
		    {
		      pkts_dropped++;
		    }
		  next0 = OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP;
		}
	    }

	  if (pppoe1)
	    {
	      ppp_proto1 = clib_net_to_host_u16 (pppoe1->ppp_proto);
	      if (ppp_proto_is_ip (ppp_proto1))
		{
		  is_ip1 = 1;
		  pkts_passed++;
		}
	      else
		{
		  if (osvbng_punt_send_packet (b1, sw_if_index1,
					       OSVBNG_PUNT_PROTO_PPPOE_SESSION) == 0)
		    {
		      pkts_punted++;
		      punted1 = 1;
		    }
		  else
		    {
		      pkts_dropped++;
		    }
		  next1 = OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP;
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  osvbng_punt_pppoe_sess_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->ppp_proto = ppp_proto0;
		  t->punted = punted0;
		  t->is_ip = is_ip0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  osvbng_punt_pppoe_sess_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->ppp_proto = ppp_proto1;
		  t->punted = punted1;
		  t->is_ip = is_ip1;
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  pppoe_header_t *pppoe0;
	  u16 ppp_proto0 = 0;
	  u16 ethertype0;
	  u8 punted0 = 0;
	  u8 is_ip0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  vnet_feature_next (&next0, b0);

	  pppoe0 = get_pppoe_header (b0, &ethertype0);
	  if (pppoe0)
	    {
	      ppp_proto0 = clib_net_to_host_u16 (pppoe0->ppp_proto);
	      if (ppp_proto_is_ip (ppp_proto0))
		{
		  is_ip0 = 1;
		  pkts_passed++;
		}
	      else
		{
		  if (osvbng_punt_send_packet (b0, sw_if_index0,
					       OSVBNG_PUNT_PROTO_PPPOE_SESSION) == 0)
		    {
		      pkts_punted++;
		      punted0 = 1;
		    }
		  else
		    {
		      pkts_dropped++;
		    }
		  next0 = OSVBNG_PUNT_PPPOE_SESS_NEXT_DROP;
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_pppoe_sess_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->ppp_proto = ppp_proto0;
	      t->punted = punted0;
	      t->is_ip = is_ip0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_PUNTED,
			       pkts_punted);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_PASSED,
			       pkts_passed);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_DROPPED,
			       pkts_dropped);

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_pppoe_sess_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
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
  },
};

VNET_FEATURE_INIT (osvbng_punt_pppoe_sess, static) = {
  .arc_name = "device-input",
  .node_name = "osvbng-punt-pppoe-sess",
  .runs_before = VNET_FEATURES ("pppoe-input", "ethernet-input"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
