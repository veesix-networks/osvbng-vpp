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

#define ETHERNET_TYPE_PPPOE_DISCOVERY 0x8863
#define ETHERNET_TYPE_VLAN            0x8100
#define ETHERNET_TYPE_DOT1AD          0x88a8

typedef struct
{
  u32 sw_if_index;
  u8 punted;
  u8 is_pppoe_disc;
} osvbng_punt_pppoe_disc_trace_t;

#define foreach_osvbng_punt_pppoe_disc_error \
  _(PUNTED, "PPPoE Discovery packets punted") \
  _(DROPPED, "PPPoE Discovery packets dropped (socket error)") \
  _(PASSED, "Non-PPPoE Discovery packets passed")

typedef enum
{
#define _(sym,str) OSVBNG_PUNT_PPPOE_DISC_ERROR_##sym,
  foreach_osvbng_punt_pppoe_disc_error
#undef _
    OSVBNG_PUNT_PPPOE_DISC_N_ERROR,
} osvbng_punt_pppoe_disc_error_t;

static char *osvbng_punt_pppoe_disc_error_strings[] = {
#define _(sym,string) string,
  foreach_osvbng_punt_pppoe_disc_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_PPPOE_DISC_NEXT_DROP,
  OSVBNG_PUNT_PPPOE_DISC_N_NEXT,
} osvbng_punt_pppoe_disc_next_t;

static u8 *
format_osvbng_punt_pppoe_disc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_pppoe_disc_trace_t *t =
    va_arg (*args, osvbng_punt_pppoe_disc_trace_t *);

  s = format (s, "sw_if_index %d %s",
	      t->sw_if_index,
	      t->is_pppoe_disc ? (t->punted ? "punted" : "dropped") : "passed");
  return s;
}

always_inline u16
get_ethertype (vlib_buffer_t * b0)
{
  ethernet_header_t *eth0 = vlib_buffer_get_current (b0);
  u16 ethertype = clib_net_to_host_u16 (eth0->type);

  if (ethertype == ETHERNET_TYPE_VLAN || ethertype == ETHERNET_TYPE_DOT1AD)
    {
      ethernet_vlan_header_t *vlan0 = (ethernet_vlan_header_t *) (eth0 + 1);
      ethertype = clib_net_to_host_u16 (vlan0->type);

      if (ethertype == ETHERNET_TYPE_VLAN)
	{
	  vlan0 = (ethernet_vlan_header_t *) ((u8 *) vlan0 +
					      sizeof (ethernet_vlan_header_t));
	  ethertype = clib_net_to_host_u16 (vlan0->type);
	}
    }

  return ethertype;
}

static_always_inline uword
osvbng_punt_pppoe_disc_inline (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_punted = 0, pkts_dropped = 0, pkts_passed = 0;

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
	  u16 ethertype0, ethertype1;
	  u8 punted0 = 0, punted1 = 0;
	  u8 is_disc0 = 0, is_disc1 = 0;

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

	  ethertype0 = get_ethertype (b0);
	  ethertype1 = get_ethertype (b1);

	  if (ethertype0 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      is_disc0 = 1;
	      if (osvbng_punt_send_packet (b0, sw_if_index0,
					   OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY) == 0)
		{
		  pkts_punted++;
		  punted0 = 1;
		}
	      else
		{
		  pkts_dropped++;
		}
	      next0 = OSVBNG_PUNT_PPPOE_DISC_NEXT_DROP;
	    }
	  else
	    {
	      pkts_passed++;
	    }

	  if (ethertype1 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      is_disc1 = 1;
	      if (osvbng_punt_send_packet (b1, sw_if_index1,
					   OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY) == 0)
		{
		  pkts_punted++;
		  punted1 = 1;
		}
	      else
		{
		  pkts_dropped++;
		}
	      next1 = OSVBNG_PUNT_PPPOE_DISC_NEXT_DROP;
	    }
	  else
	    {
	      pkts_passed++;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  osvbng_punt_pppoe_disc_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->punted = punted0;
		  t->is_pppoe_disc = is_disc0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  osvbng_punt_pppoe_disc_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->punted = punted1;
		  t->is_pppoe_disc = is_disc1;
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
	  u16 ethertype0;
	  u8 punted0 = 0;
	  u8 is_disc0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  vnet_feature_next (&next0, b0);

	  ethertype0 = get_ethertype (b0);

	  if (ethertype0 == ETHERNET_TYPE_PPPOE_DISCOVERY)
	    {
	      is_disc0 = 1;
	      if (osvbng_punt_send_packet (b0, sw_if_index0,
					   OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY) == 0)
		{
		  pkts_punted++;
		  punted0 = 1;
		}
	      else
		{
		  pkts_dropped++;
		}
	      next0 = OSVBNG_PUNT_PPPOE_DISC_NEXT_DROP;
	    }
	  else
	    {
	      pkts_passed++;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_pppoe_disc_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->punted = punted0;
	      t->is_pppoe_disc = is_disc0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_DISC_ERROR_PUNTED,
			       pkts_punted);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_DISC_ERROR_DROPPED,
			       pkts_dropped);
  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_DISC_ERROR_PASSED,
			       pkts_passed);

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_pppoe_disc_node) (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    vlib_frame_t * frame)
{
  return osvbng_punt_pppoe_disc_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_pppoe_disc_node) = {
  .name = "osvbng-punt-pppoe-disc",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_pppoe_disc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_punt_pppoe_disc_error_strings),
  .error_strings = osvbng_punt_pppoe_disc_error_strings,
  .n_next_nodes = OSVBNG_PUNT_PPPOE_DISC_N_NEXT,
  .next_nodes = {
    [OSVBNG_PUNT_PPPOE_DISC_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (osvbng_punt_pppoe_disc, static) = {
  .arc_name = "device-input",
  .node_name = "osvbng-punt-pppoe-disc",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
