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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_local.h>
#include <vnet/ip/ip4_packet.h>
#include <osvbng_punt/osvbng_punt.h>

/* T-bit (Message type) in the first byte of the L2TPv2 header.
 * RFC 2661 §3.1: T=1 control message, T=0 data message. */
#define L2TPV2_FLAG_T_MASK 0x80

typedef struct
{
  u32 sw_if_index;
  u16 src_port;
  u16 dst_port;
  u8 is_control;
  u8 dispatched_to_l2tpv2;
} osvbng_punt_l2tp_trace_t;

static u8 *
format_osvbng_punt_l2tp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_l2tp_trace_t *t = va_arg (*args, osvbng_punt_l2tp_trace_t *);

  s = format (s, "L2TP punt: sw_if_index %d, %d -> %d, %s%s",
	      t->sw_if_index, t->src_port, t->dst_port,
	      t->is_control ? "control" : "data",
	      t->is_control
		? " (punted to userspace)"
		: (t->dispatched_to_l2tpv2 ? " (to l2tpv2-input)"
					  : " (l2tpv2 plugin absent, drop)"));
  return s;
}

#define foreach_osvbng_punt_l2tp_next                                          \
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) OSVBNG_PUNT_L2TP_NEXT_##s,
  foreach_osvbng_punt_l2tp_next
#undef _
    OSVBNG_PUNT_L2TP_N_NEXT,
} osvbng_punt_l2tp_next_t;

static_always_inline uword
osvbng_punt_l2tp_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  const u32 l2tpv2_next = pm->l2tpv2_input_next_arc;

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
	  u32 next0 = OSVBNG_PUNT_L2TP_NEXT_DROP;
	  u32 sw_if_index0;
	  u8 *l2tp_hdr;
	  u8 is_control;
	  u8 dispatched = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Buffer is positioned at L2TP header (UDP has been processed by
	   * udp-local-port-1701 demux). Inspect the T-bit before deciding
	   * the path. */
	  l2tp_hdr = vlib_buffer_get_current (b0);
	  is_control = (l2tp_hdr[0] & L2TPV2_FLAG_T_MASK) != 0;

	  if (is_control &&
	      !hash_get (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_L2TP],
			 sw_if_index0))
	    {
	      /* Control frame on an interface with no L2TP punt: the global
	       * port registration delivered it, but this is not our
	       * subscriber. Drop rather than punt someone else's L2TP. */
	      next0 = OSVBNG_PUNT_L2TP_NEXT_DROP;
	    }
	  else if (is_control)
	    {
	      /* Control message: rewind to full L2 frame and hand off to
	       * userspace via the existing SHM channel. Behaviour
	       * unchanged from the pre-T-bit-dispatch code path. */
	      i16 rewind = sizeof (udp_header_t) + sizeof (ip4_header_t)
			   + sizeof (ethernet_header_t);

	      if (b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
		rewind += 2 * sizeof (ethernet_vlan_header_t);
	      else if (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
		rewind += sizeof (ethernet_vlan_header_t);

	      vlib_buffer_advance (b0, -rewind);

	      osvbng_punt_send_packet (vm, b0, sw_if_index0,
				       OSVBNG_PUNT_PROTO_L2TP);
	      pm->packets_punted[OSVBNG_PUNT_PROTO_L2TP]++;
	      next0 = OSVBNG_PUNT_L2TP_NEXT_DROP;
	    }
	  else if (l2tpv2_next != ~0u)
	    {
	      /* Data message and the L2TPv2 plugin is loaded: forward to
	       * its input node with the buffer still positioned at the
	       * L2TP header (l2tpv2-input expects that). */
	      next0 = l2tpv2_next;
	      dispatched = 1;
	    }
	  else
	    {
	      /* Data message but no L2TPv2 plugin loaded: drop. */
	      pm->packets_dropped[OSVBNG_PUNT_PROTO_L2TP]++;
	      next0 = OSVBNG_PUNT_L2TP_NEXT_DROP;
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_l2tp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->is_control = is_control;
	      t->dispatched_to_l2tpv2 = dispatched;
	      if (is_control)
		{
		  ip4_header_t *ip0 = (ip4_header_t *) (vlib_buffer_get_current (b0)
						       + sizeof (ethernet_header_t)
						       + ((b0->flags & VNET_BUFFER_F_VLAN_2_DEEP)
							    ? 2 * sizeof (ethernet_vlan_header_t)
							    : (b0->flags & VNET_BUFFER_F_VLAN_1_DEEP)
								? sizeof (ethernet_vlan_header_t)
								: 0));
		  udp_header_t *udp0 = ip4_next_header (ip0);
		  t->src_port = clib_net_to_host_u16 (udp0->src_port);
		  t->dst_port = clib_net_to_host_u16 (udp0->dst_port);
		}
	      else
		{
		  t->src_port = 0;
		  t->dst_port = 1701;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (osvbng_punt_l2tp_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return osvbng_punt_l2tp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (osvbng_punt_l2tp_node) = {
  .name = "osvbng-punt-l2tp",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_l2tp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = OSVBNG_PUNT_L2TP_N_NEXT,
  .next_nodes = {
#define _(s, n) [OSVBNG_PUNT_L2TP_NEXT_##s] = n,
    foreach_osvbng_punt_l2tp_next
#undef _
  },
};

/* Resolve the dynamic next-arc from this node to l2tpv2-input. Called
 * from `osvbng_punt_enable_l2tp` so the resolution happens after all
 * plugins have finished init. Idempotent. */
static void
osvbng_punt_l2tp_resolve_next_arc (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (pm->l2tpv2_input_next_arc != ~0u)
    return;

  vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) "l2tpv2-input");
  if (n)
    pm->l2tpv2_input_next_arc =
      vlib_node_add_next (vm, osvbng_punt_l2tp_node.index, n->index);
}

int
osvbng_punt_enable_l2tp (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;
  u32 node_index;

  node_index = osvbng_punt_l2tp_node.index;

  /* Register L2TP control port (1701) */
  vlib_worker_thread_barrier_sync (vm);
  udp_register_dst_port (vm, 1701, node_index, 1);

  /* Resolve the T=0 → l2tpv2-input next-arc now that all plugins have
   * finished init. LAC bridge dispatch is owned by osvbng_pppoe and
   * resolves its own l2tpv2-output arc independently. Idempotent. */
  osvbng_punt_l2tp_resolve_next_arc (vm);

  hash_set (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_L2TP], sw_if_index, 1);
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

int
osvbng_punt_disable_l2tp (u32 sw_if_index)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;

  vlib_worker_thread_barrier_sync (vm);
  hash_unset (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_L2TP], sw_if_index);

  /* Unregister UDP port if no more interfaces enabled */
  if (hash_elts (pm->enabled_interfaces[OSVBNG_PUNT_PROTO_L2TP]) == 0)
    {
      udp_unregister_dst_port (vm, 1701, 1);
    }
  vlib_worker_thread_barrier_release (vm);

  return 0;
}
