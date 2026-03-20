/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin
 * CAKE-equivalent per-subscriber traffic scheduling.
 *
 * Algorithms derived from the Linux CAKE qdisc (sch_cake.c).
 * Original authors: Dave Taht, Jonathan Morton, Toke Hoiland-Jorgensen,
 * Sebastian Moeller, Kevin Darbyshire-Bryant, Ryan Mounce.
 *
 * Phase 2: Per-flow queuing with set-associative hashing and DRR.
 */

#ifndef __included_osvbng_qos_sched_h__
#define __included_osvbng_qos_sched_h__

#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/xxhash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/buffer.h>
#include <vlib/vlib.h>

#define CAKE_BUFFER_F_SCHEDULED VNET_BUFFER_F_AVAIL1

#define CAKE_QUEUES	1024
#define CAKE_SET_WAYS	8
#define CAKE_SET_COUNT	(CAKE_QUEUES / CAKE_SET_WAYS)

#define CAKE_FLOW_NONE	   0
#define CAKE_FLOW_SPARSE   1
#define CAKE_FLOW_BULK	   2
#define CAKE_FLOW_DECAYING 3

#define CAKE_QUANTUM_DEFAULT 1514

typedef enum
{
#define cake_error(n, s) CAKE_ERROR_##n,
#include <osvbng_qos_sched/osvbng_qos_sched_error.def>
#undef cake_error
  CAKE_N_ERROR,
} cake_error_t;

extern char *cake_error_strings[];

typedef struct
{
  u32 *queue;
  u32 head;

  i32 deficit;
  u32 next;
  u32 prev;

  u32 backlog_bytes;
  u8 flow_state;
  u8 set_index;
} cake_flow_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  cake_flow_t *flows;
  u32 flow_tags[CAKE_QUEUES];
  u32 flow_count;

  u32 new_flow_head;
  u32 old_flow_head;
  u32 decaying_flow_head;

  u32 quantum;

  u64 packets;
  u64 bytes;
  u64 drops;
  u32 sparse_flow_count;
  u32 bulk_flow_count;
} cake_tin_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 rate_bytes_per_sec;
  u64 rate_ns_per_byte;
  u64 global_shaper_time_ns;

  u32 sw_if_index;
  u32 sched_index;

  i16 overhead_bytes;
  u8 atm_mode;
  u8 mpu;

  u32 buffer_limit;
  u32 buffer_usage;
  u32 queued_buffers;

  cake_tin_t tin;

  u64 enqueued_pkts;
  u64 enqueued_bytes;
  u64 dequeued_pkts;
  u64 dequeued_bytes;
  u64 dropped_pkts;
} cake_sched_t;

typedef struct
{
  uword *active_bitmap;
} cake_per_thread_t;

typedef struct
{
  cake_sched_t *schedulers;
  cake_per_thread_t *per_thread;
  u32 *sched_index_by_sw_if_index;
  u32 n_schedulers;

  u16 msg_id_base;

  u32 ip4_enqueue_node_index;
  u32 ip6_enqueue_node_index;
  u32 dequeue_node_index;

  u8 ip4_output_arc_index;
  u8 ip6_output_arc_index;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vlib_log_class_t log_class;
} cake_main_t;

extern cake_main_t cake_main;

int cake_sched_enable_disable (vlib_main_t *vm, u32 sw_if_index, u8 is_enable,
			       u64 rate_bytes_per_sec, u8 tin_mode,
			       i16 overhead_bytes, u8 atm_mode, u8 mpu,
			       u32 buffer_limit, u32 target_us,
			       u32 interval_us, u32 flags);

void cake_sched_reset_stats (u32 sw_if_index);

static_always_inline u32
cake_overhead_adjust (cake_sched_t *cs, u32 pkt_len)
{
  i32 adjusted = (i32) pkt_len + cs->overhead_bytes;
  if (adjusted < cs->mpu)
    adjusted = cs->mpu;
  if (cs->atm_mode == 1)
    adjusted = ((adjusted + 47) / 48) * 53;
  return (u32) adjusted;
}

/*
 * Flow hashing: 5-tuple → xxhash → tag with non-zero sentinel.
 */
static_always_inline u32
cake_hash_flow (vlib_buffer_t *b, u8 is_ip4)
{
  u64 k0, k1;

  if (is_ip4)
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b);
      u16 sport = 0, dport = 0;

      if (PREDICT_TRUE (ip4->protocol == IP_PROTOCOL_TCP ||
			ip4->protocol == IP_PROTOCOL_UDP))
	{
	  u8 *l4 = (u8 *) ip4 + ip4_header_bytes (ip4);
	  sport = *(u16 *) l4;
	  dport = *(u16 *) (l4 + 2);
	}

      k0 = ((u64) ip4->src_address.as_u32 << 32) | ip4->dst_address.as_u32;
      k1 = ((u64) sport << 16) | dport | ((u64) ip4->protocol << 32);
    }
  else
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      u16 sport = 0, dport = 0;
      u32 flow_label = ip6_flow_label_network_order (ip6);

      if (PREDICT_TRUE (ip6->protocol == IP_PROTOCOL_TCP ||
			ip6->protocol == IP_PROTOCOL_UDP))
	{
	  u8 *l4 = (u8 *) (ip6 + 1);
	  sport = *(u16 *) l4;
	  dport = *(u16 *) (l4 + 2);
	}

      k0 = ip6->src_address.as_u64[0] ^ ip6->src_address.as_u64[1];
      k1 = (ip6->dst_address.as_u64[0] ^ ip6->dst_address.as_u64[1]) ^
	   (((u64) sport << 16) | dport | ((u64) flow_label << 32));
    }

  u32 hash = (u32) clib_xxhash (k0 ^ k1);
  return hash | 1;
}

/*
 * DRR doubly-linked list operations.
 * Lists are non-circular: head/prev/next use ~0 as nil.
 */
static_always_inline void
cake_flow_list_append (u32 *list_head, cake_flow_t *flows, u32 idx)
{
  cake_flow_t *f = &flows[idx];
  f->next = *list_head;
  f->prev = ~0;

  if (*list_head != ~0)
    flows[*list_head].prev = idx;

  *list_head = idx;
}

static_always_inline void
cake_flow_list_remove (u32 *list_head, cake_flow_t *flows, u32 idx)
{
  cake_flow_t *f = &flows[idx];

  if (f->prev != ~0)
    flows[f->prev].next = f->next;
  else
    *list_head = f->next;

  if (f->next != ~0)
    flows[f->next].prev = f->prev;

  f->next = ~0;
  f->prev = ~0;
}

/*
 * Set-associative flow lookup.
 * Returns flow index (0..CAKE_QUEUES-1).
 */
static_always_inline u32
cake_flow_lookup (cake_tin_t *tin, u32 tag, u32 set_base)
{
  u32 empty_slot = ~0;
  u32 evict_slot = ~0;
  u32 evict_backlog = ~0U;

  for (u32 i = 0; i < CAKE_SET_WAYS; i++)
    {
      u32 slot = set_base + i;
      u32 slot_tag = tin->flow_tags[slot];

      if (slot_tag == tag)
	return slot;

      if (slot_tag == 0 && empty_slot == ~0)
	empty_slot = slot;

      if (slot_tag != 0 && empty_slot == ~0)
	{
	  u32 bl = tin->flows[slot].backlog_bytes;
	  if (bl < evict_backlog)
	    {
	      evict_backlog = bl;
	      evict_slot = slot;
	    }
	}
    }

  if (empty_slot != ~0)
    {
      tin->flow_tags[empty_slot] = tag;
      return empty_slot;
    }

  if (evict_slot != ~0)
    {
      cake_flow_t *ef = &tin->flows[evict_slot];
      if (ef->queue)
	vec_free (ef->queue);
      clib_memset (ef, 0, sizeof (*ef));
      ef->next = ~0;
      ef->prev = ~0;
      tin->flow_tags[evict_slot] = tag;
      return evict_slot;
    }

  return set_base;
}

extern vlib_node_registration_t ip4_cake_enqueue_node;
extern vlib_node_registration_t ip6_cake_enqueue_node;
extern vlib_node_registration_t cake_dequeue_node;

#endif /* __included_osvbng_qos_sched_h__ */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
