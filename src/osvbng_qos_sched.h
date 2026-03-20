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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/buffer.h>
#include <vlib/vlib.h>

/*
 * Constants
 */
#define CAKE_MAX_TINS      8   /* max DiffServ traffic classes */
#define CAKE_QUEUES        1024 /* flows per tin */
#define CAKE_SET_WAYS      8   /* set-associative ways */
#define CAKE_SETS          (CAKE_QUEUES / CAKE_SET_WAYS) /* 128 sets */

/* Default AQM parameters */
#define CAKE_TARGET_US     5000   /* CoDel target: 5ms */
#define CAKE_INTERVAL_US   100000 /* CoDel interval: 100ms */

/* COBALT BLUE parameters */
#define CAKE_BLUE_FREQ_INC 1     /* BLUE probability increment */
#define CAKE_BLUE_FREQ_DEC 1     /* BLUE probability decrement */
#define CAKE_BLUE_TIMER_US 100000 /* BLUE update interval: 100ms */

/* Scheduler flags */
#define CAKE_FLAG_WASH_DSCP  (1 << 0)
#define CAKE_FLAG_ACK_FILTER (1 << 1)
#define CAKE_FLAG_SPLIT_GSO  (1 << 2)

/*
 * Error codes
 */
typedef enum
{
#define cake_error(n, s) CAKE_ERROR_##n,
#include <osvbng_qos_sched/osvbng_qos_sched_error.def>
#undef cake_error
  CAKE_N_ERROR,
} cake_error_t;

extern char *cake_error_strings[];

/*
 * Flow state
 */
typedef enum
{
  CAKE_FLOW_NONE = 0,
  CAKE_FLOW_SPARSE,
  CAKE_FLOW_BULK,
  CAKE_FLOW_DECAYING,
} cake_flow_state_t;

/*
 * Per-flow structure — one per flow queue within a tin.
 * Kept compact for cache efficiency (1024 of these per tin).
 */
typedef struct
{
  /* Packet queue — vector of u32 buffer indices */
  u32 *queue;
  u32 head;
  u32 tail;

  /* DRR state */
  i32 deficit;
  u32 next; /* next flow in DRR list (index, ~0 = end) */
  u32 prev; /* prev flow in DRR list (index, ~0 = end) */

  /* COBALT AQM state */
  u64 codel_drop_next_us;  /* next CoDel drop time (microseconds) */
  u64 blue_drop_next_us;   /* next BLUE probability update */
  u32 codel_count;         /* CoDel drop interval count */
  u16 codel_rec_inv_sqrt;  /* reciprocal sqrt cache */
  u16 blue_drop_prob;      /* BLUE drop probability (0-65535) */
  u8 codel_dropping;       /* in CoDel dropping state */
  u8 ecn_enabled;          /* ECN marking enabled */

  /* Host tracking (for triple isolation) */
  u16 src_host_idx;
  u16 dst_host_idx;

  /* Queue state */
  u32 backlog_bytes;
  u32 hash_tag;         /* stored hash tag for set-associative match */
  u8 flow_state;        /* cake_flow_state_t */
  u8 set_index;         /* set within the set-associative table */
} cake_flow_t;

/*
 * Per-tin (traffic class) structure.
 */
typedef struct
{
  /* Flow queues */
  cake_flow_t flows[CAKE_QUEUES];

  /* DRR list heads (flow indices, ~0 = empty) */
  u32 new_flow_head;
  u32 old_flow_head;
  u32 decaying_flow_head;

  /* Tin-level shaper */
  u64 tin_rate_ns_per_byte;
  u64 tin_shaper_time_ns;

  /* DRR quantum */
  u32 quantum;
  u32 flow_quantum;

  /* DiffServ parameters */
  u8 tin_index;
  u8 priority;

  /* Statistics */
  u64 packets;
  u64 bytes;
  u64 drops;
  u64 ecn_marks;
  u32 peak_queue_delay_us;
  u32 avg_queue_delay_us;
  u32 sparse_flow_count;
  u32 bulk_flow_count;
} cake_tin_t;

/*
 * Per-subscriber scheduler instance.
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Shaper state */
  u64 rate_bytes_per_sec;
  u64 rate_ns_per_byte;       /* precomputed: 1e9 / rate_bytes_per_sec */
  u64 global_shaper_time_ns;  /* next allowed transmit time */
  u64 last_dequeue_time_ns;

  /* Per-interface binding */
  u32 sw_if_index;
  u32 sched_index; /* self-index in pool */

  /* Tin state */
  cake_tin_t *tins; /* vec, length = tin_cnt */
  u8 tin_cnt;
  u8 tin_mode; /* 0=besteffort, 1=diffserv3, 2=diffserv4, 3=diffserv8 */

  /* Overhead compensation */
  i16 overhead_bytes;
  u8 atm_mode; /* 0=none, 1=ATM, 2=PTM */
  u8 mpu;      /* minimum packet unit */

  /* AQM parameters */
  u32 target_us;
  u32 interval_us;

  /* Buffer limit */
  u32 buffer_limit;
  u32 buffer_usage;

  /* Flags */
  u32 flags;
} cake_sched_t;

/*
 * Per-thread scheduler state.
 */
typedef struct
{
  /* Pool of scheduler instances owned by this thread */
  cake_sched_t *schedulers;

  /* Bitmap of schedulers with queued packets */
  uword *active_bitmap;
} cake_per_thread_t;

/*
 * Plugin main structure.
 */
typedef struct
{
  /* Per-thread state */
  cake_per_thread_t *per_thread;

  /* sw_if_index → (thread_index << 16 | pool_index) */
  u32 *sched_index_by_sw_if_index;

  /* DSCP → tin mapping tables */
  u8 dscp_to_tin_besteffort[64];
  u8 dscp_to_tin_diffserv3[64];
  u8 dscp_to_tin_diffserv4[64];
  u8 dscp_to_tin_diffserv8[64];

  /* CoDel rec_inv_sqrt cache (first 16 values) */
  u16 codel_rec_inv_sqrt_cache[16];

  /* API message ID base */
  u16 msg_id_base;

  /* Node indices */
  u32 enqueue_node_index;
  u32 dequeue_node_index;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vlib_log_class_t log_class;
} cake_main_t;

extern cake_main_t cake_main;

/*
 * Public API
 */
int cake_sched_enable_disable (u32 sw_if_index, u8 is_enable,
			       u64 rate_bytes_per_sec, u8 tin_mode,
			       i16 overhead_bytes, u8 atm_mode, u8 mpu,
			       u32 buffer_limit, u32 target_us,
			       u32 interval_us, u32 flags);

void cake_sched_reset_stats (u32 sw_if_index);

/*
 * Inline helpers
 */
static_always_inline u32
cake_overhead_adjust (cake_sched_t *cs, u32 pkt_len)
{
  i32 adjusted = (i32) pkt_len + cs->overhead_bytes;
  if (adjusted < cs->mpu)
    adjusted = cs->mpu;
  if (cs->atm_mode == 1) /* ATM: round up to 48-byte cells, add 5-byte header
			     per cell */
    adjusted = ((adjusted + 47) / 48) * 53;
  return (u32) adjusted;
}

static_always_inline u32
cake_hash_flow_ip4 (ip4_header_t *ip4, u32 *hash_out)
{
  u64 key[2];
  key[0] = *((u64 *) &ip4->src_address);
  if (ip4->protocol == IP_PROTOCOL_TCP || ip4->protocol == IP_PROTOCOL_UDP)
    {
      u32 *ports = (u32 *) (((u8 *) ip4) + ip4_header_bytes (ip4));
      key[1] = ((u64) ip4->protocol << 32) | *ports;
    }
  else
    {
      key[1] = (u64) ip4->protocol << 32;
    }
  *hash_out = (u32) clib_xxhash (key[0] ^ key[1]);
  return *hash_out;
}

static_always_inline u32
cake_hash_flow_ip6 (ip6_header_t *ip6, u32 *hash_out)
{
  u64 key[4];
  /* Hash over full 128-bit src + dst addresses */
  key[0] = ip6->src_address.as_u64[0];
  key[1] = ip6->src_address.as_u64[1];
  key[2] = ip6->dst_address.as_u64[0];
  key[3] = ip6->dst_address.as_u64[1];

  u8 proto = ip6->protocol;
  u64 proto_ports = (u64) proto << 32;

  if (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP)
    {
      /* Ports follow the fixed 40-byte IPv6 header.
       * TODO: handle extension headers (hop-by-hop, routing, fragment). */
      u32 *ports = (u32 *) (((u8 *) ip6) + sizeof (ip6_header_t));
      proto_ports |= *ports;
    }

  *hash_out =
    (u32) clib_xxhash (key[0] ^ key[1] ^ key[2] ^ key[3] ^ proto_ports);
  return *hash_out;
}

static_always_inline u8
cake_dscp_from_ip4 (ip4_header_t *ip4)
{
  return ip4->tos >> 2;
}

static_always_inline u8
cake_dscp_from_ip6 (ip6_header_t *ip6)
{
  return (ip6_dscp_network_order (ip6));
}

static_always_inline u8
cake_ecn_from_ip4 (ip4_header_t *ip4)
{
  return ip4->tos & 0x03;
}

static_always_inline u8
cake_ecn_from_ip6 (ip6_header_t *ip6)
{
  return ip6_ecn_network_order (ip6);
}

static_always_inline void
cake_set_ecn_ce_ip4 (ip4_header_t *ip4)
{
  ip4->tos |= 0x03;
  ip4->checksum = ip4_header_checksum (ip4);
}

static_always_inline void
cake_set_ecn_ce_ip6 (ip6_header_t *ip6)
{
  ip6_set_ecn_network_order (ip6, IP_ECN_CE);
}

/*
 * Node registrations
 */
extern vlib_node_registration_t cake_enqueue_node;
extern vlib_node_registration_t cake_dequeue_node;

#endif /* __included_osvbng_qos_sched_h__ */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
