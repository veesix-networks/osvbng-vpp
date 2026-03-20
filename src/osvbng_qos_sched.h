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
 * Phase 1: Shaper only — single FIFO per subscriber, token-bucket pacing.
 * No AQM, no FQ, no DiffServ tins.
 */

#ifndef __included_osvbng_qos_sched_h__
#define __included_osvbng_qos_sched_h__

#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/buffer.h>
#include <vlib/vlib.h>

/*
 * Buffer flag for re-injection.
 *
 * When the dequeue node transmits a packet, it sets this flag before
 * re-injecting the buffer into the interface-output feature arc.
 * The enqueue node checks this flag first — if set, clears it and
 * calls vnet_feature_next() to continue through remaining output
 * features (span, ipsec, etc.). No output features are skipped.
 */
#define CAKE_BUFFER_F_SCHEDULED VNET_BUFFER_F_AVAIL1

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
 * Per-subscriber scheduler instance.
 *
 * Phase 1: Single FIFO queue with token-bucket shaping.
 * Future phases add per-flow queuing, DRR, COBALT AQM, DiffServ tins.
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Shaper state */
  u64 rate_bytes_per_sec;	  /* configured rate */
  u64 rate_ns_per_byte;		  /* precomputed: 1e9 / rate_bytes_per_sec */
  u64 global_shaper_time_ns;	  /* next allowed transmit time */

  /* Per-interface binding */
  u32 sw_if_index;		  /* subscriber interface */
  u32 sched_index;		  /* self-index in pool */

  /* FIFO queue (Phase 1: single queue, no per-flow) */
  u32 *queue;			  /* vec of buffer indices */
  u32 queue_head;		  /* next dequeue position */

  /* Overhead compensation */
  i16 overhead_bytes;		  /* per-packet add (framing overhead) */
  u8 atm_mode;			  /* 0=none, 1=ATM cell rounding, 2=PTM */
  u8 mpu;			  /* minimum packet unit (e.g., 64) */

  /* Buffer limits — admission control */
  u32 buffer_limit;		  /* max total queued bytes */
  u32 buffer_usage;		  /* current total queued bytes */
  u32 queued_buffers;		  /* current total queued buffer objects */

  /* Statistics */
  u64 enqueued_pkts;
  u64 enqueued_bytes;
  u64 dequeued_pkts;
  u64 dequeued_bytes;
  u64 dropped_pkts;
} cake_sched_t;

/*
 * Per-thread state.
 * Each worker thread tracks which schedulers have queued packets.
 */
typedef struct
{
  /* Bitmap of scheduler pool indices with queued packets on this thread */
  uword *active_bitmap;
} cake_per_thread_t;

/*
 * Plugin main structure.
 */
typedef struct
{
  /* Global scheduler pool (modified under barrier) */
  cake_sched_t *schedulers;

  /* Per-thread state (indexed by thread_index) */
  cake_per_thread_t *per_thread;

  /* sw_if_index → scheduler pool index (~0 = no scheduler) */
  u32 *sched_index_by_sw_if_index;

  /* Count of active schedulers (for INPUT node state management) */
  u32 n_schedulers;

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
int cake_sched_enable_disable (vlib_main_t *vm, u32 sw_if_index, u8 is_enable,
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
