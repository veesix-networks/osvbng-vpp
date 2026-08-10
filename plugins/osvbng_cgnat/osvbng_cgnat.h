/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin
 * Carrier-Grade NAT with PBA and Deterministic modes.
 */

#ifndef __included_osvbng_cgnat_h__
#define __included_osvbng_cgnat_h__

#include <vnet/plugin/plugin.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/receive_dpo.h>
#include <vlib/vlib.h>
#include <nat/lib/lib.h>		/* nat_icmp_echo_header_t, nat_tcp_udp_header_t */

#define CGNAT_ALG_FTP  (1 << 0)
#define CGNAT_ALG_TFTP (1 << 1)
#define CGNAT_ALG_PPTP (1 << 2)
#define CGNAT_ALG_SIP  (1 << 3)
#define CGNAT_ALG_RTSP (1 << 4)
#define CGNAT_ALG_DNS  (1 << 5)

/* Slot indices into cgnat_pool_t::timeouts[CGNAT_N_PROTOS]. TCP gets two
 * slots so the state machine can pick a short transitory timeout for
 * half-open / closing flows (RFC 5382 §5: 4 min minimum) and a long
 * established timeout for steady-state (2h 4m minimum). Phase 7 introduces
 * the TCP_TRANS slot — pre-#153 the array was [4] and tcp_transitory was
 * silently dropped by the plugin; v1 binapi back-fills it from defaults. */
#define CGNAT_PROTO_TCP_ESTAB 0
#define CGNAT_PROTO_TCP_TRANS 1
#define CGNAT_PROTO_UDP	      2
#define CGNAT_PROTO_ICMP      3
#define CGNAT_PROTO_OTHER     4
#define CGNAT_N_PROTOS	      5

/* Kept as an alias for the existing CGNAT_PROTO_TCP callers that don't yet
 * distinguish established vs transitory. Resolves to the established slot
 * so default-timeout reads of "TCP" continue to return the long timeout. */
#define CGNAT_PROTO_TCP CGNAT_PROTO_TCP_ESTAB

/* TCP state machine — mirrors nat44-ed's 3-state design (CLOSED → ESTABLISHED
 * → CLOSING). Implemented in cgnat_set_tcp_session_state. State transitions
 * also rewrite s->timeout so the expire walker sees the right value. */
typedef enum
{
  CGNAT_TCP_STATE_CLOSED = 0,
  CGNAT_TCP_STATE_ESTABLISHED,
  CGNAT_TCP_STATE_CLOSING,
  CGNAT_TCP_N_STATE,
} cgnat_tcp_state_e;

#define CGNAT_TCP_DIR_I2O 0
#define CGNAT_TCP_DIR_O2I 1
#define CGNAT_TCP_N_DIR	  2

#define CGNAT_SESSION_DUMP_DEFAULT_LIMIT 1024

typedef enum
{
  CGNAT_POOL_MODE_PBA = 0,
  CGNAT_POOL_MODE_DETERMINISTIC = 1,
} cgnat_pool_mode_t;

typedef enum
{
  CGNAT_ADDRESS_POOLING_PAIRED = 0,
  CGNAT_ADDRESS_POOLING_ARBITRARY = 1,
} cgnat_address_pooling_t;

typedef enum
{
  CGNAT_FILTERING_ENDPOINT_INDEPENDENT = 0,
  CGNAT_FILTERING_ENDPOINT_DEPENDENT = 1,
} cgnat_filtering_t;

typedef enum
{
#define cgnat_error(n, s) CGNAT_ERROR_##n,
#include <osvbng_cgnat/osvbng_cgnat_error.def>
#undef cgnat_error
  CGNAT_N_ERROR,
} cgnat_error_t;

extern char *cgnat_error_strings[];

/*
 * Plugin-shared API return code for the duplicate-add idempotency
 * contract. Returned by cgnat_add_del_subscriber_mapping() when a
 * mapping already exists for the (inside_ip, inside_fib_index)
 * lookup key but one or more mutable inputs (outside_ip, port range,
 * pool, sw_if_index) have drifted from the stored record. The caller
 * must delete-and-recreate the mapping to converge on the new inputs.
 *
 * Value is chosen outside VPP's vnet_api_error_t range (-1..-171)
 * to avoid collision. Same numeric value across all osvbng plugins
 * (ipoe, pppoe, cgnat) so the Go control plane has one constant.
 */
#ifndef VNET_API_ERROR_ENTRY_NEEDS_REFRESH
#define VNET_API_ERROR_ENTRY_NEEDS_REFRESH (-500)
#endif

/* Per-direction flow record. One cgnat_session_t carries two: i2o (the
 * subscriber-originated lookup + the outside rewrite to apply) and o2i (the
 * outside-originated lookup + the inside rewrite to apply). Each carries its
 * own match key + rewrite targets + precomputed L3/L4 checksum delta, so the
 * fast path picks ONE flow record per packet based on which bihash matched
 * and applies one ip_csum_add_even + fold per checksum. Direction-specific is
 * required for correctness (applying an i2o delta on an o2i packet produces
 * wrong checksums). Mirrors nat44-ed's nat_6t_flow_t pattern. */
/* Layout: u64-aligned ip_csum_t fields first so the natural alignment of the
 * struct (8 bytes) matches and no internal padding is wasted. Total is 56
 * bytes (8+8+4+4+4+4+4+4+2+2+2+2+1 + 7 trailing pad to round to 8-byte align).
 * Two of these fit comfortably in one cache line with room for small per-
 * direction fields. */
typedef struct
{
  ip_csum_t l3_csum_delta;
  ip_csum_t l4_csum_delta;

  ip4_address_t saddr;
  ip4_address_t daddr;
  ip4_address_t rewrite_saddr;
  ip4_address_t rewrite_daddr;

  u32 fib_index;
  u32 rewrite_fib_index;

  u16 sport;
  u16 dport;
  u16 rewrite_sport;
  u16 rewrite_dport;

  u8 proto;
  u8 _pad[7];
} cgnat_flow_t;

STATIC_ASSERT_SIZEOF (cgnat_flow_t, 56);

typedef struct
{
  /* Line 0: in2out flow record + per-direction small fields read on the i2o
   * fast path. tcp_state read for state-aware timeout once TCP state lands
   * in phase 7. alg_flags kept for #151 wire compat (always 0 after phase 10
   * removes the set code). 56 + 1 + 1 + 6 = 64. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cgnat_flow_t i2o;
  u8 tcp_state;
  u8 alg_flags;
  u8 _pad0[6];

  /* Line 1: out2in flow record + back-references resolved on the o2i fast
   * path. mapping_index used by session_delete for cleanup; pool_index used
   * by the session dump handler to resolve operator-facing pool_id.
   * 56 + 4 + 4 = 64. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  cgnat_flow_t o2i;
  u32 mapping_index;
  u32 pool_index;

  /* Line 2: written on every translated packet (bookkeeping). Separate cache
   * line keeps the read-mostly flow records out of the dirty-line write set.
   * frag_rewrite_index is an O(1) back-pointer into cm->frag_rewrite_pool so
   * session_delete can refcount-down without re-keying the aux bihash.
   * mapping_next/mapping_prev thread the intrusive per-mapping session list
   * (indices into cm->sessions, ~0 = end) so a mapping delete reaps only its
   * own sessions instead of scanning the whole pool; read-mostly (written on
   * session create/delete, never per packet). Kept adjacent to
   * frag_rewrite_index so the three u32s stay naturally aligned with no hole
   * before tcp_flags.
   * 8 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 18 = 64. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  f64 last_active;
  u64 total_pkts;
  u64 total_bytes;
  f64 timeout;
  u32 frag_rewrite_index;
  u32 mapping_next;
  u32 mapping_prev;
  u8 tcp_flags[2];
  u8 _pad2[18];
} cgnat_session_t;

STATIC_ASSERT_SIZEOF (cgnat_session_t, 192);

/* Refcounted IP-only rewrite record for non-first fragments. The aux bihash
 * (cm->frag_aux) is keyed on (saddr, daddr, proto, fib_index) and resolves
 * to one of these in cm->frag_rewrite_pool. Refcount tracks how many sessions
 * share the same (saddr, daddr, proto, fib); session_create increments,
 * session_delete decrements + evicts at zero so a non-first fragment can
 * always find a live rewrite record while ANY sibling session is alive. */
/* Slowpath-only record, no cache-line alignment needed (accessed only on the
 * fragment slow path which is rare; alignment optimisation would just waste
 * 24 bytes per entry). */
typedef struct
{
  ip_csum_t l3_csum_delta_i2o;
  ip_csum_t l3_csum_delta_o2i;
  ip4_address_t inside_ip;
  ip4_address_t outside_ip;
  u32 inside_fib_index;
  u32 outside_fib_index;
  u32 refcount;
  u32 _pad0;
} cgnat_frag_rewrite_t;

STATIC_ASSERT_SIZEOF (cgnat_frag_rewrite_t, 40);

/* Inline read accessors derive #151 wire-compatible field names from the new
 * two-flow-record layout. Writers (cgnat_session_create) touch flow fields
 * directly; readers go through these so the dump handler doesn't need to know
 * the new shape. */
always_inline ip4_address_t cgnat_session_inside_ip (cgnat_session_t *s)
{
  return s->i2o.saddr;
}
always_inline ip4_address_t cgnat_session_outside_ip (cgnat_session_t *s)
{
  return s->i2o.rewrite_saddr;
}
always_inline ip4_address_t cgnat_session_remote_ip (cgnat_session_t *s)
{
  return s->i2o.daddr;
}
always_inline u16 cgnat_session_inside_port (cgnat_session_t *s)
{
  return s->i2o.sport;
}
always_inline u16 cgnat_session_outside_port (cgnat_session_t *s)
{
  return s->i2o.rewrite_sport;
}
always_inline u16 cgnat_session_remote_port (cgnat_session_t *s)
{
  return s->i2o.dport;
}
always_inline u8 cgnat_session_proto (cgnat_session_t *s)
{
  return s->i2o.proto;
}
always_inline u32 cgnat_session_inside_fib (cgnat_session_t *s)
{
  return s->i2o.fib_index;
}
always_inline u32 cgnat_session_outside_fib (cgnat_session_t *s)
{
  return s->i2o.rewrite_fib_index;
}

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t src_ip;
      ip4_address_t dst_ip;
      u16 src_port;
      u16 dst_port;
      u8 proto;
      u8 _pad;
      u16 fib_index_lo16;
    };
    u64 as_u64[2];
  };
} cgnat_session_key_t;

STATIC_ASSERT_SIZEOF (cgnat_session_key_t, 16);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip4_address_t inside_ip;
  ip4_address_t outside_ip;
  u32 inside_vrf_id;
  u32 inside_fib_index;
  u16 port_block_start;
  u16 port_block_end;
  u32 pool_index;
  u32 sw_if_index;

  u16 next_port;
  u32 session_count;

  /* Head of the intrusive per-mapping session list (index into cm->sessions,
   * ~0 = empty). Lets a mapping delete reap this subscriber's sessions in
   * O(sessions-on-mapping) instead of an O(CGNAT_MAX_SESSIONS) pool scan. */
  u32 sessions_head;

  /* Per-port f64 timestamp of last release; cgnat_port_alloc skips ports
   * still in the RFC 6056 reuse cooldown. Was declared u64* historically and
   * reinterpret-cast as f64 on read/write — same width on 64-bit, but
   * strict-aliasing fragile; phase 10 fixes the type. */
  f64 *port_reuse_timestamps;

  /* Serialises port_alloc / port_free / session_count++/-- across workers.
   * Slow path only (session create / delete), so contention is microscopic
   * compared to the cost of port number reuse going wrong. */
  clib_spinlock_t lock;
} cgnat_mapping_t;

typedef struct
{
  fib_prefix_t prefix;
  u32 fib_index;
  fib_node_index_t fib_entry_index;
} cgnat_bypass_entry_t;

typedef struct
{
  ip4_address_t inside_base;
  u32 inside_count;
  ip4_address_t outside_base;
  u32 outside_count;
  u32 sharing_ratio;
  u32 ports_per_host;
  u16 port_range_start;
  u16 port_range_end;
} cgnat_det_params_t;

typedef struct
{
  fib_prefix_t prefix;
  u32 vrf_id;
  u32 fib_index;
} cgnat_inside_prefix_entry_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 pool_id;
  cgnat_pool_mode_t mode;
  cgnat_address_pooling_t address_pooling;
  cgnat_filtering_t filtering;

  u16 block_size;
  u8 max_blocks_per_sub;
  u32 max_sessions_per_sub;
  u16 port_range_start;
  u16 port_range_end;
  u16 port_reuse_timeout;
  u8 alg_bitmask;

  u32 timeouts[CGNAT_N_PROTOS];

  u32 outside_vrf_table_id;
  u32 outside_fib_index;
  u8 outside_fib_valid;

  fib_prefix_t *outside_prefixes;
  fib_node_index_t *outside_fib_entries;
  dpo_id_t dpo;

  /* Outside sw_if_indexes this pool has refcnt-enabled
   * `ip4-sv-reassembly-feature` on. Vec so multiple interfaces per pool are
   * supported; the sv-reass refcnt itself is global per sw_if so multiple
   * pools sharing an interface compose correctly. Cleaned up by
   * cgnat_pool_cascade_delete. */
  u32 *outside_sw_if_indexes;

  cgnat_inside_prefix_entry_t *inside_prefixes;

  cgnat_det_params_t *det_params;
  u32 n_det_params;
} cgnat_pool_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ip;
      u32 fib_index;
    };
    u64 as_u64;
  };
} cgnat_inside_key_t;

typedef enum
{
  CGNAT_IN2OUT_NEXT_DROP,
  CGNAT_IN2OUT_NEXT_LOOKUP,
  CGNAT_IN2OUT_NEXT_SLOWPATH,
  CGNAT_IN2OUT_N_NEXT,
} cgnat_in2out_next_t;

typedef enum
{
  CGNAT_OUT2IN_NEXT_DROP,
  CGNAT_OUT2IN_NEXT_LOOKUP,
  CGNAT_OUT2IN_NEXT_SLOWPATH,
  CGNAT_OUT2IN_N_NEXT,
} cgnat_out2in_next_t;

/* Fixed capacity of the shared session and fragment-rewrite pools. Both are
 * pre-reserved with pool_init_fixed so they never realloc at runtime: a moving
 * pool base would race the lock-free fast-path pool_elt_at_index reads on other
 * workers. Static ceilings for now; a future system scale profile will derive
 * them from the configured subscriber count. */
#define CGNAT_MAX_SESSIONS	(1u << 19)
#define CGNAT_MAX_FRAG_REWRITES (1u << 16)

typedef struct
{
  cgnat_pool_t *pools;
  uword *pool_by_id;

  cgnat_mapping_t *mappings;
  clib_bihash_8_8_t inside_lookup;

  cgnat_session_t *sessions;
  clib_bihash_16_8_t session_table_in2out;
  clib_bihash_16_8_t session_table_out2in;

  /* Fragment rewrite pool + aux lookup (D14). bihash_16_8 keyed on
   * (saddr, daddr, proto, fib_index) — same shape as the session tables so
   * collisions only occur on the true (saddr,daddr,proto,fib) equivalence
   * class, NOT cross-VRF subscribers happening to share an inside IP. */
  cgnat_frag_rewrite_t *frag_rewrite_pool;
  clib_bihash_16_8_t frag_aux;

  /* Serialises pool_get on cm->sessions / cm->frag_rewrite_pool across workers.
   * The shared-pool model lets any worker create a session on the slowpath, and
   * VPP pools are not multi-writer safe. Delete and reap run under the worker
   * barrier, so only create-vs-create contends here. */
  clib_spinlock_t session_pool_lock;

  cgnat_bypass_entry_t *bypass_entries;
  u32 bypass_entry_count;
  fib_source_t bypass_fib_src;

  dpo_type_t dpo_type;
  fib_source_t outside_fib_src;

  u16 msg_id_base;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vlib_log_class_t log_class;
} cgnat_main_t;

extern cgnat_main_t cgnat_main;

int cgnat_pool_add_del (cgnat_pool_t *cfg, u8 is_add);
int cgnat_set_outside_fib (u32 pool_id, u32 vrf_id);
int cgnat_add_del_subscriber_mapping (u32 pool_id, u32 sw_if_index,
				      ip4_address_t *inside_ip,
				      u32 inside_vrf_id,
				      ip4_address_t *outside_ip,
				      u16 port_start, u16 port_end,
				      u8 enable_feature, u8 is_add);
int cgnat_enable_on_session (u32 pool_id, u32 sw_if_index, u8 is_enable);
int cgnat_add_del_bypass (fib_prefix_t *prefix, u32 vrf_id, u8 is_add);
int cgnat_pool_add_outside_prefix (u32 pool_id, fib_prefix_t *prefix);
int cgnat_pool_del_outside_prefix (u32 pool_id, fib_prefix_t *prefix);
int cgnat_pool_outside_interface_add_del (u32 pool_id, u32 sw_if_index,
					  u8 is_add);
int cgnat_pool_inside_prefix_add_del (u32 pool_id, fib_prefix_t *prefix,
				      u32 vrf_id, u8 is_add);
void cgnat_dpo_module_init (void);

extern vlib_node_registration_t cgnat_out2in_node;
int cgnat_pool_update (u32 pool_id, u32 max_sessions, u8 alg_bitmask,
		       u32 *timeouts);

cgnat_session_t *cgnat_session_create (cgnat_mapping_t *mapping,
				       ip4_address_t *remote_ip,
				       u16 remote_port, u8 proto,
				       u16 outside_port, u16 inside_port,
				       f64 now);
cgnat_session_t *cgnat_session_lookup_in2out (ip4_address_t *src_ip,
					      ip4_address_t *dst_ip,
					      u16 src_port, u16 dst_port,
					      u8 proto, u32 fib_index);
cgnat_session_t *cgnat_session_lookup_out2in (ip4_address_t *dst_ip,
					      ip4_address_t *src_ip,
					      u16 dst_port, u16 src_port,
					      u8 proto, u32 fib_index);
void cgnat_session_delete (cgnat_session_t *s);
u16 cgnat_port_alloc (cgnat_mapping_t *m, f64 now);
void cgnat_port_free (cgnat_mapping_t *m, u16 port);
void cgnat_session_expire_walk (vlib_main_t *vm, f64 now);
void cgnat_session_table_init (void);

/* Aux fragment rewrite record lookup for non-first fragments. Returns NULL
 * on miss (drop with FRAGMENT_DROP at the caller). */
cgnat_frag_rewrite_t *cgnat_frag_rewrite_lookup (ip4_address_t saddr,
						 ip4_address_t daddr,
						 u8 proto, u32 fib_index);

always_inline cgnat_mapping_t *
cgnat_mapping_lookup (ip4_address_t *inside_ip, u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_8_8_t kv;
  cgnat_inside_key_t key;

  key.ip.as_u32 = inside_ip->as_u32;
  key.fib_index = fib_index;
  kv.key = key.as_u64;
  kv.value = ~0ULL;

  if (clib_bihash_search_inline_8_8 (&cm->inside_lookup, &kv) == 0)
    return pool_elt_at_index (cm->mappings, (u32) kv.value);
  return NULL;
}

/* Fast-path check: does `dst` resolve to a local-receive DPO in `fib_index`?
 * Used by cgnat-in2out to skip translation for packets aimed at a BNG-owned
 * address (subscriber default gateway, loopback, subnet/global broadcast,
 * etc.) so they fall through to ip4-lookup → receive → punt-to-LCP instead
 * of being NAT'd and shipped upstream into the void. */
always_inline int
cgnat_is_local_receive (u32 fib_index, ip4_address_t *dst)
{
  u32 lbi = ip4_fib_forwarding_lookup (fib_index, dst);
  const load_balance_t *lb = load_balance_get (lbi);
  const dpo_id_t *dpo = load_balance_get_bucket_i (lb, 0);
  return dpo->dpoi_type == DPO_RECEIVE;
}

always_inline int
cgnat_bypass_check (ip4_address_t *inside_ip, u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;

  if (PREDICT_TRUE (cm->bypass_entry_count == 0))
    return 0;

  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4.as_u32 = inside_ip->as_u32,
  };

  u32 fei = fib_table_lookup (fib_index, &pfx);
  if (fei == FIB_NODE_INDEX_INVALID)
    return 0;

  return fib_entry_is_sourced (fei, cm->bypass_fib_src);
}

always_inline u8
cgnat_proto_from_ip (u8 ip_proto)
{
  switch (ip_proto)
    {
    case IP_PROTOCOL_TCP:
      return CGNAT_PROTO_TCP;
    case IP_PROTOCOL_UDP:
      return CGNAT_PROTO_UDP;
    case IP_PROTOCOL_ICMP:
      return CGNAT_PROTO_ICMP;
    default:
      return CGNAT_PROTO_OTHER;
    }
}

always_inline u32
cgnat_session_timeout (cgnat_pool_t *pool, u8 proto)
{
  if (proto < CGNAT_N_PROTOS)
    return pool->timeouts[proto];
  return pool->timeouts[CGNAT_PROTO_UDP];
}

/* TCP state-aware timeout. Established uses the long bucket, every other
 * state (CLOSED/CLOSING — half-open and post-FIN/RST) uses the short
 * transitory bucket. Called from cgnat_set_tcp_session_state on every state
 * change so s->timeout is kept fresh for the expire walker. */
always_inline u32
cgnat_session_timeout_for_tcp (cgnat_pool_t *pool, u8 tcp_state)
{
  if (tcp_state == CGNAT_TCP_STATE_ESTABLISHED)
    return pool->timeouts[CGNAT_PROTO_TCP_ESTAB];
  return pool->timeouts[CGNAT_PROTO_TCP_TRANS];
}

/* Drive the TCP state machine on every TCP packet. Mirrors nat44-ed's
 * nat44_set_tcp_session_state shape — CLOSED becomes ESTABLISHED on a
 * SYN+ACK seen from both sides; ESTABLISHED becomes CLOSING on a FIN or
 * RST from either side; CLOSING reopens on a fresh SYN+ACK pair. State
 * change rewrites s->timeout so the expire walker uses the right bucket. */
always_inline void
cgnat_set_tcp_session_state (cgnat_session_t *s, cgnat_pool_t *pool,
			     u8 tcp_flags, u8 dir, f64 now)
{
  u8 mask = TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK;
  u8 old = s->tcp_flags[dir];
  s->tcp_flags[dir] |= tcp_flags & mask;
  if (old == s->tcp_flags[dir])
    return;

  u8 old_state = s->tcp_state;
  switch (old_state)
    {
    case CGNAT_TCP_STATE_CLOSED:
      if ((s->tcp_flags[CGNAT_TCP_DIR_I2O] & s->tcp_flags[CGNAT_TCP_DIR_O2I]) ==
	  (TCP_FLAG_SYN | TCP_FLAG_ACK))
	s->tcp_state = CGNAT_TCP_STATE_ESTABLISHED;
      break;
    case CGNAT_TCP_STATE_ESTABLISHED:
      if (s->tcp_flags[dir] & (TCP_FLAG_FIN | TCP_FLAG_RST))
	{
	  s->tcp_state = CGNAT_TCP_STATE_CLOSING;
	  s->tcp_flags[CGNAT_TCP_DIR_I2O] = 0;
	  s->tcp_flags[CGNAT_TCP_DIR_O2I] = 0;
	  s->last_active = now;
	}
      break;
    case CGNAT_TCP_STATE_CLOSING:
      if ((s->tcp_flags[CGNAT_TCP_DIR_I2O] & s->tcp_flags[CGNAT_TCP_DIR_O2I]) ==
	  (TCP_FLAG_SYN | TCP_FLAG_ACK))
	s->tcp_state = CGNAT_TCP_STATE_ESTABLISHED;
      break;
    }
  if (old_state == s->tcp_state)
    return;
  s->timeout = cgnat_session_timeout_for_tcp (pool, s->tcp_state);
}

/* Find the det_params entry on `pool` that covers `inside_ip`. Walks pool
 * det_params (usually 1-2 entries — one per inside prefix). Returns NULL on
 * miss (operator hasn't configured a covering inside prefix yet). */
always_inline cgnat_det_params_t *
cgnat_det_lookup_params_inside (cgnat_pool_t *pool, ip4_address_t *inside_ip)
{
  u32 ip_h = clib_net_to_host_u32 (inside_ip->as_u32);
  for (u32 i = 0; i < pool->n_det_params; i++)
    {
      cgnat_det_params_t *dp = &pool->det_params[i];
      u32 base_h = clib_net_to_host_u32 (dp->inside_base.as_u32);
      if (ip_h >= base_h && ip_h < base_h + dp->inside_count)
	return dp;
    }
  return NULL;
}

always_inline int
cgnat_det_forward (cgnat_det_params_t *dp, ip4_address_t *inside_ip,
		   ip4_address_t *outside_ip_out, u16 *port_start_out,
		   u16 *port_end_out)
{
  u32 host_offset =
    clib_net_to_host_u32 (inside_ip->as_u32) -
    clib_net_to_host_u32 (dp->inside_base.as_u32);

  if (host_offset >= dp->inside_count)
    return -1;

  u32 outside_offset = host_offset / dp->sharing_ratio;
  u32 port_index = host_offset % dp->sharing_ratio;

  outside_ip_out->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (dp->outside_base.as_u32) + outside_offset);

  *port_start_out = dp->port_range_start + (dp->ports_per_host * port_index);
  *port_end_out = *port_start_out + dp->ports_per_host - 1;

  return 0;
}

always_inline int
cgnat_det_reverse (cgnat_det_params_t *dp, ip4_address_t *outside_ip,
		   u16 port, ip4_address_t *inside_ip_out)
{
  u32 outside_offset =
    clib_net_to_host_u32 (outside_ip->as_u32) -
    clib_net_to_host_u32 (dp->outside_base.as_u32);

  if (outside_offset >= dp->outside_count)
    return -1;

  if (port < dp->port_range_start || port > dp->port_range_end)
    return -1;

  u32 port_offset = (port - dp->port_range_start) / dp->ports_per_host;
  u32 host_offset = (outside_offset * dp->sharing_ratio) + port_offset;

  if (host_offset >= dp->inside_count)
    return -1;

  inside_ip_out->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (dp->inside_base.as_u32) + host_offset);

  return 0;
}

always_inline cgnat_pool_t *
cgnat_pool_for_outside_ip (ip4_address_t *outside_ip)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;

  pool_foreach (pool, cm->pools)
    {
      if (pool->mode == CGNAT_POOL_MODE_DETERMINISTIC)
	{
	  for (u32 i = 0; i < pool->n_det_params; i++)
	    {
	      cgnat_det_params_t *dp = &pool->det_params[i];
	      u32 off = clib_net_to_host_u32 (outside_ip->as_u32) -
			clib_net_to_host_u32 (dp->outside_base.as_u32);
	      if (off < dp->outside_count)
		return pool;
	    }
	}
    }
  return NULL;
}

/* True for protocols where outside_port allocation is meaningless (no L4
 * demux: GRE, ESP, AH, SCTP, IP-in-IP, OSPF, UDP-Lite, etc.). Sessions for
 * unknown protos are keyed on (saddr, daddr, 0, 0, proto, fib) — one shared
 * session per (subscriber, remote, proto) tuple regardless of how many
 * simultaneous flows the subscriber opens. RFC 4787 permits this for
 * non-port-bearing protocols. */
always_inline int
cgnat_is_unk_proto (u8 proto)
{
  switch (proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_ICMP:
      return 0;
    default:
      return 1;
    }
}

/* RFC 792 ICMP types we treat as errors. Errors carry the inner IP+L4 header
 * in their payload — the NAT slowpath uses that inner header to find the
 * original session and rewrite both the outer dst and the inner src/sport so
 * subscribers see correctly-targeted ICMP errors (the path that makes
 * traceroute / PMTUD / Dest-Unreach feedback work). Lifted from VPP's
 * cnat plugin (cnat_node.h:99-113), matches what nat44-ed's
 * nat_get_icmp_session_lookup_values dispatches on. */
always_inline u8
icmp_type_is_error_message (u8 icmp_type)
{
  switch (icmp_type)
    {
    case ICMP4_destination_unreachable:
    case ICMP4_source_quench:
    case ICMP4_redirect:
    case ICMP4_alternate_host_address:
    case ICMP4_time_exceeded:
    case ICMP4_parameter_problem:
      return 1;
    }
  return 0;
}

#endif /* __included_osvbng_cgnat_h__ */
