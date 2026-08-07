/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng L2GW Plugin
 *
 * Layer 2 wholesale gateway: cross-connects subscriber circuits between
 * access ports and handoff ports with optional S/C-VLAN tag rewrite.
 * Circuits are keyed on (rx sw_if_index, svlan, cvlan) with a per-S-VLAN
 * wildcard fallback, installed in bidirectional pairs, and forwarded
 * entirely in the dataplane — no L3 termination, no MAC learning, no
 * flooding.
 */

#ifndef __included_osvbng_l2gw_h__
#define __included_osvbng_l2gw_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/error.h>

#define L2GW_CVLAN_ANY 0xFFFF

#define L2GW_NUM_BUCKETS (64 * 1024)
#define L2GW_MEMORY_SIZE (8 << 20)

#define L2GW_DAMPENER_NUM_BUCKETS (16 * 1024)
#define L2GW_DAMPENER_MEMORY_SIZE (4 << 20)
#define L2GW_DAMPENER_DEFAULT_INTERVAL 5.0

/* Shared osvbng plugin idempotency contract: duplicate add whose mutable
 * fields drifted from the stored circuit. Same value across osvbng
 * plugins so the Go control plane has one constant. */
#ifndef VNET_API_ERROR_ENTRY_NEEDS_REFRESH
#define VNET_API_ERROR_ENTRY_NEEDS_REFRESH (-500)
#endif

#define L2GW_ENTRY_F_ENABLED     (1 << 0)
#define L2GW_ENTRY_F_WILDCARD    (1 << 1)
#define L2GW_ENTRY_F_TRANSPARENT (1 << 2)
#define L2GW_ENTRY_F_ACCESS_SIDE (1 << 3)

typedef struct
{
  union
  {
    struct
    {
      u32 rx_sw_if_index;
      u16 svlan;   /* outer tag; 0 = untagged */
      u16 cvlan;   /* inner tag; 0 = none; L2GW_CVLAN_ANY = wildcard */
      u64 _pad;
    } fields;
    u64 as_u64[2];
  };
} l2gw_key_t;

STATIC_ASSERT_SIZEOF (l2gw_key_t, 16);

/* One direction of a circuit. Entries are installed in pairs; the entry
 * pool index doubles as the combined-counter index. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* forwarding result */
  u32 tx_sw_if_index;
  u16 tx_svlan;        /* 0 = emit untagged (exact circuits only) */
  u16 tx_cvlan;        /* 0 = no inner tag */
  u16 tx_outer_tpid;   /* ETHERNET_TYPE_DOT1AD or ETHERNET_TYPE_VLAN */
  u8 flags;
  u8 _rsvd0;

  /* own lookup key (for delete / dump) */
  u32 rx_sw_if_index;
  u16 rx_svlan;
  u16 rx_cvlan;

  u32 peer_entry_index;
  u32 circuit_id;      /* pool index of the access-side entry */

  /* reserved for later sub-features */
  u32 qos_index;
  u32 acl_index;
} l2gw_entry_t;

typedef struct
{
  union
  {
    struct
    {
      u32 entry_index;
      u32 _unused;
    } fields;
    u64 raw;
  };
} l2gw_result_t;

typedef enum
{
#define l2gw_error(n, s) L2GW_ERROR_##n,
#include <osvbng_l2gw/osvbng_l2gw_error.def>
#undef l2gw_error
  L2GW_N_ERROR,
} l2gw_error_t;

extern char *l2gw_error_strings[];

typedef struct
{
  l2gw_entry_t *entries;
  clib_bihash_16_8_t circuit_table;

  /* ports armed with the device-input feature (bookkeeping) */
  uword *enabled_by_sw_if_index;

  /* per-port S-VLAN bitmaps arming the DHCP trigger snoop on circuit
   * miss; vector indexed by sw_if_index, NULL = no snoop on port */
  uword **trigger_svlans;

  /* per-port S-VLAN bitmaps arming the any-protocol trigger snoop:
   * every ethertype punts on circuit miss, gated by the dampener */
  uword **trigger_any_svlans;

  /* per-tuple last-punt time for the any-protocol trigger; key
   * port<<32|svlan<<16|cvlan, value f64 vlib time bits. Entries are
   * overwritten on punt, so the table is bounded by the armed tuple
   * count and needs no sweeper. */
  clib_bihash_8_8_t trigger_dampener;
  f64 trigger_dampen_interval;

  /* l2gw-input -> osvbng-punt-shm-tx (~0 = punt plugin not loaded) */
  u32 punt_shm_tx_next_arc;

  vlib_combined_counter_main_t counters;

  u16 msg_id_base;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2gw_main_t;

extern l2gw_main_t l2gw_main;

extern vlib_node_registration_t l2gw_input_node;

typedef struct
{
  u8 is_add;
  u32 access_sw_if_index;
  u16 access_svlan;
  u16 access_cvlan;   /* L2GW_CVLAN_ANY for wildcard */
  u16 access_tpid;
  u32 handoff_sw_if_index;
  u16 handoff_svlan;
  u16 handoff_cvlan;  /* L2GW_CVLAN_ANY for wildcard */
  u16 handoff_tpid;
  u8 transparent;
  u8 enabled;
} vnet_l2gw_add_del_circuit_args_t;

int vnet_l2gw_add_del_circuit (vnet_l2gw_add_del_circuit_args_t *a,
			       u32 *circuit_idp);
int vnet_l2gw_circuit_set_state (u32 circuit_id, u8 enabled);
int vnet_l2gw_enable_disable (u32 sw_if_index, u8 enable);
int vnet_l2gw_trigger_svlan_range (u32 sw_if_index, u16 svlan_lo,
				   u16 svlan_hi, u8 any_protocol, u8 is_add);

always_inline void
l2gw_make_key (l2gw_key_t *key, u32 sw_if_index, u16 svlan, u16 cvlan)
{
  key->as_u64[0] = 0;
  key->as_u64[1] = 0;
  key->fields.rx_sw_if_index = sw_if_index;
  key->fields.svlan = svlan;
  key->fields.cvlan = cvlan;
}

/* Exact-then-wildcard lookup with a one-entry cache per key form. */
static_always_inline void
l2gw_lookup_1 (clib_bihash_16_8_t *table, l2gw_key_t *cached_key,
	       l2gw_result_t *cached_result, u32 sw_if_index, u16 svlan,
	       u16 cvlan, l2gw_result_t *result)
{
  l2gw_key_t key;
  l2gw_make_key (&key, sw_if_index, svlan, cvlan);

  if (key.as_u64[0] == cached_key->as_u64[0] &&
      key.as_u64[1] == cached_key->as_u64[1])
    {
      result->raw = cached_result->raw;
      return;
    }

  clib_bihash_kv_16_8_t kv;
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.value = ~0ULL;
  clib_bihash_search_inline_16_8 (table, &kv);
  result->raw = kv.value;

  cached_key->as_u64[0] = key.as_u64[0];
  cached_key->as_u64[1] = key.as_u64[1];
  cached_result->raw = result->raw;
}

#endif /* __included_osvbng_l2gw_h__ */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
