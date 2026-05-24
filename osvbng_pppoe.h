/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Copyright (c) 2025 veesix ::networks
 *
 * Based on VPP pppoe plugin, modified for explicit control plane programming
 * and Q-in-Q VLAN support.
 */

#ifndef __included_osvbng_pppoe_h__
#define __included_osvbng_pppoe_h__

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>

typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
  u16 ppp_proto;
} pppoe_header_t;

#define PPPOE_VER_TYPE 0x11

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* pppoe session_id in HOST byte order */
  u16 session_id;

  /* session client addresses */
  ip46_address_t client_ip;

  /* the index of tx interface for pppoe encaped packet */
  u32 encap_if_index;

  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  u8 local_mac[6];
  u8 client_mac[6];

  /* Q-in-Q VLAN support */
  u16 outer_vlan;  /* S-VLAN (0 if untagged) */
  u16 inner_vlan;  /* C-VLAN (0 if not Q-in-Q) */

  /* Snapshot of parent sub-interface TPID (ETHERNET_TYPE_DOT1AD or
   * ETHERNET_TYPE_VLAN) for outer-tag emission. Resolved at session add. */
  u16 outer_tpid;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /* LAC bridge state. When set, this PPPoE session is bridged to an
   * L2TPv2 session (no local PPP termination). The punt and decap
   * paths forward full PPP frames to `l2tpv2-encap-raw` with
   * `vnet_buffer_l2tpv2_opaque(b)` set to `lac_l2tp_session_index`.
   * Set by the Go control plane via the new
   * `osvbng_pppoe_set_lac_tunnel()` helper when the LAC session
   * reaches `PhaseLACTunneled`; cleared on session teardown. */
  u8 is_lac_tunneled;
  u32 lac_l2tp_session_index;

} osvbng_pppoe_session_t;

#define foreach_pppoe_input_next        \
_(DROP, "error-drop")                   \
_(IP4_INPUT, "ip4-input")               \
_(IP6_INPUT, "ip6-input" )

typedef enum
{
#define _(s,n) PPPOE_INPUT_NEXT_##s,
  foreach_pppoe_input_next
#undef _
    PPPOE_INPUT_N_NEXT,
} pppoe_input_next_t;

typedef enum
{
#define pppoe_error(n,s) PPPOE_ERROR_##n,
#include <osvbng_pppoe/osvbng_pppoe_error.def>
#undef pppoe_error
  PPPOE_N_ERROR,
} pppoe_input_error_t;

extern char *pppoe_error_strings[];

#define MTU 1500
#define MTU_BUFFERS ((MTU + vlib_buffer_get_default_data_size(vm) - 1) / vlib_buffer_get_default_data_size(vm))
#define NUM_BUFFERS_TO_ALLOC 32

/*
 * The size of pppoe session table
 */
#define PPPOE_NUM_BUCKETS (64 * 1024)
#define PPPOE_MEMORY_SIZE (8<<20)

/*
 * The PPPoE key is the mac address and session ID
 */
typedef struct
{
  union
  {
    struct
    {
      u16 session_id;
      u8 mac[6];
    } fields;
    struct
    {
      u32 w0;
      u32 w1;
    } words;
    u64 raw;
  };
} pppoe_entry_key_t;

/*
 * The PPPoE entry results
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;
      u32 session_index;
    } fields;
    u64 raw;
  };
} pppoe_entry_result_t;

typedef struct
{
  /* Vector of encap session instances */
  osvbng_pppoe_session_t *sessions;

  /* Session lookup table by (mac, session_id) */
  BVT (clib_bihash) session_table;

  /* Free vlib hw_if_indices */
  u32 *free_pppoe_session_hw_if_indices;

  /* Mapping from sw_if_index to session index */
  u32 *session_index_by_sw_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Number of PPPoE sessions currently in LAC-tunneled mode. Bumped
   * by `osvbng_pppoe_set_lac_tunnel()` on set, decremented on clear.
   * Plugin-internal: read by osvbng-pppoe-input to gate the LAC
   * dispatch branch on whether any LAC sessions exist at all. */
  u32 lac_session_count;

  /* Next-arc indices resolved lazily at first LAC-binding / first
   * non-IP PPP frame. ~0 means the destination plugin is not loaded
   * — frames fall back to drop. Resolved via vlib_node_add_next on
   * graph-node-by-name lookup; no cross-plugin symbol resolution. */
  u32 l2tpv2_encap_raw_next_arc; /* osvbng-pppoe-input -> l2tpv2-encap-raw */
  u32 punt_shm_tx_next_arc;   /* osvbng-pppoe-input -> osvbng-punt-shm-tx */

} osvbng_pppoe_main_t;

extern osvbng_pppoe_main_t osvbng_pppoe_main;

extern vlib_node_registration_t osvbng_pppoe_input_node;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u16 session_id;
  ip46_address_t client_ip;
  u32 encap_if_index;
  u32 decap_fib_index;
  u8 local_mac[6];
  u8 client_mac[6];
  u16 outer_vlan;
  u16 inner_vlan;
} vnet_osvbng_pppoe_add_del_session_args_t;

int vnet_osvbng_pppoe_add_del_session
  (vnet_osvbng_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp);

/* Set or clear the LAC-tunneled flag on a PPPoE session identified by
 * sw_if_index. On set, stores lac_l2tp_session_index for the punt-path
 * LAC bridge. Maintains osvbng_pppoe_main.lac_session_count. Returns 0
 * on success or -1 if the sw_if_index does not resolve to a session. */
int osvbng_pppoe_set_lac_tunnel
  (u32 sw_if_index, u8 is_lac_tunneled, u32 lac_l2tp_session_index);

always_inline u64
pppoe_make_key (u8 * mac_address, u16 session_id)
{
  u64 temp;

  /*
   * The mac address in memory is A:B:C:D:E:F
   * The session_id in register is H:L
   */
#if CLIB_ARCH_IS_LITTLE_ENDIAN
  /*
   * Create the in-register key as F:E:D:C:B:A:H:L
   * In memory the key is L:H:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) << 16;
  temp = (temp & ~0xffff) | (u64) (session_id);
#else
  /*
   * Create the in-register key as H:L:A:B:C:D:E:F
   * In memory the key is H:L:A:B:C:D:E:F
   */
  temp = *((u64 *) (mac_address)) >> 16;
  temp = temp | (((u64) session_id) << 48);
#endif

  return temp;
}

static_always_inline void
pppoe_lookup_1 (BVT (clib_bihash) * table,
                pppoe_entry_key_t * cached_key,
                pppoe_entry_result_t * cached_result,
                u8 * mac0,
                u16 session_id0,
                pppoe_entry_key_t * key0,
                u32 * bucket0, pppoe_entry_result_t * result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  if (key0->raw == cached_key->raw)
    {
      /* Hit in the one-entry cache */
      result0->raw = cached_result->raw;
    }
  else
    {
      /* Do a regular session table lookup */
      BVT (clib_bihash_kv) kv;

      kv.key = key0->raw;
      kv.value = ~0ULL;
      BV (clib_bihash_search_inline) (table, &kv);
      result0->raw = kv.value;

      /* Update one-entry cache */
      cached_key->raw = key0->raw;
      cached_result->raw = result0->raw;
    }
}

static_always_inline void
pppoe_update_1 (BVT (clib_bihash) * table,
                u8 * mac0,
                u16 session_id0,
                pppoe_entry_key_t * key0,
                u32 * bucket0, pppoe_entry_result_t * result0)
{
  /* set up key */
  key0->raw = pppoe_make_key (mac0, session_id0);
  *bucket0 = ~0;

  /* Update the entry */
  BVT (clib_bihash_kv) kv;
  kv.key = key0->raw;
  kv.value = result0->raw;
  BV (clib_bihash_add_del) (table, &kv, 1 /* is_add */ );
}

static_always_inline void
pppoe_delete_1 (BVT (clib_bihash) * table,
                u8 * mac0,
                u16 session_id0)
{
  BVT (clib_bihash_kv) kv;
  kv.key = pppoe_make_key (mac0, session_id0);
  kv.value = 0;
  BV (clib_bihash_add_del) (table, &kv, 0 /* is_add */ );
}

#endif /* __included_osvbng_pppoe_h__ */
