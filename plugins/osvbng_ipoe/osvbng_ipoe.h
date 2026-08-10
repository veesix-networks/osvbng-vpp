/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 veesix ::networks
 *
 * osvbng IPoE Plugin
 * Per-subscriber virtual interfaces for IPoE (IP over Ethernet) subscribers.
 */

#ifndef __included_osvbng_ipoe_h__
#define __included_osvbng_ipoe_h__

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
#include <vppinfra/bihash_16_8.h>

/*
 * IPoE Session Structure
 *
 * One session per subscriber, identified by (encap_if_index + inner_vlan + MAC).
 * Supports dual-stack with independent IPv4/IPv6/PD bindings.
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Session identification */
  u32 encap_if_index;           /* Parent S-VLAN sub-interface */
  u8 client_mac[6];             /* Subscriber MAC address */
  u8 local_mac[6];              /* BNG MAC address (src in TX frames) */
  u16 outer_vlan;               /* S-VLAN (0 if untagged) - for TX rewrite */
  u16 inner_vlan;               /* C-VLAN (0 if none) - for lookup + TX rewrite */
  u16 outer_tpid;               /* Snapshot of parent sub-interface TPID
                                   (ETHERNET_TYPE_DOT1AD or _VLAN) for outer
                                   tag emission. Resolved at session add. */

  /*
   * Dual-stack IP bindings (independent lifecycles)
   * Each binding can be set/cleared independently.
   */

  /* IPv4 binding (from DHCPv4) */
  ip4_address_t client_ipv4;
  u8 ipv4_bound;                /* 0 = no binding, 1 = bound */

  /* IPv6 WAN binding (from DHCPv6 IA_NA) */
  ip6_address_t client_ipv6;
  u8 ipv6_bound;                /* 0 = no binding, 1 = bound */

  /* IPv6 Prefix Delegation (from DHCPv6 IA_PD) */
  ip6_address_t delegated_prefix;
  u8 delegated_prefix_len;      /* 0 = no PD */
  ip6_address_t pd_next_hop;    /* Next-hop for PD route (link-local or IA_NA) */

  /* VRF */
  u32 decap_fib_index;
  u32 decap_fib_index_ip6;

  /* VPP interface indices */
  u32 sw_if_index;              /* ipoe_session virtual interface */
  u32 hw_if_index;

} ipoe_session_t;

/*
 * Input node next indices
 */
#define foreach_ipoe_input_next        \
_(DROP, "error-drop")                   \
_(ETHERNET_INPUT, "ethernet-input")     \
_(IP4_INPUT, "ip4-input")               \
_(IP6_INPUT, "ip6-input")

typedef enum
{
#define _(s,n) IPOE_INPUT_NEXT_##s,
  foreach_ipoe_input_next
#undef _
  IPOE_INPUT_N_NEXT,
} ipoe_input_next_t;

/*
 * Error codes
 */
typedef enum
{
#define ipoe_error(n,s) IPOE_ERROR_##n,
#include <osvbng_ipoe/osvbng_ipoe_error.def>
#undef ipoe_error
  IPOE_N_ERROR,
} ipoe_input_error_t;

extern char *ipoe_error_strings[];

/*
 * Session table sizing
 */
#define IPOE_NUM_BUCKETS (64 * 1024)
#define IPOE_MEMORY_SIZE (8 << 20)

/*
 * Session Lookup Key
 *
 * 16 bytes: sw_if_index (4) + inner_vlan (2) + mac (6) + pad (4)
 *
 * Supports all VLAN deployment models:
 * - 1:1 (S-VLAN per sub): Different sw_if_index per subscriber
 * - Q-in-Q 1:1 (S+C per sub): Same sw_if_index, different inner_vlan
 * - N:1 (shared S-VLAN): Same sw_if_index, inner_vlan=0, unique MAC
 * - N:1 Q-in-Q (shared S+C): Same sw_if_index + inner_vlan, unique MAC
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;          /* S-VLAN sub-interface (or physical) */
      u16 inner_vlan;           /* C-VLAN from packet (0 if none) */
      u8 mac[6];                /* Source MAC */
      u32 _pad;                 /* Pad to 16 bytes */
    } fields;
    u64 as_u64[2];
  };
} ipoe_entry_key_t;

STATIC_ASSERT_SIZEOF (ipoe_entry_key_t, 16);

/*
 * Session Lookup Result
 */
typedef struct
{
  union
  {
    struct
    {
      u32 sw_if_index;          /* ipoe_session sw_if_index */
      u32 session_index;        /* Index in session pool */
    } fields;
    u64 raw;
  };
} ipoe_entry_result_t;

/*
 * Main plugin structure
 */
typedef struct
{
  /* Session pool */
  ipoe_session_t *sessions;

  /* Lookup table: (sw_if_index + inner_vlan + MAC) -> session */
  clib_bihash_16_8_t session_table;

  /* Reverse lookup: ipoe_session sw_if_index -> session_index */
  u32 *session_index_by_sw_if_index;

  /* Bitmap of interfaces with IPoE enabled */
  uword *enabled_by_sw_if_index;

  /* Lazy ethertype registration (deferred until first BNG interface enable) */
  u8 ethertypes_registered;

  /* API message ID base */
  u16 msg_id_base;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} ipoe_main_t;

extern ipoe_main_t ipoe_main;

extern vlib_node_registration_t ipoe_input_node;

/*
 * Session add/del arguments
 */
typedef struct
{
  u8 is_add;
  u32 encap_if_index;
  u8 client_mac[6];
  u8 local_mac[6];
  u16 outer_vlan;
  u16 inner_vlan;
  u32 decap_fib_index;
} vnet_ipoe_add_del_session_args_t;

int vnet_ipoe_add_del_session (vnet_ipoe_add_del_session_args_t *a,
                               u32 *sw_if_indexp);

int vnet_ipoe_set_session_ipv4 (u32 sw_if_index, ip4_address_t *addr,
                                u8 is_add);

int vnet_ipoe_set_session_ipv6 (u32 sw_if_index, ip6_address_t *addr,
                                u8 is_add);

int vnet_ipoe_set_delegated_prefix (u32 sw_if_index, ip6_address_t *prefix,
                                    u8 prefix_len, ip6_address_t *next_hop,
                                    u8 is_add);

int vnet_ipoe_enable_disable (u32 sw_if_index, u8 enable);

/*
 * Inline helper to build lookup key
 */
always_inline void
ipoe_make_key (ipoe_entry_key_t *key, u32 sw_if_index, u16 inner_vlan,
               u8 *mac)
{
  key->as_u64[0] = 0;
  key->as_u64[1] = 0;
  key->fields.sw_if_index = sw_if_index;
  key->fields.inner_vlan = inner_vlan;
  clib_memcpy_fast (key->fields.mac, mac, 6);
}

/*
 * Session lookup with one-entry cache
 */
static_always_inline void
ipoe_lookup_1 (clib_bihash_16_8_t *table,
               ipoe_entry_key_t *cached_key,
               ipoe_entry_result_t *cached_result,
               u32 sw_if_index, u16 inner_vlan, u8 *mac,
               ipoe_entry_key_t *key,
               ipoe_entry_result_t *result)
{
  /* Build key */
  ipoe_make_key (key, sw_if_index, inner_vlan, mac);

  /* Check one-entry cache */
  if (key->as_u64[0] == cached_key->as_u64[0] &&
      key->as_u64[1] == cached_key->as_u64[1])
    {
      result->raw = cached_result->raw;
      return;
    }

  /* Cache miss - do table lookup */
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];
  kv.value = ~0ULL;

  clib_bihash_search_inline_16_8 (table, &kv);
  result->raw = kv.value;

  /* Update cache */
  cached_key->as_u64[0] = key->as_u64[0];
  cached_key->as_u64[1] = key->as_u64[1];
  cached_result->raw = result->raw;
}

/*
 * Add session to lookup table
 */
static_always_inline void
ipoe_session_table_add (clib_bihash_16_8_t *table, u32 sw_if_index,
                        u16 inner_vlan, u8 *mac, ipoe_entry_result_t *result)
{
  clib_bihash_kv_16_8_t kv;
  ipoe_entry_key_t key;

  ipoe_make_key (&key, sw_if_index, inner_vlan, mac);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.value = result->raw;

  clib_bihash_add_del_16_8 (table, &kv, 1 /* is_add */);
}

/*
 * Delete session from lookup table
 */
static_always_inline void
ipoe_session_table_del (clib_bihash_16_8_t *table, u32 sw_if_index,
                        u16 inner_vlan, u8 *mac)
{
  clib_bihash_kv_16_8_t kv;
  ipoe_entry_key_t key;

  ipoe_make_key (&key, sw_if_index, inner_vlan, mac);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.value = 0;

  clib_bihash_add_del_16_8 (table, &kv, 0 /* is_add */);
}

#endif /* __included_osvbng_ipoe_h__ */
