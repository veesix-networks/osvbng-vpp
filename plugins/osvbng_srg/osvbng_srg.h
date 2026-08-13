/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin
 * Subscriber Resilience Group dataplane management.
 */

#ifndef __included_osvbng_srg_h__
#define __included_osvbng_srg_h__

#include <vnet/plugin/plugin.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/mhash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/vlib.h>

/*
 * Key for hw_mac_refcount mhash: (hw_if_index, mac[6], pad[2]) = 12 bytes.
 * Tracks how many sub-interfaces on the same HW interface share a vMAC.
 */
typedef struct
{
  u32 hw_if_index;
  u8 mac[6];
  u8 _pad[2];
} osvbng_srg_hw_mac_key_t;

STATIC_ASSERT_SIZEOF (osvbng_srg_hw_mac_key_t, 12);

/*
 * Per-SRG data. Pool-allocated.
 */
typedef struct
{
  u8 srg_name[64];
  mac_address_t virtual_mac;
  bool is_active;
  u32 *sw_if_indices; /* vec of registered sub-interfaces */
} osvbng_srg_t;

/*
 * Plugin main structure
 */
typedef struct
{
  /* SRG pool */
  osvbng_srg_t *srgs;

  /* name → pool index */
  uword *srg_by_name;

  /* sw_if_index → pool index (~0 = unmapped) */
  u32 *if_to_srg;

  /* (hw_if_index, mac) → refcount for vMAC add/del dedup */
  mhash_t hw_mac_refcount;

  /* Per-SRG counters (main-thread only, no workers) */
  u64 *garp_sent;
  u64 *na_sent;
  u64 *mac_adds;
  u64 *mac_removes;
  u64 *garp_skipped;

  /* API message ID base */
  u16 msg_id_base;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  u32 intf_output_node_idx;
  vlib_log_class_t log_class;
} osvbng_srg_main_t;

extern osvbng_srg_main_t osvbng_srg_main;

/* Core functions */
int osvbng_srg_add_del (u8 *name, mac_address_t *mac, u32 *sw_if_indices,
			u32 count, u8 is_add);
int osvbng_srg_set_state (u8 *name, u8 is_active);

#endif /* __included_osvbng_srg_h__ */
