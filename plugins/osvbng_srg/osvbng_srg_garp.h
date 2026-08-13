/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin - GARP/NA construction
 */

#ifndef __included_osvbng_srg_garp_h__
#define __included_osvbng_srg_garp_h__

#include <osvbng_srg/osvbng_srg.h>

/* One GARP/NA to build and send. The frame transmits on the wire parent
 * of sw_if_index; VLAN tags come from the entry, not from sub-interface
 * rewrite state (catch-all vlan-any sub-interfaces have none). */
typedef struct
{
  u32 sw_if_index;
  u16 outer_vlan; /* 0 = untagged */
  u16 inner_vlan; /* 0 = single tag */
  u16 outer_tpid; /* 0 = 0x8100 */
  u8 is_ip6;
  ip46_address_t ip;
} osvbng_srg_garp_entry_arg_t;

int osvbng_srg_send_garp_batch (vlib_main_t *vm, u8 *srg_name,
				osvbng_srg_garp_entry_arg_t *entries,
				u32 count, mac_address_t *virtual_mac);

#endif /* __included_osvbng_srg_garp_h__ */
