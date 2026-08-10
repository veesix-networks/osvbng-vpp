/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin - GARP/NA construction
 */

#ifndef __included_osvbng_srg_garp_h__
#define __included_osvbng_srg_garp_h__

#include <osvbng_srg/osvbng_srg.h>

void osvbng_srg_garp_build (vlib_buffer_t *b, u32 sw_if_index,
			    ip4_address_t *ip4, mac_address_t *vmac);

void osvbng_srg_na_build (vlib_main_t *vm, vlib_buffer_t *b, u32 sw_if_index,
			  ip6_address_t *ip6, mac_address_t *vmac);

int osvbng_srg_send_garp_batch (vlib_main_t *vm, u8 *srg_name,
				u32 *sw_if_indices, ip46_address_t *ip_addrs,
				u8 *af_flags, u32 count,
				mac_address_t *virtual_mac);

#endif /* __included_osvbng_srg_garp_h__ */
