/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin
 *
 * Generic tunnel RX dispatch: makes overlay tunnel interfaces (VXLAN
 * today, other encaps later) behave like physical ports at RX by
 * re-entering the device-input feature arc after decap. Every osvbng
 * dataplane feature that arms ports on that arc (l2gw, ipoe, pppoe,
 * punt) then works on tunnel interfaces without tunnel-specific code.
 */

#ifndef __included_osvbng_tunnel_h__
#define __included_osvbng_tunnel_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>

typedef struct
{
  /* osvbng-tunnel-input as a next of vxlan4-input / vxlan6-input, for
   * use as the vxlan tunnel decap_next_index (~0 = vxlan plugin not
   * loaded) */
  u32 vxlan4_decap_next;
  u32 vxlan6_decap_next;

  u16 msg_id_base;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} osvbng_tunnel_main_t;

extern osvbng_tunnel_main_t osvbng_tunnel_main;

extern vlib_node_registration_t osvbng_tunnel_input_node;

#endif /* __included_osvbng_tunnel_h__ */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
