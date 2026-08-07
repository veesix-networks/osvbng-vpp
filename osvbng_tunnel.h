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
 *
 * Pseudowire headend (PWHE): a transport tunnel can instead be bound
 * to a loopback headend. RX rewrites VLIB_RX to the headend and enters
 * ethernet-input, so subscriber VLAN subinterfaces on the headend
 * classify normally; the headend's hw output node is replaced so all
 * TX (including subif TX, which funnels through the sup hw) rides the
 * transport tunnel.
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

  /* osvbng-pw-input as a next of vxlan4-input / vxlan6-input, for
   * transport tunnels bound to a pseudowire headend */
  u32 pw_vxlan4_decap_next;
  u32 pw_vxlan6_decap_next;

  /* PWHE bindings, all vectors indexed by sw_if_index (~0 = unbound):
   * transport tunnel -> headend, headend -> transport tunnel, and the
   * headend's original hw output node for restore on unbind */
  u32 *pw_headend_by_tunnel;
  u32 *pw_tunnel_by_headend;
  u32 *pw_saved_output_node;

  u32 error_drop_node_index;

  u16 msg_id_base;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} osvbng_tunnel_main_t;

extern osvbng_tunnel_main_t osvbng_tunnel_main;

extern vlib_node_registration_t osvbng_tunnel_input_node;
extern vlib_node_registration_t osvbng_pw_input_node;
extern vlib_node_registration_t osvbng_pw_output_node;

int osvbng_tunnel_pw_bind (u32 tunnel_sw_if_index, u32 headend_sw_if_index,
			   u8 is_bind);

#endif /* __included_osvbng_tunnel_h__ */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
