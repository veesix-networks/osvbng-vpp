/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin - init
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <osvbng_tunnel/osvbng_tunnel.h>

osvbng_tunnel_main_t osvbng_tunnel_main;

static clib_error_t *
osvbng_tunnel_init (vlib_main_t *vm)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;

  tm->vlib_main = vm;
  tm->vnet_main = vnet_get_main ();

  /* Register osvbng-tunnel-input as a next of the vxlan input nodes so
   * the control plane can create tunnels with it as the decap next.
   * vlib_node_add_next must run on the main thread; the vxlan nodes (if
   * that plugin is loaded) are registered before any
   * VLIB_INIT_FUNCTION. ~0 = vxlan plugin not loaded. */
  tm->vxlan4_decap_next = ~0;
  tm->vxlan6_decap_next = ~0;
  tm->pw_vxlan4_decap_next = ~0;
  tm->pw_vxlan6_decap_next = ~0;
  {
    vlib_node_t *vx4 = vlib_get_node_by_name (vm, (u8 *) "vxlan4-input");
    vlib_node_t *vx6 = vlib_get_node_by_name (vm, (u8 *) "vxlan6-input");
    if (vx4)
      {
	tm->vxlan4_decap_next =
	  vlib_node_add_next (vm, vx4->index, osvbng_tunnel_input_node.index);
	tm->pw_vxlan4_decap_next =
	  vlib_node_add_next (vm, vx4->index, osvbng_pw_input_node.index);
      }
    if (vx6)
      {
	tm->vxlan6_decap_next =
	  vlib_node_add_next (vm, vx6->index, osvbng_tunnel_input_node.index);
	tm->pw_vxlan6_decap_next =
	  vlib_node_add_next (vm, vx6->index, osvbng_pw_input_node.index);
      }
  }

  {
    vlib_node_t *drop = vlib_get_node_by_name (vm, (u8 *) "error-drop");
    tm->error_drop_node_index = drop->index;
  }

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_tunnel_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng Generic Tunnel RX Dispatch Plugin",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
