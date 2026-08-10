/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin - CLI
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <osvbng_tunnel/osvbng_tunnel.h>

static clib_error_t *
show_osvbng_tunnel_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;

  vlib_cli_output (vm, "osvbng-tunnel-input decap next indices:");
  if (tm->vxlan4_decap_next != ~0u)
    vlib_cli_output (vm, "  vxlan4-input: %u", tm->vxlan4_decap_next);
  else
    vlib_cli_output (vm, "  vxlan4-input: (vxlan plugin not loaded)");
  if (tm->vxlan6_decap_next != ~0u)
    vlib_cli_output (vm, "  vxlan6-input: %u", tm->vxlan6_decap_next);
  else
    vlib_cli_output (vm, "  vxlan6-input: (vxlan plugin not loaded)");

  vlib_cli_output (vm, "osvbng-pw-input decap next indices:");
  if (tm->pw_vxlan4_decap_next != ~0u)
    vlib_cli_output (vm, "  vxlan4-input: %u", tm->pw_vxlan4_decap_next);
  else
    vlib_cli_output (vm, "  vxlan4-input: (vxlan plugin not loaded)");
  if (tm->pw_vxlan6_decap_next != ~0u)
    vlib_cli_output (vm, "  vxlan6-input: %u", tm->pw_vxlan6_decap_next);
  else
    vlib_cli_output (vm, "  vxlan6-input: (vxlan plugin not loaded)");

  vlib_cli_output (vm, "pseudowire bindings:");
  for (u32 i = 0; i < vec_len (tm->pw_headend_by_tunnel); i++)
    if (tm->pw_headend_by_tunnel[i] != ~0u)
      vlib_cli_output (vm, "  %U -> %U", format_vnet_sw_if_index_name,
		       tm->vnet_main, i, format_vnet_sw_if_index_name,
		       tm->vnet_main, tm->pw_headend_by_tunnel[i]);

  return 0;
}

VLIB_CLI_COMMAND (show_osvbng_tunnel_command, static) = {
  .path = "show osvbng tunnel",
  .short_help = "show osvbng tunnel",
  .function = show_osvbng_tunnel_fn,
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
