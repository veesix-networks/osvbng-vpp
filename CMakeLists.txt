# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# osvbng Tunnel Plugin
# Generic tunnel RX dispatch: re-enters the device-input feature arc
# after tunnel decap so osvbng features work on tunnel interfaces.

add_vpp_plugin(osvbng_tunnel
  SOURCES
  osvbng_tunnel.c
  osvbng_tunnel_api.c
  osvbng_tunnel_cli.c
  osvbng_tunnel_node.c

  API_FILES
  osvbng_tunnel.api
)
