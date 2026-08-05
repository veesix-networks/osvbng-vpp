# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# osvbng L2GW Plugin
# Layer 2 wholesale gateway: DHCP-triggered L2 circuit switching between
# access networks and ISP handoff ports.

add_vpp_plugin(osvbng_l2gw
  SOURCES
  osvbng_l2gw.c
  osvbng_l2gw_api.c
  osvbng_l2gw_cli.c
  osvbng_l2gw_node.c

  API_FILES
  osvbng_l2gw.api
)
