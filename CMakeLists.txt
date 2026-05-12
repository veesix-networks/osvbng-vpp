# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 veesix ::networks
#
# osvbng PPPoE Control Plugin
# Based on VPP pppoe plugin, with explicit control plane programming
# and Q-in-Q VLAN support.

add_vpp_plugin(osvbng_pppoe
  SOURCES
  osvbng_pppoe.c
  osvbng_pppoe_api.c
  osvbng_pppoe_decap.c
  osvbng_pppoe_lac_tx.c

  API_FILES
  osvbng_pppoe.api

  LINK_LIBRARIES
  ppp_plugin
)
