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
)

# Deliberately no LINK_LIBRARIES ppp_plugin: only headers are used (the
# built .so has no undefined ppp symbols), and a plugin-to-plugin link
# in the in-tree build records a relative-path NEEDED entry that dlopen
# resolves against the working directory, which silently prevented this
# plugin from loading at all.
