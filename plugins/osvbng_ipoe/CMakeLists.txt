# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 veesix ::networks
#
# osvbng IPoE Plugin
# Per-subscriber virtual interfaces for IPoE (IP over Ethernet) subscribers
# with explicit control plane programming and Q-in-Q VLAN support.

add_vpp_plugin(osvbng_ipoe
  SOURCES
  osvbng_ipoe.c
  osvbng_ipoe_api.c
  osvbng_ipoe_input.c

  API_FILES
  osvbng_ipoe.api
)
