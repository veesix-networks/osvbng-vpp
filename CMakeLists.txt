# Copyright 2025 Veesix Networks Ltd
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# osvbng SRG Plugin
# Subscriber Resilience Group dataplane management: virtual MAC programming,
# GARP/NA flooding, and per-SRG counters.

add_vpp_plugin(osvbng_srg
  SOURCES
  osvbng_srg.c
  osvbng_srg_api.c
  osvbng_srg_garp.c

  API_FILES
  osvbng_srg.api
)
