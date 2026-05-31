# Copyright 2026 Veesix Networks Ltd
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# osvbng CGNAT Plugin
# Carrier-Grade NAT with PBA and Deterministic modes.

add_vpp_plugin(osvbng_cgnat
  SOURCES
  osvbng_cgnat.c
  osvbng_cgnat_api.c
  osvbng_cgnat_session.c
  osvbng_cgnat_in2out.c
  osvbng_cgnat_out2in.c
  osvbng_cgnat_handoff.c

  API_FILES
  osvbng_cgnat.api
)
