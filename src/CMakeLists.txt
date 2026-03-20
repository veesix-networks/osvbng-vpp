# Copyright 2026 Veesix Networks Ltd
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# osvbng QoS Scheduler Plugin
# CAKE-equivalent per-subscriber traffic scheduling with FQ, AQM, and shaping.

add_vpp_plugin(osvbng_qos_sched
  SOURCES
  osvbng_qos_sched.c
  osvbng_qos_sched_api.c
  cake_enqueue.c
  cake_dequeue.c
  cake_cobalt.c
  cake_overhead.c

  MULTIARCH_SOURCES
  cake_enqueue.c
  cake_dequeue.c

  API_FILES
  osvbng_qos_sched.api
)
