/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Overhead compensation
 * Link-layer overhead adjustment for accurate shaping on DSL/PON access links.
 *
 * Overhead modes:
 *   none           - Raw Ethernet (0 overhead)
 *   ethernet       - +14 bytes Ethernet header
 *   docsis         - +18 bytes DOCSIS framing
 *   dsl-pppoe-ptm  - +27 bytes PPPoE over PTM (VDSL2 typical)
 *   dsl-pppoe-atm  - +32 bytes PPPoE over ATM (ADSL typical) + cell rounding
 *   gpon           - +4 bytes GPON GEM framing
 *
 * ATM cell rounding: packets are rounded up to the next 48-byte boundary,
 * then 5 bytes of ATM header per cell are added. This models the actual
 * link capacity consumed by each packet on ATM-based DSL.
 */

#include <osvbng_qos_sched/osvbng_qos_sched.h>

/*
 * Overhead mode presets.
 * Returns overhead_bytes, atm_mode, and mpu for a given mode string.
 *
 * TODO: Expose as API for Go-side overhead mode resolution.
 * Currently the Go side resolves mode → parameters and passes raw values
 * via the binary API. This file provides the reference implementation.
 */

typedef struct
{
  const char *name;
  i16 overhead_bytes;
  u8 atm_mode; /* 0=none, 1=ATM, 2=PTM */
  u8 mpu;
} cake_overhead_preset_t;

static cake_overhead_preset_t cake_overhead_presets[] = {
  { .name = "none", .overhead_bytes = 0, .atm_mode = 0, .mpu = 0 },
  { .name = "ethernet", .overhead_bytes = 14, .atm_mode = 0, .mpu = 64 },
  { .name = "docsis", .overhead_bytes = 18, .atm_mode = 0, .mpu = 64 },
  { .name = "dsl-pppoe-ptm",
    .overhead_bytes = 27,
    .atm_mode = 2,
    .mpu = 64 },
  { .name = "dsl-pppoe-atm",
    .overhead_bytes = 32,
    .atm_mode = 1,
    .mpu = 64 },
  { .name = "gpon", .overhead_bytes = 4, .atm_mode = 0, .mpu = 64 },
  { .name = NULL },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
