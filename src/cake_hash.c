/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Flow hashing
 * Set-associative flow lookup with SIMD tag comparison.
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <osvbng_qos_sched/osvbng_qos_sched.h>

/*
 * Batch flow hash computation for a vector of packets.
 * Extracts 5-tuple from IP + TCP/UDP headers and computes xxhash.
 *
 * TODO: SIMD-optimized version for AVX2/AVX-512:
 * - Gather IP src/dst addresses across 4-8 packets
 * - Gather port pairs
 * - Compute hashes in parallel
 * - 8-way tag comparison with _mm256_cmpeq_epi32 + _mm256_movemask_epi8
 */

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
