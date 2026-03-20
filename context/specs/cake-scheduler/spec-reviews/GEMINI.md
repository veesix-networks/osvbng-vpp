# Spec Review: CAKE-Equivalent Per-Subscriber Scheduler (GEMINI)

## Overview

This review evaluates the `cake-scheduler` implementation specification and the current skeleton implementation for RFC compliance, protocol correctness, and algorithmic integrity. The design is ambitious and correctly identifies the BNG as the optimal point for CAKE deployment. However, several critical implementation gaps and mathematical inaccuracies in the AQM logic must be addressed to ensure the scheduler behaves as intended.

## Findings

### CRITICAL

#### 1. Buffer Ownership and Memory Corruption (cake_enqueue.c)
- **Problem:** The `cake_enqueue_node` currently stores buffer indices in the flow queue and then sets `next0 = CAKE_ENQUEUE_NEXT_DROP`. 
- **Impact:** In VPP, the `error-drop` node will immediately free the buffer back to the pool unless its reference count is incremented. When the `cake_dequeue_node` later attempts to access these buffer indices, it will result in a **use-after-free** (UAF) condition, leading to crashes or data corruption.
- **Resolution:** The enqueue node must "steal" the buffer by NOT forwarding it to any next node in the frame, or it must explicitly increment the buffer reference count if it is passed to a drop node. The preferred VPP pattern is to not enqueue stolen buffers to any next node.

#### 2. Inefficient Dequeue Frame Handling (cake_dequeue.c)
- **Problem:** The `cake_dequeue_node` calls `vlib_get_next_frame` and `vlib_put_next_frame` *inside* the per-packet dequeue loop.
- **Impact:** This is extremely expensive in VPP and defeats the purpose of vector processing. It will cause massive CPU overhead and severely limit the number of subscribers the BNG can handle.
- **Resolution:** Frame acquisition and release must be moved outside the per-packet loop. Use a local vector to collect dequeued buffer indices and perform a bulk enqueue to the next node (`interface-output-arc-end`).

### HIGH

#### 3. Incorrect CoDel Control Law (cake_dequeue.c)
- **Problem:** The implementation uses `now_us + cs->interval_us / (flow->codel_count + 1)` to schedule the next drop.
- **Impact:** **Violation of RFC 8289.** The CoDel algorithm MUST use the reciprocal square root: `interval / sqrt(count)`. Using a linear divisor `1/(n+1)` will cause the drop rate to increase exponentially faster than intended, leading to premature throughput collapse and poor TCP performance.
- **Resolution:** Implement the Newton-Raphson `rec_inv_sqrt` cache and calculation as described in the spec and used in `sch_cake.c`.

#### 4. Missing Triple Isolation Implementation
- **Problem:** While the spec describes "triple isolation" (per-host fairness), the implementation (both `osvbng_qos_sched.h` and `cake_enqueue.c`) lacks the host tracking table and the logic to adjust quantum based on host flow counts.
- **Impact:** A single host behind a CPE (e.g., a PC with many torrent connections) can still starve other hosts (e.g., a VoIP phone) within the same subscriber's allocation.
- **Resolution:** Add a per-tin host hash table and implement host flow counting in the enqueue path and quantum adjustment in the dequeue path.

#### 5. IPv6 Extension Header Handling (cake_hash_flow_ip6)
- **Problem:** The IPv6 flow hashing logic assumes L4 ports are always at a fixed offset after the IPv6 header.
- **Impact:** Packets with extension headers (Hop-by-Hop, Fragmentation, etc.) will have incorrect port extraction, leading to all such packets from a host being lumped into a single flow queue, breaking FQ-CoDel isolation.
- **Resolution:** Use a VPP helper or implement a simple loop to skip extension headers to reach the L4 header.

### MEDIUM

#### 6. Missing IPv6 Flow Label in Hashing (RFC 8290)
- **Problem:** `cake_hash_flow_ip6` does not incorporate the 20-bit IPv6 Flow Label.
- **Impact:** **Non-compliance with RFC 8290.** The RFC RECOMMENDS including the Flow Label to improve isolation for encrypted or opaque traffic where L4 ports are unavailable.
- **Resolution:** Incorporate the Flow Label into the `clib_xxhash` input for IPv6 packets.

#### 7. Memory Footprint at Scale
- **Problem:** 1024 flows per tin * 8 tins = 8192 flows (~640 KB) per subscriber.
- **Impact:** 10,000 subscribers require ~6.4 GB of memory just for the scheduler state. This may exceed default VPP hugepage allocations in typical BNG deployments.
- **Resolution:** Consider reducing `CAKE_QUEUES` to 256 or 512 for residential BNG use cases, or make it a configurable parameter. Ensure the `flows` array is only allocated for active tins.

#### 8. Weak Randomness for BLUE Algorithm
- **Problem:** BLUE uses `now_us ^ bi` as a source of randomness.
- **Impact:** This is highly predictable and may lead to synchronized drops or poor isolation for unresponsive flows.
- **Resolution:** Use a proper pseudo-random generator (e.g., `clib_random_u32` or a fast SIMD PRNG).

### LOW

#### 9. Missing DRR List Rotations
- **Problem:** `cake_dequeue.c` lacks the logic to move a flow to the end of the DRR list when its deficit is exhausted.
- **Impact:** Degraded fairness; the first flow in the list may consume more than its fair share of the dequeue budget in a single node invocation.

#### 10. Scalar Processing Bottleneck
- **Problem:** The current implementation is purely scalar.
- **Impact:** Higher CPU cycles per packet compared to standard VPP vector nodes.
- **Resolution:** Future phases should implement the dual-loop / quad-loop pattern with prefetch for both enqueue and dequeue nodes.

## Recommendations

1.  **Prioritize Buffer Safety:** Address the `error-drop` issue in `cake_enqueue.c` immediately, as it prevents any functional testing of the dequeue path.
2.  **Fix CoDel Math:** Replace the linear divisor with the `rec_inv_sqrt` approach before proceeding to AQM validation.
3.  **Host Tracking:** If "Triple Isolation" is a marquee feature, the host table structures must be added to `cake_tin_t`.
4.  **Incremental Checksum:** Use `ip4_header_checksum_update` for ECN marking in IPv4 for better performance.
5.  **Clean-up Path:** Ensure that `cake_sched_enable_disable(is_enable=false)` correctly drains and frees all buffers currently held in flow queues to avoid memory leaks on subscriber disconnect.
