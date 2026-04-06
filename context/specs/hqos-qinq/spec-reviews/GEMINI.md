# Spec Review: Hierarchical QoS (HQoS) for QinQ Deployments (GEMINI)

## Overview

This review evaluates the Hierarchical QoS (HQoS) implementation specification for the VPP CAKE plugin. The design correctly identifies the need for aggregate shaping in QinQ (S-VLAN/C-VLAN) deployments and leverages the existing CAKE per-subscriber scheduler as a leaf node. While the dual-level token bucket and DRR approach are sound, there are significant risks regarding cross-thread memory safety during subscriber migration and potential algorithmic inefficiencies in the dequeue path.

## Findings

### CRITICAL

#### 1. Unsafe Cross-Thread Migration of Active Schedulers
- **Problem:** The spec (Section 4.5) forces a child's `owner_thread` to match the aggregate's owner during the "Attach" operation. If the child already has buffers queued on its original thread, the new owner thread will attempt to dequeue those buffers.
- **Impact:** **Use-after-free or race conditions.** VPP buffers are owned by the thread that "stole" them from the frame. If thread B attempts to dequeue or free a buffer that thread A is still managing (or has metadata for in its local cache), it will cause memory corruption or crashes.
- **Resolution:** Attach/Detach operations must be synchronized with a worker barrier if the child is not empty. Alternatively, only allow attaching a scheduler that has `owner_thread == ~0` or is verified to be empty. A VPP worker barrier is the standard way to handle such configuration changes safely.

#### 2. Potential Aggregate Buffer Accounting Drift
- **Problem:** The spec relies on manual charge/discharge of `agg->buffer_usage` across multiple code paths (Section 4.9).
- **Impact:** **Permanent Backpressure.** If any drop path (e.g., COBALT AQM, FQ-CoDel drop-head, or teardown) fails to decrement `agg->buffer_usage`, the aggregate will eventually believe it is full even when empty, permanently blocking new traffic for all children.
- **Resolution:** Implement a unified `cake_count_drop(sched, len)` helper that automatically handles aggregate discharge if `sched->aggregate_index != ~0`. This ensures all current and future drop logic remains consistent.

### HIGH

#### 3. Inefficient Dequeue Loop for Idle Children
- **Problem:** Section 4.6 describes a Phase 2 loop that iterates over children from `agg->child_head`. It implies idle children are "rotated to tail" rather than removed.
- **Impact:** **CPU Cycle Waste.** If an aggregate has 1,000 attached children but only 2 are active, the dequeue node will waste cycles traversing the linked list of 998 idle children in every invocation. This violates the mandate that "CPU cycles matter."
- **Resolution:** Maintain an "active_children" list/bitmap for each aggregate. Only children with queued packets should be part of the DRR rotation. Use the existing transition logic (empty to non-empty) to add/remove children from the aggregate's active set.

#### 4. Token Bucket "Credit" and Burst Handling
- **Problem:** The aggregate shaper `agg->global_shaper_time_ns` needs careful handling when the aggregate transitions from idle to active.
- **Impact:** **Massive Bursts.** If `global_shaper_time_ns` is not reset when the aggregate is idle, it may accumulate "negative time," leading to a line-rate burst when traffic resumes, potentially overwhelming downstream buffers.
- **Resolution:** Apply the same "no-accumulator" or "limited-credit" logic used in the base CAKE shaper: `if (now_ns > agg->global_shaper_time_ns) agg->global_shaper_time_ns = now_ns;` (possibly with a small burst allowance).

### MEDIUM

#### 5. Fairness under Asymmetric Load with DRR
- **Problem:** While DRR provides fair sharing by packet count/bytes, the spec defaults to equal quanta for all children (Section 4.10).
- **Impact:** A child configured for 10Mbps will get the same share of a congested 1Gbps aggregate as a child configured for 500Mbps, which is often counter-intuitive for tiered service models.
- **Resolution:** Implement the "Weighted DRR" extension in Phase 1. Since `agg_deficit` and `quantum` fields are already planned, calculating `child->quantum` proportional to its rate during the "Attach" operation is low-effort and significantly improves the product's utility.

#### 6. IPv6 Metric Consistency
- **Problem:** The spec mentions "shaped packets/bytes" but doesn't explicitly mandate IPv6-specific counters.
- **Impact:** Violation of the "IPv6 is a first-class citizen" mandate if IPv6 traffic is not explicitly tracked or if counters are 32-bit (prone to wrap on high-speed aggregates).
- **Resolution:** Ensure aggregate counters use `u64` and are incremented for both IPv4 and IPv6 traffic.

### LOW

#### 7. Aggregate Lookup Optimization
- **Problem:** Looking up the aggregate index via `sw_if_index` on every enqueue (Section 4.9).
- **Impact:** Minor performance hit depending on how `agg_index_by_sw_if_index` is implemented (sparse array vs. dense vector).
- **Resolution:** Since `sw_if_index` is usually dense in VPP, a simple vector is likely fine, but ensure the lookup is cached in the child's `cake_sched_t` (which the spec already does via `aggregate_index`).

## Recommendations

1.  **Mandatory Worker Barrier:** Add a worker barrier requirement to the "Attach" and "Detach" binary API handlers to ensure thread safety during ownership changes.
2.  **Explicit Active List:** Refine the data structures to include a `backlogged_child_head` to avoid iterating over idle subscribers.
3.  **Audit Drop Paths:** Before implementation, create a checklist of all locations in the CAKE plugin where buffers are freed/dropped to ensure `agg->buffer_usage` is always discharged.
4.  **Weighted DRR:** Promote Phase 4's weighted DRR to Phase 1 to ensure tiered fairness from the start.
