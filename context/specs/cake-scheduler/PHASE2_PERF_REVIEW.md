# Phase 2 Performance Review Spec

**Purpose:** Document performance concerns identified during Phase 2 implementation for review by Codex and Gemini before optimization work begins.

**Context:** Phase 2 (per-flow queuing + DRR) is functionally complete and tested. This document captures the delta between our current VPP implementation and the Linux CAKE reference (`sch_cake.c`), focusing on hot-path CPU efficiency.

## Current Implementation (functional, not yet optimized)

### Hot-Path: Enqueue (ip4-cake-enqueue node)

Per-packet operations in the enqueue path:

1. **Flow hashing:** `clib_xxhash()` on 5-tuple extracted from IP/TCP/UDP headers
2. **Set-associative lookup:** 8 sequential `u32` comparisons in `flow_tags[]` array
3. **Per-flow queue append:** `vec_add1(flow->queue, bi0)` — VPP vec append
4. **DRR list management:** O(1) prepend via head+tail pointer linked list
5. **Flow state transition:** NONE→SPARSE→BULK state machine with list move

Current measured overhead: **282 c/v** (Phase 1 FIFO baseline, Phase 2 not yet benchmarked)

### Hot-Path: Dequeue (cake-dequeue INPUT node)

Per-packet operations in the dequeue path:

1. **Flow selection:** Walk DRR list heads (new→old→decaying)
2. **Deficit accounting:** Subtract adjusted packet length from flow deficit
3. **Per-flow queue pop:** `flow->queue[flow->head++]` — array index + increment
4. **Shaper charge:** Multiply adjusted length by rate_ns_per_byte
5. **Re-injection:** `vnet_feature_arc_start()` + buffer flag set
6. **DRR rotation:** O(1) remove + append-tail on deficit exhaustion

## Identified Performance Concerns

### 1. Per-Flow Queue: `vec_add1` on Every Enqueue

**Problem:** Every enqueued packet calls `vec_add1(flow->queue, bi0)`. VPP vecs are dynamically-grown arrays — `vec_add1` checks capacity and may call `clib_mem_alloc` to grow the vec. Even when capacity is sufficient, the branch prediction overhead of the growth check runs on every packet.

**Linux CAKE approach:** Uses `__skb_queue_tail()` — an intrusive doubly-linked list where each `sk_buff` has built-in `next`/`prev` pointers. Zero allocation, O(1), no capacity checks.

**VPP equivalent options:**

- **Option A: Pre-allocated ring buffer.** Replace `u32 *queue` + `u32 head` with a fixed-size circular buffer per flow. Pre-allocate on flow activation (e.g. 256 entries). Head and tail indices, mask-based wrap. Zero allocations on the hot path. Cost: 1KB per active flow (256 × 4 bytes). Similar to VPP's `svm_fifo` pattern.

  ```c
  typedef struct {
    u32 *ring;         /* pre-allocated fixed array */
    u32 ring_mask;     /* power-of-2 mask for wrap */
    u32 head;          /* dequeue position */
    u32 tail;          /* enqueue position */
  } cake_flow_t;

  /* Enqueue: */
  flow->ring[flow->tail & flow->ring_mask] = bi0;
  flow->tail++;

  /* Dequeue: */
  u32 bi = flow->ring[flow->head & flow->ring_mask];
  flow->head++;

  /* Queue length: */
  u32 len = flow->tail - flow->head;
  ```

  Pro: Zero allocation, single cache line for head/tail, mask wrap is 1 AND instruction.
  Con: Wastes memory if flow has few packets. Fixed max depth per flow (but overflow = AQM drop, which is correct behavior).

- **Option B: Vec with pre-allocation.** Keep `vec_add1` but call `vec_validate` on flow activation to pre-size the vec. Reduces reallocation frequency but doesn't eliminate the growth check branch.

- **Option C: VPP buffer index FIFOs.** Use `clib_fifo_add1` / `clib_fifo_sub1` from `vppinfra/fifo.h`. VPP's built-in circular FIFO for `u32` values. Power-of-2 sizing, mask-based wrap, pre-allocated. This is the VPP-idiomatic equivalent of Option A.

**Recommendation:** Option C (`clib_fifo`) if it fits the API, otherwise Option A (manual ring buffer). Both are zero-allocation on the hot path.

### 2. DRR List: Non-Circular with Separate Head+Tail

**Problem:** Our DRR linked lists use separate `head` and `tail` pointers with a non-circular doubly-linked list. This works and is O(1), but every list operation must update both pointers with conditional checks for empty/single-element cases.

**Linux CAKE approach:** Uses `list_head` — a circular doubly-linked list where `head->prev` IS the tail. `list_add_tail(&flow->flowchain, &b->old_flows)` is O(1) with no conditionals (the sentinel head is always present). `list_move_tail` combines remove + add-tail in a single function.

**VPP equivalent:** VPP provides `clib_llist` (`vppinfra/llist.h`) which implements the exact same pattern — circular doubly-linked with sentinel, O(1) add/add_tail/remove, pool-backed elements. However, `clib_llist` assumes pool-allocated elements (uses `pool_elt_at_index`), and our flows are a pre-allocated vec, not a pool.

**Options:**

- **Option A: Embed `clib_llist_anchor_t` in `cake_flow_t`.** Use `clib_llist` macros with the flows vec treated as a pool (it's a contiguous array indexed by u32, which is what pool macros expect). The `clib_llist` macros use `pool_elt_at_index` which is just `vec + index` — this works on any array. Need to verify no pool metadata assumptions.

- **Option B: Manual circular list with sentinel.** Allocate one extra flow entry as the sentinel (e.g. flow index `CAKE_QUEUES` = 1024, never used for real flows). `head->prev = tail`, `tail->next = head`. All operations become unconditional. No separate tail pointer needed.

- **Option C: Keep current approach.** The head+tail pointer approach is already O(1). The extra conditionals for empty-list edge cases are a single branch prediction per operation. At 10 active flows, this is ~10 branches per dequeue round — likely immeasurable vs the cache-miss cost of accessing flow state.

**Recommendation:** Option C (keep current). The branch cost is negligible vs memory access. If profiling shows otherwise, Option B is clean.

### 3. Set-Associative Lookup: Sequential 8-Way Probe

**Problem:** The flow lookup probes 8 slots sequentially with a loop. Each iteration loads `flow_tags[slot]`, compares, and branches.

**Linux CAKE approach:** Same sequential scan. The `cake_hash` function does `for (i = 0; i < CAKE_SET_WAYS; i++)` with an early-exit on match. No SIMD.

**VPP optimization opportunity:** The 8 tags fit in a single 256-bit AVX2 register. A `_mm256_cmpeq_epi32` + `_mm256_movemask_epi8` reduces 8 comparisons to 1 instruction + a bit scan. However:
- The tags are `u32` values in a contiguous array — perfect for SIMD load.
- Only beneficial if flow count is high enough that the loop doesn't early-exit on the first slot.
- For typical BNG subscribers (10-50 concurrent flows, 128 sets), most lookups hit in the first 1-2 probes.

**Recommendation:** Keep sequential for Phase 2. Profile first. SIMD is a Phase 5+ micro-optimization. The spec already notes this as future work.

### 4. Dequeue: Per-Packet `vlib_buffer_length_in_chain`

**Problem:** Every dequeued packet calls `vlib_buffer_length_in_chain(vm, b)` which may walk the buffer chain for multi-segment packets.

**Linux CAKE approach:** Uses `skb->len` which is pre-computed and O(1).

**VPP equivalent:** For single-segment buffers (the common case at 100 Mbps — packets are well under 9KB MTU), `vlib_buffer_length_in_chain` returns `b->current_length` directly. For multi-segment (GSO/jumbo), it walks the chain. This is acceptable for Phase 2.

**Optimization:** Store the packet length at enqueue time in a per-flow side array or in the buffer opaque. This avoids re-computing it at dequeue. However, the single-segment fast path is already O(1), so the benefit is marginal.

**Recommendation:** Keep current. Optimize only if multi-segment packets become common (GSO split is Phase 5+).

### 5. Flow Queue Compaction: `vec_reset_length` After Drain

**Problem:** When a flow's queue drains (`head >= vec_len(queue)`), we call `vec_reset_length(queue)` and reset `head = 0`. This is fine but the vec memory is never freed until flow reclamation. With the ring buffer approach (Concern #1), this becomes irrelevant.

### 6. `quantum_div` Pre-Computed Table (Linux CAKE Pattern)

**Problem:** Linux CAKE uses a pre-computed `quantum_div[i] = 65535 / i` table to avoid integer division when computing per-flow deficit with triple isolation host load. Our Phase 2 doesn't implement triple isolation (Phase 6), but the pattern is worth noting.

**Recommendation:** Implement `quantum_div` table when triple isolation is added in Phase 6. Not relevant for Phase 2.

## Summary: Priority-Ordered Optimizations

| # | Concern | Impact | Phase | Recommendation |
|---|---------|--------|-------|---------------|
| 1 | `vec_add1` per enqueue | High — allocation check on every packet | Phase 2 | Switch to `clib_fifo` or ring buffer |
| 2 | Non-circular DRR lists | Low — already O(1), branch cost negligible | Defer | Keep current, profile later |
| 3 | Sequential 8-way probe | Low — early exit, typical <2 probes | Defer | Keep sequential, SIMD later |
| 4 | `vlib_buffer_length_in_chain` per dequeue | Low — O(1) for single-segment | Defer | Keep current |
| 5 | Vec compaction | None if ring buffer adopted | Phase 2 | Resolved by #1 |
| 6 | `quantum_div` table | N/A until Phase 6 | Phase 6 | Implement with triple isolation |

## Questions for Reviewers

1. Is `clib_fifo` the right VPP primitive for per-flow packet queues, or is there a better VPP-native FIFO for `u32` buffer indices?
2. Should we consider storing the packet length in buffer opaque at enqueue time to avoid `vlib_buffer_length_in_chain` at dequeue, or is the single-segment fast path sufficient?
3. Are there VPP-specific cache-line alignment considerations for the `cake_flow_t` struct that we should address now?
4. The Linux CAKE `cake_dequeue_one` function handles COBALT AQM inline within the dequeue loop. For VPP's vector model, should Phase 3 COBALT be a separate inline called per-packet, or integrated directly into the dequeue loop?
5. Any concerns about the `flow_tags[1024]` array being 4KB — does this cause cache pressure when multiple subscribers are active?
