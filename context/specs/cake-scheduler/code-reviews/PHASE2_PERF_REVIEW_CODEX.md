# Phase 2 Performance Review Findings (Codex)

**Author:** Codex
**Date:** 2026-03-20
**Scope:** Static review of the current Phase 2 implementation against the Gemini-authored performance brief, the implementation spec, and the accepted decisions.

## Executive Summary

The top issue is not a micro-optimization: the current code still uses one scheduler per `sw_if_index` instead of per `(sw_if_index, thread_index)`, which creates real shared-state corruption risk on multi-worker TX paths. After that, the most worthwhile hot-path optimization remains replacing `vec_add1(flow->queue, bi0)` with a bounded FIFO/ring to remove allocation checks from enqueue.

I did not benchmark this pass. The conclusions below are from source review of `src/osvbng_qos_sched.h`, `src/osvbng_qos_sched.c`, `src/cake_enqueue.c`, and `src/cake_dequeue.c`.

## Reviewer Questions

### 1. Is `clib_fifo` the right VPP primitive for per-flow packet queues?

`clib_fifo` is reasonable only if it is created once at a fixed power-of-two depth and never resized on the hot path. For this scheduler, I would still prefer a simple manual ring buffer for `u32` buffer indices:

- it matches the exact access pattern
- bounded depth is acceptable and useful for CAKE-style admission/drop behavior
- it avoids any ambiguity around resize or helper-side bookkeeping

`svm_fifo` is not the right primitive here.

### 2. Should packet length be cached at enqueue time?

Not yet. `vlib_buffer_length_in_chain()` is effectively cheap for the common single-segment case, and Phase 3 already needs opaque space for enqueue timestamps. If metadata caching becomes necessary later, cache `adj_len` rather than raw packet length.

### 3. Are there cache-line alignment issues worth addressing now?

Yes, but not by cache-line-aligning every `cake_flow_t`.

- Keep `cake_flow_t` compact and hot-field-first.
- The more useful fix is to make sure `flow_tags[]` starts on a 32- or 64-byte boundary inside `cake_tin_t`, so an 8-way probe stays cache-friendly.
- The current `cake_tin_t` layout places `flow_tags` immediately after the `flows` pointer, so some sets will straddle cache lines unnecessarily.

### 4. Should COBALT be a separate inline or integrated into the dequeue loop?

Keep it integrated into the dequeue loop via a `static_always_inline` helper. A separate pass or node would force another walk over the same hot flow/buffer state and is the wrong tradeoff for VPP here.

### 5. Does the 4KB `flow_tags[1024]` array create cache pressure?

By itself, not much. Each lookup only touches 8 adjacent `u32` tags. The larger cache/scaling problem is the total per-scheduler working set:

- `flow_tags`
- the full preallocated 1024-entry `flows` array
- the embedded tin state

That is a stronger reason to move toward the lazy/pool-backed model from the accepted decisions than to micro-optimize the tag scan itself.

## Additional Performance Concerns Missed in the Brief

### 1. The hot paths are still scalar

Both enqueue and dequeue are still simple single-packet loops. There is no dual-loop batching, prefetch, or partitioning of scheduled vs passthrough traffic. That is likely higher leverage than concerns 2, 3, or 5 from the brief.

Relevant code:

- `../../../../src/cake_enqueue.c`
- `../../../../src/cake_dequeue.c`

### 2. Active-scheduler bookkeeping is on the enqueue hot path

Each enqueued packet does a `clib_bitmap_set()` on the active bitmap. That is extra write traffic and allocator risk in a path that should stay minimal.

### 3. The implementation still uses the larger preallocated working set

The accepted design moved toward per-thread instances plus lazy tin/flow allocation and a global queued-buffer watermark. The current code still preallocates 1024 flows per scheduler and only enforces a byte limit, so cache locality and memory pressure are worse than the brief assumes.

## Correctness Issues That Can Crash or Corrupt Memory Under Load

### 1. Shared scheduler state across workers

The implementation still maps `sw_if_index -> sched_index` globally instead of per thread. That means multiple workers can mutate the same scheduler, flow vecs, lists, counters, and shaper fields concurrently.

Files:

- `../../../../src/osvbng_qos_sched.h`
- `../../../../src/osvbng_qos_sched.c`
- `../../../../src/cake_enqueue.c`
- `../../../../src/cake_dequeue.c`

This is the highest-severity issue in the current implementation.

### 2. `deactivate[]` stack overflow in dequeue

`deactivate` is sized to `VLIB_FRAME_SIZE`, but the code can append more than that while scanning the active bitmap. A large number of emptied/freed schedulers in one pass will overrun the stack array.

File:

- `../../../../src/cake_dequeue.c`

### 3. Full-set eviction corrupts live state

When `cake_flow_lookup()` evicts a slot, it frees only the queue vec and zeroes the flow struct. It does not:

- free queued packet buffers still owned by the flow
- unlink the flow from DRR lists
- fix `flow_count`, `sparse_flow_count`, or `bulk_flow_count`

Under collision-heavy load this can orphan buffers and leave stale list pointers behind.

File:

- `../../../../src/osvbng_qos_sched.h`

## Other Important Correctness / Behavior Gaps

### 1. IPv6 extension headers are still not handled

The current IPv6 hash path assumes the transport header starts immediately after the fixed IPv6 header. That breaks hashing and fairness for extension-header traffic and fragments, despite the accepted decision to walk extension headers.

### 2. DRR deficit crediting is not truly round-based

`flow->deficit += tin->quantum` happens on every revisit of the selected bulk/decaying flow. Combined with shaper exits, that can give a flow more credit than intended before rotation.

## Ratings for the 6 Identified Concerns

| # | Concern | Rating | Reasoning |
|---|---------|--------|-----------|
| 1 | `vec_add1` on every enqueue | IMPORTANT | This is still the best legitimate Phase 2 hot-path optimization once the correctness issues are fixed. |
| 2 | Non-circular DRR lists | SKIP | Current operations are already O(1); the extra branches are noise relative to memory traffic and queue work. |
| 3 | Sequential 8-way probe | LOW | Linux CAKE does the same thing, and 8 adjacent tag loads are cheap relative to the surrounding state accesses. |
| 4 | `vlib_buffer_length_in_chain` per dequeue | LOW | Cheap in the single-segment case. Revisit only if chained buffers become common in production traffic. |
| 5 | `vec_reset_length` after drain | SKIP | Mostly a consequence of concern 1, not a worthwhile standalone optimization target. |
| 6 | `quantum_div` table | SKIP | Not relevant until triple isolation is implemented. |

## Bottom Line

If you want the next implementation step to have the highest value, I would prioritize in this order:

1. Fix per-thread scheduler ownership and the two memory-corruption hazards.
2. Replace per-flow vec queues with a bounded ring/FIFO.
3. Only then spend time on lower-level micro-optimizations such as list shape or tag-probe SIMD.
