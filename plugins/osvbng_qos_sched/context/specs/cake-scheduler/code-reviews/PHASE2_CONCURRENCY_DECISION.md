# Phase 2 Concurrency Architecture — Final Decision

**Date:** 2026-03-20
**Sources:** Claude, Codex, Gemini — all three reviews in agreement

## Agreed Architecture

All three reviewers converge on the same design. No disagreements.

### 1. Per-session-interface scheduler ownership

- One `cake_sched_t` per subscriber (ipoe_session, pppoe_session, VLAN sub, physical — any VPP interface)
- One `owner_thread` per scheduler — immutable after assignment until explicit disable/rebind under barrier
- All mutable state (flow queues, DRR lists, shaper, deficit, counters) accessed only by the owner thread

### 2. Owner assignment

- **Primary:** explicit `owner_thread` parameter on `cake_sched_enable_disable` API. Control plane (osvbng or any other) determines the right worker based on deployment topology.
- **Fallback:** CAS-on-first-touch if `owner_thread == ~0`. First packet to enqueue claims the scheduler for its worker via `clib_atomic_cmp_and_swap`.
- Once claimed, owner is immutable. Rebind requires disable + re-enable under barrier.

### 3. Wrong-worker handoff

- Enqueue node: `if (PREDICT_FALSE(cs->owner_thread != vm->thread_index))` → handoff
- Store owner thread index in buffer opaque → next = dedicated handoff node
- Handoff node: `vlib_buffer_enqueue_to_thread(vm, node, fq_index, from, thread_indices, n, 1 /* drop_on_congestion */)`
- Congestion drops counted as `CAKE_ERROR_HANDOFF_CONGESTION` (separate from AQM drops)
- Handoff queue size: power-of-2, default 64, configurable via plugin init (follow IPsec pattern)

### 4. Dequeue node placement

- Keep `cake-dequeue` as `VLIB_NODE_TYPE_INPUT`
- **DISABLED** on workers with no owned schedulers
- **POLLING** on workers that own at least one scheduler
- Enable/disable per-worker via `vlib_node_set_state(vlib_get_main_by_index(owner_thread), ...)` at scheduler create/destroy time
- Dequeue only processes schedulers where `cs->owner_thread == vm->thread_index`
- Zero CPU cost on non-owner workers (node never dispatched)

### 5. Active bitmap guarantee

- Per-thread `active_bitmap` set ONLY by owner-thread enqueue (after handoff)
- Wrong-worker path does NOT set any bitmap bit
- Dequeue iterates only its own thread's bitmap
- This guarantees single-writer for all scheduler state

### 6. Bounded ring buffer per flow

- Replace `u32 *queue` + `vec_add1` with power-of-2 ring buffer
- Pre-allocate on flow activation (256 entries = 1KB per active flow)
- Enqueue: `ring[tail & mask] = bi; tail++` — one store, one AND, one increment
- Dequeue: `bi = ring[head & mask]; head++` — one load, one AND, one increment
- Overflow = drop (tail-drop in Phase 2, AQM drop in Phase 3)
- Zero allocator calls on hot path

### 7. Frame queue handoff mechanics

Pattern from IP reassembly + IPsec:

```
ip4-cake-enqueue (any worker)
  ├── owner_thread == thread_index → enqueue locally (fast path)
  └── owner_thread != thread_index → store owner in buffer opaque
                                    → next = cake-handoff node

cake-handoff node (any worker)
  └── vlib_buffer_enqueue_to_thread(..., drop_on_congestion=1)
      → target worker's frame queue

target worker main loop
  └── drain frame queue → ip4-cake-enqueue runs on owner thread
      → enqueue locally (always fast path now)
```

### 8. What we are NOT doing

- **No spinlock** in the datapath (defeats VPP vector processing)
- **No per-thread scheduler instances** (complex rate splitting, more memory)
- **No INTERRUPT mode for dequeue** (tight pacing needs POLLING, not coarse timer wakeups)
- **No NUMA-local allocation** in Phase 2 (defer to Phase 3/4 tuning, structure allows it later)
- **No live owner rebalance** (disable + re-enable under barrier is sufficient)

## Implementation Order

1. Add `owner_thread` to `cake_sched_t`, `owner_thread` parameter to enable API
2. Add CAS-on-first-touch in enqueue for fallback assignment
3. Register frame queue via `vlib_frame_queue_main_init()`
4. Add `cake-handoff` node (ip4 + ip6 variants)
5. Update enqueue: check owner → fast path or handoff
6. Update dequeue: only process schedulers where `owner_thread == thread_index`
7. Per-worker dequeue node state: DISABLED on non-owners, POLLING on owners
8. Replace `vec_add1` per-flow queue with power-of-2 ring buffer
9. Fix C2 (eviction buffer leak) and C3 (deactivate overflow) from consolidated findings
10. Add `CAKE_ERROR_HANDOFF_CONGESTION` counter

## Files to Modify

- `osvbng_qos_sched.h` — add `owner_thread` to `cake_sched_t`, ring buffer to `cake_flow_t`, handoff node registration
- `osvbng_qos_sched.c` — owner_thread in enable/disable, per-worker node state management, frame queue init
- `cake_enqueue.c` — owner check + handoff path
- `cake_dequeue.c` — owner_thread filter, deactivate bounds fix
- `cake_handoff.c` — NEW file: handoff node using `vlib_buffer_enqueue_to_thread()`
- `CMakeLists.txt` — add `cake_handoff.c`
- `osvbng_qos_sched_error.def` — add `HANDOFF_CONGESTION`
