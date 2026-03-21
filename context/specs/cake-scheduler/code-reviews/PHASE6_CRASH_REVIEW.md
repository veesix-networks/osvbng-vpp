# Phase 6 Crash Review — Worker Thread Deadlock on Multi-Flow Traffic

**Date:** 2026-03-21
**Severity:** CRITICAL — VPP crashes under multi-flow load
**Symptom:** `vlib_worker_thread_barrier_sync_int: worker thread deadlock` → SIGABRT

## Reproduction

1. Deploy containerlab test 18 (ipoe-linux-client) with osvbng QoS plugin v6.0.0
2. Enable scheduler: `set cake scheduler ipoe_session0 rate 100000`
3. Run single iperf3 flow: **WORKS** — shapes to ~100 Mbits/sec
4. Run 10 parallel flows: `iperf3 -c 10.255.0.2 -t 10 -P 10` → **CRASH**

## Root Cause Analysis (Incomplete)

A worker thread gets stuck in the dequeue node's `while (budget > 0)` loop at `src/cake_dequeue.c:238`. The loop cannot terminate because either:

- A doubly-linked list (new_flow, old_flow, or decaying_flow) has become circular due to corrupted next/prev pointers, causing `cake_select_flow()` to always return the same flow
- Flow count fields (`sparse_flow_count`, `bulk_flow_count`) are out of sync with the actual list contents, so the tin selection finds a tin with claimed active flows but empty lists
- The DRR rotation (remove from old_flow list head, append to old_flow list tail) corrupts the list when operating on the only element or on adjacent elements

The crash only occurs with multiple flows because single-flow traffic exercises minimal list operations (one flow stays on new_flow list as SPARSE, gets reclaimed when empty — no DRR rotation needed).

## Files to Review

All source files are in `src/`:

- `osvbng_qos_sched.h` — data structures (`cake_flow_t`, `cake_tin_t`, `cake_host_t`), inline list operations (`cake_flow_list_prepend`, `cake_flow_list_append_tail`, `cake_flow_list_remove`), flow lookup (`cake_flow_lookup`), COBALT inlines, host tracking (`cake_host_lookup`, `cake_quantum_for_flow`)
- `cake_enqueue.c` — enqueue path: owner-thread check, DSCP classification, flow hash + set-associative lookup, flow eviction (`cake_flow_evict`), per-flow ring buffer enqueue, flow state transitions (NONE→SPARSE, SPARSE→BULK, DECAYING→BULK), DRR list insertion, host bulk_flow_count increment
- `cake_dequeue.c` — dequeue path: tin selection by strict priority, `cake_select_flow()` from DRR lists, sparse flow immediate service, bulk flow deficit-based dequeue, DRR rotation (remove + append_tail on deficit exhaustion), flow state transitions (BULK→DECAYING, DECAYING→NONE), `cake_flow_reclaim()` with list removal + ring free + counter decrement + host bulk_flow_count decrement, COBALT AQM integration

## Specific Areas of Concern

### 1. Doubly-Linked List Operations

The three list operations are at `osvbng_qos_sched.h:321-369`. They use head+tail pointers with `~0` as nil sentinel. Edge cases to verify:
- Remove the only element (head == tail == idx)
- Remove the head element
- Remove the tail element
- Append to a single-element list
- Prepend to a single-element list

### 2. Flow State Machine

```
NONE → SPARSE (enqueue: first packet to flow)
SPARSE → BULK (enqueue: second packet queued)
BULK → DECAYING (dequeue: queue drains to empty)
DECAYING → BULK (enqueue: new packet arrives)
DECAYING → NONE (dequeue: reclaimed)
SPARSE → NONE (dequeue: reclaimed after single packet sent)
```

Each transition must: remove from current list, add to new list, update counters. Verify every transition in both `cake_enqueue.c` and `cake_dequeue.c`.

### 3. DRR Rotation in Dequeue

At `cake_dequeue.c:319-327`, when a bulk flow's deficit is exhausted:
```c
cake_flow_list_remove(&tin->old_flow_head, &tin->old_flow_tail, tin->flows, flow_idx);
cake_flow_list_append_tail(&tin->old_flow_head, &tin->old_flow_tail, tin->flows, flow_idx);
```
This removes from old_flow list head and appends to old_flow list tail. If this is the only flow in the list, it removes and re-adds — does this work correctly with head+tail pointer management?

### 4. Tin Selection Loop

At `cake_dequeue.c:240-261`, the tin selection checks `sparse_flow_count + bulk_flow_count > 0` but then `cake_select_flow()` checks the actual list heads. If counts are positive but all three list heads are `~0`, `cake_select_flow()` returns `~0` and the code breaks out — but are there scenarios where this desync occurs?

### 5. cake_flow_reclaim vs cake_flow_evict

Both functions clean up flow state. `cake_flow_reclaim` is called from dequeue, `cake_flow_evict` from enqueue. Verify they both:
- Remove from the correct list (matching the flow's current state)
- Decrement the correct counter
- Decrement host bulk_flow_count when applicable
- Zero the flow struct and reset next/prev to ~0
- Clear the flow_tags entry

### 6. COBALT queue_empty Side Effects

`cake_flow_reclaim` calls `cobalt_queue_empty()` which modifies flow COBALT state (`dropping`, `codel_count`, `drop_next_us`). This runs BEFORE the flow is removed from the list. Could the COBALT state modification affect list iteration?

## Expected Output

For each finding:
1. Exact file:line of the bug
2. Description of the failure mode
3. The fix (code change)
