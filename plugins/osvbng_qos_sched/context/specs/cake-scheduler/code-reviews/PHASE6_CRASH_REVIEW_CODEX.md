# Phase 6 Crash Review — Codex

**Date:** 2026-03-21
**Scope reviewed:** `src/osvbng_qos_sched.h`, `src/cake_enqueue.c`, `src/cake_dequeue.c`

## Conclusion

I did **not** find a direct doubly-linked-list corruption bug in the reviewed list helpers or their enqueue/dequeue call sites. The helpers in `src/osvbng_qos_sched.h:489-538` handle singleton/head/tail cases correctly.

The crash is instead caused by a **flow-state/accounting bug**:

1. Per-host `bulk_flow_count` is incremented every time a flow enters `BULK`.
2. It is **not decremented** on the normal `BULK -> DECAYING` path, and it is also not decremented when a `BULK` flow is evicted.
3. `cake_quantum_for_flow()` then uses that leaked count as an **unchecked index** into `cake_quantum_div[]`.
4. Once the leaked host count grows past `CAKE_QUEUES` (1024), the code reads past the end of `cake_quantum_div[]`. If that read yields `0`, the dequeue node reaches a true non-progressing loop:
   - `src/cake_dequeue.c:302-303` adds zero quantum
   - `src/cake_dequeue.c:345-353` rotates the flow without sending a packet
   - `budget` never decreases, so `src/cake_dequeue.c:238` spins forever

This matches the observed symptom: single-flow traffic is stable, while 10 parallel flows create repeated `BULK <-> DECAYING` churn and drive the leaked host counter upward until the dequeue loop deadlocks.

## Findings

### 1. Missing host bulk-count decrement on `BULK -> DECAYING`

- **Location:** `src/cake_dequeue.c:309`
- **Failure mode:** The dequeue path decrements `tin->bulk_flow_count` when a bulk flow drains, but it never decrements `tin->hosts[flow->dst_host_idx].bulk_flow_count`. The enqueue path increments that host counter on both `SPARSE -> BULK` and `DECAYING -> BULK` (`src/cake_enqueue.c:292-305`), so the host count ratchets upward every time a flow drains and later refills. Under multi-flow TCP this is enough to poison `cake_quantum_for_flow()`.
- **Fix:** Decrement the host bulk-flow count at the point where the flow leaves `BULK`.

```c
/* src/cake_dequeue.c */
if (flow->flow_state == CAKE_FLOW_BULK)
  {
    if (flow->dst_host_idx < CAKE_HOSTS &&
        tin->hosts[flow->dst_host_idx].bulk_flow_count > 0)
      tin->hosts[flow->dst_host_idx].bulk_flow_count--;

    flow->flow_state = CAKE_FLOW_DECAYING;
    cake_flow_list_remove (&tin->old_flow_head, &tin->old_flow_tail,
                           tin->flows, flow_idx);
    cake_flow_list_append_tail (&tin->decaying_flow_head,
                                &tin->decaying_flow_tail,
                                tin->flows, flow_idx);
    tin->bulk_flow_count--;
  }
```

### 2. Missing host bulk-count decrement in `cake_flow_evict()` for `BULK` flows

- **Location:** `src/cake_enqueue.c:66`
- **Failure mode:** The enqueue eviction path removes a `BULK` flow from `old_flow` and decrements `tin->bulk_flow_count`, but it does not decrement the per-host `bulk_flow_count`. Any eviction of a bulk flow therefore leaks the same host counter and accelerates the deadlock path above.
- **Fix:** Mirror the host counter decrement in the `CAKE_FLOW_BULK` branch of `cake_flow_evict()`.

```c
/* src/cake_enqueue.c */
else if (ef->flow_state == CAKE_FLOW_BULK)
  {
    cake_flow_list_remove (&tin->old_flow_head, &tin->old_flow_tail,
                           tin->flows, slot);
    tin->bulk_flow_count--;
    if (ef->dst_host_idx < CAKE_HOSTS &&
        tin->hosts[ef->dst_host_idx].bulk_flow_count > 0)
      tin->hosts[ef->dst_host_idx].bulk_flow_count--;
  }
```

### 3. `cake_quantum_for_flow()` trusts a leaked host count as an array index

- **Location:** `src/osvbng_qos_sched.h:299`
- **Failure mode:** `cake_quantum_div` is sized for indices `0..CAKE_QUEUES` (`src/osvbng_qos_sched.h:73`, `src/osvbng_qos_sched.c:538-540`). `cake_quantum_for_flow()` indexes it with `tin->hosts[f->dst_host_idx].bulk_flow_count` without any clamp. Once the leaked count from Findings 1 and 2 exceeds 1024, this becomes an out-of-bounds read. If the read returns `0`, the dequeue node enters a true infinite loop at `src/cake_dequeue.c:238`, because DRR rotation keeps moving flows without ever restoring positive deficit.
- **Fix:** Clamp the host load before indexing and guarantee a minimum quantum of 1 as a hardening guard.

```c
/* src/osvbng_qos_sched.h */
static_always_inline u32
cake_quantum_for_flow (cake_tin_t *tin, cake_flow_t *f)
{
  u16 host_load = 1;
  if (f->dst_host_idx < CAKE_HOSTS)
    {
      u16 hl = tin->hosts[f->dst_host_idx].bulk_flow_count;
      if (hl > CAKE_QUEUES)
        hl = CAKE_QUEUES;
      if (hl > host_load)
        host_load = hl;
    }

  u32 quantum = (tin->quantum * cake_quantum_div[host_load]) >> 16;
  return quantum ? quantum : 1;
}
```

### 4. Tin activity check is inconsistent with flow selection

- **Location:** `src/cake_dequeue.c:244` and `src/cake_dequeue.c:81`
- **Failure mode:** Tin selection considers only `sparse_flow_count + bulk_flow_count`, but `cake_select_flow()` can still return `decaying_flow_head`. A tin with only decaying flows is treated as inactive and the scheduler is deactivated before those flows are reclaimed. This does not create the worker deadlock, but it does strand decaying flows, retain `flow_tags[]`, and increase set pressure.
- **Fix:** Make the tin activity predicate consistent with the selector. The minimal fix is to treat a non-empty decaying list as active.

```c
/* src/cake_dequeue.c */
if (candidate->sparse_flow_count + candidate->bulk_flow_count > 0 ||
    candidate->decaying_flow_head != ~0)
  {
    tin = candidate;
    break;
  }
```

## Area-By-Area Verdict

### 1. Doubly-Linked List Operations

- **Verdict:** No bug found.
- `cake_flow_list_prepend()`, `cake_flow_list_append_tail()`, and `cake_flow_list_remove()` in `src/osvbng_qos_sched.h:489-538` are correct for:
  - removing the only element
  - removing head/tail
  - append/prepend on singleton lists
- I do not see a direct path in the reviewed code that creates a cycle from these helpers under the single-owner-thread model.

### 2. Flow State Machine

- **Verdict:** Bug found.
- The `BULK -> DECAYING` transition leaks the per-host bulk-flow count (`src/cake_dequeue.c:309`).
- This is the main logic bug behind the deadlock.

### 3. DRR Rotation in Dequeue

- **Verdict:** No standalone list bug found.
- The `remove + append_tail` rotation at `src/cake_dequeue.c:348-352` is correct even for a one-element list.
- This loop becomes non-terminating only after Finding 3 allows `cake_quantum_for_flow()` to return zero/garbage.

### 4. Tin Selection Loop

- **Verdict:** Bug found.
- The activity predicate and selector disagree about whether decaying flows count as schedulable (`src/cake_dequeue.c:244` vs `src/cake_dequeue.c:81`).
- This is not the root cause of the worker deadlock, but it is a real state/list lifetime bug.

### 5. `cake_flow_reclaim()` vs `cake_flow_evict()`

- **Verdict:** Bug found.
- `cake_flow_evict()` is not symmetric with `cake_flow_reclaim()` for `BULK` flows because it leaks the per-host `bulk_flow_count` (`src/cake_enqueue.c:66`).
- This contributes to the same deadlock path as Finding 1.

### 6. COBALT `queue_empty` Side Effects

- **Verdict:** No bug found.
- `cobalt_queue_empty()` in `src/osvbng_qos_sched.h:348-369` mutates only COBALT state (`dropping`, `codel_count`, `drop_next_us`, `blue_timer_us`, `rec_inv_sqrt`).
- It does not touch `next`, `prev`, list heads, list tails, or flow state, so it is not the source of the list/list-iteration failure.

## Bottom Line

The reviewed code does **not** support the “doubly-linked-list helper corrupts itself” hypothesis. The actual deadlock comes from:

1. leaking per-host bulk-flow counts on `BULK` exit,
2. using that leaked count as an unchecked quantum-table index, and
3. letting DRR rotation continue even when the computed quantum is zero.

Fix Findings 1-3 together. Finding 4 should also be fixed, but it is a cleanup/lifetime bug rather than the worker-deadlock trigger.
