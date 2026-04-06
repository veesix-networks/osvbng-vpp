# Implementation Spec: Hierarchical QoS (HQoS) for QinQ Deployments

## 1. Overview

Add a two-level hierarchical scheduler to the existing CAKE plugin. A parent aggregate shaper per S-VLAN gates the total egress throughput of all subscriber (C-VLAN) schedulers sharing that outer VLAN, with DRR across children for fairness when the aggregate link is congested. The existing per-subscriber CAKE scheduler becomes the leaf level; deployments without aggregates are unaffected.

## 2. References

- IEEE 802.1ad -- Provider Bridges (QinQ)
- IEEE 802.1Q -- VLAN tagging
- RFC 8290 -- The Flow Queue CoDel Packet Scheduler (FQ-CoDel structural reference)
- Linux `sch_hfsc`, `sch_htb` -- hierarchical schedulers (conceptual reference, not algorithmic)
- ITU-T G.984/G.987 -- GPON/XGS-PON (aggregate bandwidth context for PON deployments)
- `context/specs/cake-scheduler/IMPLEMENTATION_SPEC.md` -- existing CAKE design

## 3. Current State

The CAKE scheduler is a flat, single-level design. Each subscriber gets an independent `cake_sched_t` instance with:
- Its own token bucket (`rate_ns_per_byte`, `global_shaper_time_ns`)
- Per-flow DRR + COBALT AQM within the subscriber
- Owner-thread model with CAS claim + handoff for cross-worker packets

There is no concept of a parent scheduler, aggregate rate limiter, or per-VLAN shaping. The `IMPLEMENTATION_SPEC.md` for cake-scheduler explicitly defers hierarchical scheduling:

> "Hierarchical scheduling: No aggregate/per-VLAN/per-OLT-port scheduling. Each subscriber gets an independent scheduler instance. H-QoS across subscribers is a separate feature."

### The Problem

In QinQ deployments, the S-VLAN (outer VLAN) represents an aggregate link to downstream equipment (OLT, DSLAM, aggregation switch) with a finite physical capacity. Multiple C-VLAN subscribers share this capacity. Without an aggregate shaper:

1. N subscribers each shaped to X Mbps can collectively push N*X into a link with capacity << N*X
2. The downstream equipment tail-drops excess packets randomly
3. No fair queuing across subscribers at the aggregate level
4. Bursty subscribers steal bandwidth from well-behaved ones
5. AQM benefits of per-subscriber CAKE are negated by uncontrolled aggregate congestion

## 4. Design

### 4.1 Architecture

```
                    ┌──────────────────────────────┐
                    │      cake_aggregate_t         │
                    │   S-VLAN aggregate shaper     │
                    │   Token bucket: 1G/10G        │
                    │   DRR across children         │
                    └──────┬───────┬───────┬────────┘
                           │       │       │
              ┌────────────┘       │       └────────────┐
              ▼                    ▼                     ▼
      ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
      │ cake_sched_t  │   │ cake_sched_t  │   │ cake_sched_t  │
      │ C-VLAN sub 1  │   │ C-VLAN sub 2  │   │ C-VLAN sub N  │
      │ CAKE per-flow │   │ CAKE per-flow │   │ CAKE per-flow │
      │ DRR + COBALT  │   │ DRR + COBALT  │   │ DRR + COBALT  │
      └───────────────┘   └───────────────┘   └───────────────┘
```

Two levels:
- **Leaf** (existing): per-subscriber CAKE scheduler. Unchanged internal behavior (per-flow FQ, COBALT AQM, DRR, DiffServ tins, token-bucket shaping).
- **Parent** (new): per-aggregate token bucket + DRR across children. One aggregate per S-VLAN interface. Gates the total output of all attached children.

### 4.2 Aggregate Scheduler Data Structure

```c
#define CAKE_AGG_OWNER_UNSET ((u32) ~0)
#define CAKE_AGG_QUANTUM_DEFAULT 65535

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 rate_bytes_per_sec;
  u64 rate_ns_per_byte;
  u64 global_shaper_time_ns;

  u32 sw_if_index;
  u32 agg_index;
  u32 owner_thread;

  u32 child_head;
  u32 child_tail;
  u32 n_children;
  u32 quantum;

  u32 drr_cursor;           /* persistent DRR position (child sched_index), ~0 = start from head */
  u32 active_child_head;    /* head of backlogged children DRR list */
  u32 active_child_tail;    /* tail of backlogged children DRR list */
  u32 n_active_children;    /* children with queued packets */

  u32 buffer_limit;
  u32 buffer_usage;

  u64 shaped_pkts;
  u64 shaped_bytes;
  u64 backpressure_events;
} cake_aggregate_t;
```

### 4.3 Child Scheduler Extensions

Add to `cake_sched_t`:

```c
u32 aggregate_index;    /* ~0 if standalone (no parent) */
i32 agg_deficit;        /* DRR deficit within aggregate */
u32 agg_next;           /* next sibling in aggregate DRR list */
u32 agg_prev;           /* prev sibling in aggregate DRR list */
u8 agg_draining;        /* 1 = draining: still in DRR list, no new enqueues */
```

### 4.4 Global State Extensions

Add to `cake_main_t`:

```c
cake_aggregate_t *aggregates;             /* pool */
u32 *agg_index_by_sw_if_index;           /* S-VLAN sw_if_index -> pool index */
```

Add to `cake_per_thread_t`:

```c
uword *active_agg_bitmap;    /* aggregates with queued children on this thread */
u32 standalone_cursor;        /* persistent round-robin cursor for standalone schedulers */
u32 agg_cursor;               /* persistent round-robin cursor for aggregates */
```

### 4.5 Thread Ownership Model

The aggregate uses the same owner-thread model as child schedulers:

1. Aggregate created with `owner_thread = CAKE_AGG_OWNER_UNSET` (or explicit thread via `owner_thread` API parameter)
2. When a child attaches to an aggregate, if the aggregate has no owner yet, the child's owner thread becomes the aggregate's owner
3. If the aggregate already has an owner, the child's `owner_thread` is forced to match the aggregate's owner. Packets for that child arriving on other workers are handed off (existing handoff mechanism)
4. If the child has no owner yet (freshly created), the child inherits the aggregate's owner when the aggregate's owner is set (lazy propagation on first packet)

This guarantees all children of an aggregate run on the same worker thread, eliminating cross-thread synchronization for the aggregate token bucket and DRR state.

**First-packet flow for aggregate with unset owner:**
1. Packet arrives at enqueue node on worker W
2. Enqueue looks up child scheduler, finds `owner_thread == CAKE_AGG_OWNER_UNSET`
3. CAS claims child: `owner_thread = W`
4. Child has `aggregate_index != ~0`, looks up aggregate
5. Aggregate `owner_thread == CAKE_AGG_OWNER_UNSET`, CAS claims: `owner_thread = W`
6. Activate aggregate on thread W's `active_agg_bitmap`

**Subsequent child attachment when aggregate already owned by W:**
1. New child created with `owner_thread = CAKE_AGG_OWNER_UNSET`
2. Go control plane calls attach API (under worker barrier)
3. Plugin sets `child->owner_thread = aggregate->owner_thread` (forced pin)
4. If packets for this child arrive on worker != W, the existing handoff path redirects them

**Thread placement and capacity planning:** One aggregate maps to one worker thread. All children of that aggregate are pinned to the same worker. With hundreds of subscribers per S-VLAN, this means one worker bears the full aggregate load. This is a deliberate design constraint: cross-thread aggregate scheduling would require atomic token-bucket operations on every packet, which is unacceptable on the hot path.

The `osvbng_cake_aggregate_create` API accepts an optional `owner_thread` parameter so the Go control plane can implement least-loaded placement by tracking per-thread aggregate counts and choosing the least-loaded worker at aggregate creation time. When `owner_thread` is `~0` (default), ownership falls back to first-packet CAS. Operators should ensure aggregates are distributed across workers, not concentrated on one. The Go control plane is the right place for this policy because it has visibility into the full set of aggregates and their subscriber counts.

### 4.6 Dequeue Loop Changes

The existing dequeue node has a single loop over `active_bitmap` (standalone schedulers). With HQoS, the dequeue function uses a single interleaved loop with persistent round-robin cursors to prevent starvation between standalone and aggregate schedulers.

**Unified dequeue loop with interleaved scheduling:**

The per-thread state maintains a persistent cursor (`pt->dequeue_cursor`) that tracks the current position across all schedulable entities. Each node invocation resumes from where the previous one left off, ensuring fair budget distribution between standalone schedulers and aggregates.

```
budget = VLIB_FRAME_SIZE

/* interleaved iteration: standalone and aggregate schedulers share budget */
/* persistent cursor prevents restart-from-head starvation */

while budget > 0:
    /* alternate between standalone and aggregate processing */
    /* using pt->dequeue_cursor to track position */

    /* standalone: pick next from active_bitmap after cursor */
    si = clib_bitmap_next_set(pt->active_bitmap, pt->standalone_cursor)
    if si != ~0 && scheduler[si].aggregate_index == ~0:
        [existing CAKE dequeue logic for one scheduler, bounded by per-sched limit]
        pt->standalone_cursor = si + 1

    /* aggregate: pick next from active_agg_bitmap after cursor */
    ai = clib_bitmap_next_set(pt->active_agg_bitmap, pt->agg_cursor)
    if ai != ~0:
        cake_aggregate_t *agg = aggregates[ai]
        if now_ns >= agg->global_shaper_time_ns:
            [one DRR round across children, starting from agg->drr_cursor]
        pt->agg_cursor = ai + 1

    /* wrap cursors at end of bitmap */
    if both cursors wrapped: break
```

**Per-aggregate DRR with saved cursor and active children list:**

Each aggregate maintains two child lists: `child_head/child_tail` (all attached children) and `active_child_head/active_child_tail` (only children with queued packets). The DRR round iterates the **active** list only, so aggregates with 1000 attached children but only 2 active ones only visit 2 children per dequeue invocation.

Children move to the active list when their first packet enqueues (on the enqueue path) and are removed when their backlog reaches zero (on the dequeue path). `agg->drr_cursor` points into the active list.

```
child = agg->drr_cursor (or active_child_head if cursor invalid)
children_visited = 0

while children_visited < agg->n_active_children && budget > 0:
    if child->agg_deficit <= 0:
        child->agg_deficit += agg->quantum

    while child->agg_deficit > 0 && budget > 0:
        if now_ns < child->global_shaper_time_ns: break (child rate-limited)
        if now_ns < agg->global_shaper_time_ns: goto agg_exhausted

        [dequeue one packet from child using existing CAKE logic]
        charge child->agg_deficit by adjusted packet length
        charge agg->global_shaper_time_ns

    /* advance to next sibling */
    child = child->agg_next (wrap to child_head if tail)
    children_visited++

agg->drr_cursor = child  /* save position for next invocation */

agg_exhausted:
    if all children empty: deactivate aggregate
```

The critical property: every packet dequeued from a child charges BOTH the child's token bucket (per-subscriber rate) AND the aggregate's token bucket (S-VLAN rate). This enforces both levels simultaneously.

**Aggregate burst cap:** The aggregate token bucket must not accumulate unbounded credit during idle periods. When the aggregate has no active children and becomes active again, stale `global_shaper_time_ns` values in the past would allow a line-rate burst. The same burst cap used by the per-subscriber CAKE shaper applies: `if (now_ns > agg->global_shaper_time_ns) agg->global_shaper_time_ns = now_ns;` This limits accumulated credit to zero (no burst beyond the shaped rate). A small configurable burst allowance could be added later if needed, but zero-burst is the safe default.

**Fast path (aggregate not congested):** When the aggregate has spare capacity (common case with oversubscription < 1.0), the aggregate token bucket check is a single comparison (`now_ns < agg->global_shaper_time_ns`). The DRR deficit tracking still runs to maintain fairness state, but packets flow through without aggregate-level delay.

**Congested path:** When aggregate bandwidth is saturated, the DRR across children ensures each subscriber gets a fair share of the aggregate capacity, regardless of individual subscriber rates. A subscriber shaped to 1G on a 10G aggregate with 20 active subscribers gets min(1G, 10G/20) = 500M.

### 4.7 Enqueue Path Changes

Minimal changes to the enqueue path:

1. When enqueueing to a child that has `aggregate_index != ~0`, activate the aggregate on the thread's `active_agg_bitmap` (in addition to the existing child activation on `active_bitmap`)
2. The unified dequeue loop checks `aggregate_index` per scheduler: children with an aggregate are skipped in standalone iteration and instead processed through their aggregate's DRR round

### 4.8 Aggregate Lifecycle

All lifecycle mutations (create, attach, detach, delete) run under `vlib_worker_thread_barrier_sync()` / `vlib_worker_thread_barrier_release()`. This pauses all worker threads during the mutation, preventing the dequeue loop from walking the DRR list while it is being modified. Lifecycle operations are infrequent control-plane events (subscriber session up/down), so the barrier cost is acceptable.

**Create:** Go control plane calls `osvbng_cake_aggregate_create` with S-VLAN `sw_if_index`, aggregate rate, and optional `owner_thread` (for explicit placement). Returns aggregate index. The API handler acquires the worker barrier, allocates from the aggregate pool, initializes the token bucket, and releases the barrier.

**Attach:** After creating a per-subscriber scheduler, Go calls `osvbng_cake_aggregate_attach` with the child's `sw_if_index` and the aggregate's `sw_if_index`. Under barrier, the plugin:
1. Looks up aggregate by S-VLAN `sw_if_index`
2. Sets `child->aggregate_index = agg->agg_index`
3. Pins `child->owner_thread` to aggregate's owner (if aggregate owner is set)
4. Adds child to aggregate's DRR list (before `drr_cursor` to avoid skipping on first round)
5. Initializes `child->agg_deficit = agg->quantum`
6. Increments `agg->n_children`

**Detach:** When a subscriber session releases, Go calls `osvbng_cake_aggregate_detach`. The child enters a **draining state** rather than being immediately unlinked:

1. Under barrier: set `child->agg_draining = 1` and stop accepting new enqueues to this child via the aggregate path (enqueue treats draining children as standalone for the `active_agg_bitmap` check)
2. The dequeue loop continues to process the draining child through the aggregate's DRR round, charging `agg->buffer_usage` on each dequeue/drop as normal
3. When the child's backlog reaches zero (all queued packets dequeued or dropped), the dequeue loop completes the detach:
   - Removes child from aggregate's DRR list
   - Discharges any remaining `agg->buffer_usage` for this child
   - Sets `child->aggregate_index = ~0`
   - Clears `child->agg_draining`
   - Decrements `agg->n_children`
   - If `agg->drr_cursor` pointed to this child, advances cursor to next sibling
4. If `n_children == 0` after detach completes, deactivates aggregate on thread bitmap

This ensures no packets escape aggregate shaping during teardown and `agg->buffer_usage` accounting remains correct.

**Delete:** Go calls `osvbng_cake_aggregate_delete` when the S-VLAN is removed. Under barrier, the plugin verifies `n_children == 0` (all children must have completed draining first). If children remain (including draining), the delete is rejected.

### 4.9 Aggregate Buffer Accounting

The aggregate tracks `buffer_usage` as the sum of all children's `buffer_usage`. This is not independently maintained; instead, when the dequeue loop processes an aggregate's children, the aggregate's total queued bytes are derived from child state.

The aggregate's `buffer_limit` provides a global cap across all children. If the aggregate's total buffered bytes exceed this limit, the enqueue path applies backpressure: new packets are dropped at the child level using the existing COBALT `cobalt_queue_full()` signal. This prevents a single subscriber from buffering excessively and consuming aggregate buffer space that other subscribers need.

**Enqueue backpressure check (new):**
```c
if (child->aggregate_index != ~0)
{
    cake_aggregate_t *agg = &cm->aggregates[child->aggregate_index];
    if (agg->buffer_usage + pkt_len > agg->buffer_limit)
    {
        /* aggregate buffer full, drop at child */
        cobalt_queue_full(...);
        drop;
    }
    agg->buffer_usage += pkt_len;  /* charged on enqueue */
}
```

All buffer discharge paths (dequeue transmit, AQM drop, overflow drop, teardown drain) must use a unified helper to prevent accounting drift:

```c
static_always_inline void
cake_agg_discharge (cake_main_t *cm, cake_sched_t *cs, u32 pkt_len)
{
  if (cs->aggregate_index != ~0)
    cm->aggregates[cs->aggregate_index].buffer_usage -= pkt_len;
}
```

Every code path that frees a buffer from a child with `aggregate_index != ~0` MUST call this helper. The existing five buffer-free paths in the CAKE plugin (dequeue transmit, AQM drop, overflow drop, subscriber teardown, handoff congestion) must all be audited during implementation.

### 4.10 Weighted Fair Queuing (Future Extension)

The initial implementation uses equal-quantum DRR: all children get the same quantum (aggregate fairness by packet count). A future extension could support weighted DRR where each child's quantum is proportional to its configured rate:

```c
child->agg_quantum = (child->rate_bytes_per_sec * 65535) / agg->rate_bytes_per_sec;
```

This would give a 1G subscriber twice the aggregate bandwidth of a 500M subscriber when the aggregate is congested. The data structures already support per-child quantum; the initial phase uses a fixed value for simplicity.

## 5. Configuration

### 5.1 Go Control Plane Configuration

Aggregate configuration is derived from the S-VLAN topology, not manually configured per subscriber. The Go control plane determines aggregate membership by inspecting the subscriber's interface hierarchy.

```yaml
service-groups:
  residential-qinq:
    qos:
      egress-policy: residential-100m
      scheduler:
        enabled: true
        aggregate:
          enabled: true
          rate: 10000000    # aggregate S-VLAN rate in kbps (10G)
```

When `aggregate.enabled` is true and the subscriber's access interface is a QinQ sub-interface, the Go layer:
1. Identifies the S-VLAN parent interface from VPP's interface hierarchy
2. Creates or looks up the aggregate for that S-VLAN
3. Attaches the subscriber's CAKE scheduler to the aggregate after creation

### 5.2 VPP CLI

```
set cake aggregate <s-vlan-interface> rate <kbps>
set cake aggregate <s-vlan-interface> disable

show cake aggregate [<s-vlan-interface>]
```

## 6. File Plan

### Phase 1: Data Structures and Aggregate Lifecycle

| File | Action | Purpose |
|------|--------|---------|
| `src/osvbng_qos_sched.h` | Modify | Add `cake_aggregate_t` struct; add `aggregate_index`, `agg_deficit`, `agg_next`, `agg_prev` fields to `cake_sched_t`; add `aggregates`, `agg_index_by_sw_if_index` to `cake_main_t`; add `active_agg_bitmap` to `cake_per_thread_t`; add aggregate lifecycle function declarations |
| `src/osvbng_qos_sched.c` | Modify | Implement `cake_aggregate_create()`, `cake_aggregate_delete()`, `cake_aggregate_attach()`, `cake_aggregate_detach()` all under `vlib_worker_thread_barrier_sync()`; detach implements draining state; add aggregate CLI commands; update `cake_sched_enable_disable()` to initialize new `cake_sched_t` fields (`aggregate_index = ~0`, `agg_draining = 0`, etc.) |
| `src/osvbng_qos_sched.api` | Modify | Add `osvbng_cake_aggregate_create`, `osvbng_cake_aggregate_delete`, `osvbng_cake_aggregate_attach`, `osvbng_cake_aggregate_detach`, `osvbng_cake_aggregate_dump` API messages |
| `src/osvbng_qos_sched_api.c` | Modify | Add API handlers for aggregate messages |

### Phase 2: Dequeue HQoS Loop

| File | Action | Purpose |
|------|--------|---------|
| `src/cake_dequeue.c` | Modify | Replace single-phase loop with unified interleaved loop using persistent cursors (`standalone_cursor`, `agg_cursor`); implement per-aggregate DRR with saved `drr_cursor`; skip children with `aggregate_index != ~0` in standalone iteration; handle draining children (complete detach when backlog reaches zero) |

### Phase 3: Enqueue Integration

| File | Action | Purpose |
|------|--------|---------|
| `src/cake_enqueue.c` | Modify | Add aggregate `active_agg_bitmap` activation when enqueueing to a child with an aggregate; add aggregate buffer backpressure check |

### Phase 4: Thread Ownership Pinning

| File | Action | Purpose |
|------|--------|---------|
| `src/cake_enqueue.c` | Modify | Update owner-thread CAS logic: when a child has an aggregate, propagate ownership to aggregate (or inherit from aggregate) |
| `src/cake_handoff.c` | Modify | Verify handoff path works correctly when child is pinned to aggregate's owner thread |

### Phase 5: Metrics and CLI

| File | Action | Purpose |
|------|--------|---------|
| `src/osvbng_qos_sched.c` | Modify | Add `show cake aggregate` CLI with per-aggregate stats (rate, children, shaped packets, backpressure events); add aggregate state to existing `show cake scheduler` output |
| `src/osvbng_qos_sched.api` | Modify | Add `osvbng_cake_aggregate_details` response message for dump API |
| `src/osvbng_qos_sched_api.c` | Modify | Implement aggregate dump handler |
| `src/osvbng_qos_sched_error.def` | Modify | Add aggregate-specific error counters (backpressure drops, aggregate shaped) |

## 7. Implementation Order

### Phase 1: Data Structures and Aggregate Lifecycle
- Add `cake_aggregate_t` to header (including `drr_cursor`)
- Extend `cake_sched_t` with aggregate fields (including `agg_draining`)
- Extend `cake_main_t` with aggregate pool and lookup table
- Extend `cake_per_thread_t` with `active_agg_bitmap`, `standalone_cursor`, `agg_cursor`
- Implement create/delete/attach/detach under `vlib_worker_thread_barrier_sync()`
- Detach enters draining state; completion deferred to dequeue loop
- `osvbng_cake_aggregate_create` accepts optional `owner_thread` for explicit placement
- Add binary API messages and handlers
- Add CLI for create/delete
- Initialize new `cake_sched_t` fields in `cake_sched_enable_disable()`
- **Testable:** Create an aggregate via CLI/API, attach child schedulers, verify data structure integrity via `show cake aggregate`. Detach child, verify it enters draining state. Delete aggregate with active children, verify rejection.

### Phase 2: Dequeue HQoS Loop
- Replace single-phase loop with unified interleaved loop using persistent cursors
- Standalone iteration skips children with `aggregate_index != ~0`
- Aggregate iteration uses per-aggregate `drr_cursor` for fairness across invocations
- Draining children: complete detach when backlog reaches zero (remove from DRR list, clear `aggregate_index`, discharge `buffer_usage`)
- Verify standalone schedulers (no aggregate) path is unchanged
- **Testable:** Two subscribers on same aggregate, each shaped to 1G, aggregate at 1G. Verify fair 500M/500M split. Single subscriber on 1G aggregate at 100M child rate. Verify 100M not 1G. Detach a child with queued packets, verify packets drain through aggregate shaping before detach completes.

### Phase 3: Enqueue Integration
- Activate aggregate on `active_agg_bitmap` when child receives first packet
- Add aggregate buffer backpressure check on enqueue
- Charge/discharge `agg->buffer_usage` on enqueue/dequeue/drop
- **Testable:** Verify aggregate activates when first child enqueues. Verify aggregate buffer limit prevents single child from consuming all buffer space.

### Phase 4: Thread Ownership Pinning
- Update CAS logic in enqueue: propagate owner between child and aggregate
- Force child `owner_thread` on attach when aggregate already has an owner
- Verify handoff works for children pinned to non-local threads
- **Testable:** Multi-worker VPP, subscribers on same aggregate arriving on different workers. Verify all children converge to same owner thread via handoff.

### Phase 5: Metrics and CLI
- Add per-aggregate counters: shaped packets/bytes, backpressure events, child count
- Extend `show cake aggregate` with rate utilization and per-child summary
- Add aggregate details to dump API response
- Add error counters to error.def
- **Testable:** Run traffic through aggregate, verify counters increment correctly. Dump via API, verify all fields populated.

## 8. Attribute Mappings

### API Parameter Mapping

| API Field | C Field | Type | Description |
|-----------|---------|------|-------------|
| `sw_if_index` | `agg->sw_if_index` | `u32` | S-VLAN interface |
| `rate_bytes_per_sec` | `agg->rate_bytes_per_sec` | `u64` | Aggregate shaping rate |
| `buffer_limit` | `agg->buffer_limit` | `u32` | Max aggregate buffered bytes (0 = auto) |
| `quantum` | `agg->quantum` | `u32` | DRR quantum per child (0 = default 65535) |
| `owner_thread` | `agg->owner_thread` | `u32` | Explicit thread placement (~0 = first-packet CAS) |

### Go Config to API Mapping

| Config Path | API | Field |
|-------------|-----|-------|
| `scheduler.aggregate.enabled` | `osvbng_cake_aggregate_create` | triggers create |
| `scheduler.aggregate.rate` | `osvbng_cake_aggregate_create` | `rate_bytes_per_sec = rate * 1000 / 8` |

### Aggregate to Child Relationship

| Aggregate Field | Child Field | Relationship |
|-----------------|-------------|--------------|
| `agg->owner_thread` | `child->owner_thread` | Child pinned to aggregate's thread |
| `agg->agg_index` | `child->aggregate_index` | Child points to parent |
| `agg->child_head/tail` | `child->agg_next/prev` | Doubly-linked DRR list |
| `agg->quantum` | `child->agg_deficit` | Per-child DRR deficit, replenished from `agg->quantum` |

## 9. Testing

### Phase 1: Lifecycle
- Create aggregate on S-VLAN interface, verify pool allocation and lookup table
- Create aggregate with explicit `owner_thread`, verify thread assignment
- Attach two child schedulers, verify DRR list integrity (head/tail, next/prev)
- Verify all lifecycle ops acquire/release worker barrier
- Detach one child, verify it enters draining state (still in DRR list, `agg_draining = 1`)
- Verify draining child completes detach when backlog reaches zero
- Detach last child, verify `n_children == 0` after drain completes
- Delete aggregate, verify pool freed and lookup cleared
- Attempt delete with children still attached (including draining), verify rejection

### Phase 2: Shaping Correctness
- **Fair share:** 4 subscribers each at 1G child rate, aggregate at 2G. Each should get ~500M under saturation
- **No aggregate bottleneck:** 4 subscribers each at 100M, aggregate at 10G. Each should achieve full 100M (aggregate not the bottleneck)
- **Mixed rates (future weighted DRR):** Initially all get equal share regardless of child rate. Document this as known limitation for Phase 1
- **Single subscriber:** 1 subscriber at 500M, aggregate at 10G. Should achieve 500M (child rate is the bottleneck)
- **Standalone unaffected:** Subscriber with no aggregate should behave identically to pre-HQoS
- **No starvation:** Mix of standalone and aggregate schedulers on same thread. Both get fair budget share over multiple dequeue invocations (persistent cursors prevent restart-from-head bias)
- **DRR cursor persistence:** Aggregate with 10 children, dequeue budget exhausted mid-round. Next invocation resumes from saved cursor, not from child_head
- **Draining child shaping:** Detach a child with 1000 queued packets. All 1000 packets must drain through aggregate shaping (not escape as standalone)

### Phase 3: Buffer Backpressure
- Aggregate buffer_limit = 1MB, 10 children each trying to queue 500KB. Verify total stays under 1MB via drops
- Verify COBALT `cobalt_queue_full()` signaling on aggregate overflow
- Verify buffer_usage accounting: enqueue charges, dequeue/drop discharges, no drift over time

### Phase 4: Thread Pinning
- 4-worker VPP, subscribers on same S-VLAN aggregate
- Verify first packet to any child claims the aggregate's thread (when no explicit `owner_thread`)
- Verify explicit `owner_thread` placement: aggregate created with thread 2, all children pinned to thread 2
- Verify subsequent children on different workers are handed off to aggregate's thread
- Verify no cross-thread mutation of aggregate state (single-writer invariant)
- Verify Go-side least-loaded placement: create 4 aggregates, verify they distribute across workers when using explicit thread IDs

### Phase 5: Metrics
- Verify `shaped_pkts` and `shaped_bytes` increment on every dequeued packet through an aggregate
- Verify `backpressure_events` increments on aggregate buffer overflow drops
- Verify dump API returns correct values for all aggregate fields
- Verify aggregate appears in `show cake aggregate` output with correct child count

## 10. Not In Scope

- **Ingress HQoS:** Upload direction aggregate shaping. The CPE controls upload bufferbloat; aggregate ingress policing is a separate feature.
- **More than two hierarchy levels:** No per-OLT, per-chassis, or multi-tier scheduling. Two levels (aggregate + subscriber) covers the QinQ use case.
- **Weighted DRR in Phase 1:** Initial implementation uses equal quantum for all children. Per-child quantum proportional to configured rate is a future extension (data structures already support it).
- **AQM at aggregate level:** No COBALT or CoDel on the aggregate itself. The aggregate is a pure token-bucket + DRR scheduler. Per-subscriber AQM at the leaf level is sufficient.
- **Automatic topology discovery:** The Go control plane must explicitly identify S-VLAN parent interfaces. No automatic detection of QinQ topology from VPP interface state.
- **GPON/XGS-PON OLT-port aggregates:** Same mechanism applies conceptually, but OLT-port aggregation has different topology discovery (not VLAN-based). Out of scope for this spec.
- **Cross-node aggregates:** All children and their aggregate must be on the same VPP instance. No distributed HQoS across HA peers.
