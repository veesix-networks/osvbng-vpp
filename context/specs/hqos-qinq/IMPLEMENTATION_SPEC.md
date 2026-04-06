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
```

### 4.5 Thread Ownership Model

The aggregate uses the same owner-thread model as child schedulers:

1. Aggregate created with `owner_thread = CAKE_AGG_OWNER_UNSET`
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
2. Go control plane calls attach API
3. Plugin sets `child->owner_thread = aggregate->owner_thread` (forced pin)
4. If packets for this child arrive on worker != W, the existing handoff path redirects them

### 4.6 Dequeue Loop Changes

The existing dequeue node has a single loop over `active_bitmap` (standalone schedulers). With HQoS, the dequeue function has two phases:

**Phase 1: Standalone schedulers (unchanged)**
```
for each si in pt->active_bitmap:
    if scheduler has aggregate_index != ~0: skip (handled in Phase 2)
    [existing CAKE dequeue logic]
```

**Phase 2: Aggregate schedulers**
```
for each ai in pt->active_agg_bitmap:
    cake_aggregate_t *agg = aggregates[ai]
    if now_ns < agg->global_shaper_time_ns: continue (rate-limited)

    DRR round across children:
        child = agg->child_head
        while child != ~0 && budget > 0:
            if child->agg_deficit <= 0:
                child->agg_deficit += agg->quantum

            while child->agg_deficit > 0 && budget > 0:
                if now_ns < child->global_shaper_time_ns: break (child rate-limited)
                if now_ns < agg->global_shaper_time_ns: goto agg_exhausted

                [dequeue one packet from child using existing CAKE logic]
                charge child->agg_deficit
                charge agg->global_shaper_time_ns

            if child exhausted deficit or child has no queued packets:
                rotate child to tail of DRR list

    agg_exhausted:
        if all children empty: deactivate aggregate
```

The critical property: every packet dequeued from a child charges BOTH the child's token bucket (per-subscriber rate) AND the aggregate's token bucket (S-VLAN rate). This enforces both levels simultaneously.

**Fast path (aggregate not congested):** When the aggregate has spare capacity (common case with oversubscription < 1.0), the aggregate token bucket check is a single comparison (`now_ns < agg->global_shaper_time_ns`). The DRR deficit tracking still runs to maintain fairness state, but packets flow through without aggregate-level delay.

**Congested path:** When aggregate bandwidth is saturated, the DRR across children ensures each subscriber gets a fair share of the aggregate capacity, regardless of individual subscriber rates. A subscriber shaped to 1G on a 10G aggregate with 20 active subscribers gets min(1G, 10G/20) = 500M.

### 4.7 Enqueue Path Changes

Minimal changes to the enqueue path:

1. When enqueueing to a child that has `aggregate_index != ~0`, activate the aggregate on the thread's `active_agg_bitmap` (in addition to the existing child activation)
2. The standalone `active_bitmap` activation still happens for the child, but the dequeue Phase 1 loop skips children with aggregates

### 4.8 Aggregate Lifecycle

**Create:** Go control plane calls `osvbng_cake_aggregate_create` with S-VLAN `sw_if_index` and aggregate rate. Returns aggregate index.

**Attach:** After creating a per-subscriber scheduler, Go calls `osvbng_cake_aggregate_attach` with the child's `sw_if_index` and the aggregate's `sw_if_index`. The plugin:
1. Looks up aggregate by S-VLAN `sw_if_index`
2. Sets `child->aggregate_index = agg->agg_index`
3. Pins `child->owner_thread` to aggregate's owner (if aggregate owner is set)
4. Adds child to aggregate's DRR list
5. Initializes `child->agg_deficit = agg->quantum`

**Detach:** When a subscriber session releases, Go calls `osvbng_cake_aggregate_detach` before disabling the child scheduler. The plugin:
1. Removes child from aggregate's DRR list
2. Sets `child->aggregate_index = ~0`
3. Decrements `agg->n_children`
4. If `n_children == 0`, deactivates aggregate on thread bitmap

**Delete:** Go calls `osvbng_cake_aggregate_delete` when the S-VLAN is removed. Must have `n_children == 0` (all subscribers released first).

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

Corresponding dequeue discharge:
```c
if (child->aggregate_index != ~0)
    agg->buffer_usage -= pkt_len;  /* discharged on dequeue or AQM drop */
```

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
| `src/osvbng_qos_sched.c` | Modify | Implement `cake_aggregate_create()`, `cake_aggregate_delete()`, `cake_aggregate_attach()`, `cake_aggregate_detach()`; add aggregate CLI commands; update `cake_sched_enable_disable()` to initialize new `cake_sched_t` fields (`aggregate_index = ~0`, etc.) |
| `src/osvbng_qos_sched.api` | Modify | Add `osvbng_cake_aggregate_create`, `osvbng_cake_aggregate_delete`, `osvbng_cake_aggregate_attach`, `osvbng_cake_aggregate_detach`, `osvbng_cake_aggregate_dump` API messages |
| `src/osvbng_qos_sched_api.c` | Modify | Add API handlers for aggregate messages |

### Phase 2: Dequeue HQoS Loop

| File | Action | Purpose |
|------|--------|---------|
| `src/cake_dequeue.c` | Modify | Add Phase 2 aggregate dequeue loop after existing standalone loop; implement DRR across children gated by aggregate token bucket; skip children with `aggregate_index != ~0` in Phase 1 standalone loop |

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
- Add `cake_aggregate_t` to header
- Extend `cake_sched_t` with aggregate fields
- Extend `cake_main_t` with aggregate pool and lookup table
- Implement create/delete/attach/detach functions
- Add binary API messages and handlers
- Add CLI for create/delete
- Initialize new `cake_sched_t` fields in `cake_sched_enable_disable()`
- **Testable:** Create an aggregate via CLI/API, attach child schedulers, verify data structure integrity via `show cake aggregate`

### Phase 2: Dequeue HQoS Loop
- Add `active_agg_bitmap` to `cake_per_thread_t`
- Modify dequeue node: Phase 1 loop skips children with aggregates
- Add Phase 2 loop: iterate aggregates, DRR across children, dual token-bucket gating
- Verify standalone schedulers (no aggregate) path is unchanged
- **Testable:** Two subscribers on same aggregate, each shaped to 1G, aggregate at 1G. Verify fair 500M/500M split. Single subscriber on 1G aggregate at 100M child rate. Verify 100M not 1G.

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
- Attach two child schedulers, verify DRR list integrity (head/tail, next/prev)
- Detach one child, verify list correctly unlinks without corrupting sibling
- Detach last child, verify `n_children == 0`
- Delete aggregate, verify pool freed and lookup cleared
- Attempt delete with children still attached, verify rejection

### Phase 2: Shaping Correctness
- **Fair share:** 4 subscribers each at 1G child rate, aggregate at 2G. Each should get ~500M under saturation
- **No aggregate bottleneck:** 4 subscribers each at 100M, aggregate at 10G. Each should achieve full 100M (aggregate not the bottleneck)
- **Mixed rates (future weighted DRR):** Initially all get equal share regardless of child rate. Document this as known limitation for Phase 1
- **Single subscriber:** 1 subscriber at 500M, aggregate at 10G. Should achieve 500M (child rate is the bottleneck)
- **Standalone unaffected:** Subscriber with no aggregate should behave identically to pre-HQoS

### Phase 3: Buffer Backpressure
- Aggregate buffer_limit = 1MB, 10 children each trying to queue 500KB. Verify total stays under 1MB via drops
- Verify COBALT `cobalt_queue_full()` signaling on aggregate overflow
- Verify buffer_usage accounting: enqueue charges, dequeue/drop discharges, no drift over time

### Phase 4: Thread Pinning
- 4-worker VPP, subscribers on same S-VLAN aggregate
- Verify first packet to any child claims the aggregate's thread
- Verify subsequent children on different workers are handed off to aggregate's thread
- Verify no cross-thread mutation of aggregate state (single-writer invariant)

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
