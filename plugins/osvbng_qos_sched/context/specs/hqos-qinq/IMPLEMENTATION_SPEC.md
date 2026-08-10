# Implementation Spec: Hierarchical QoS (HQoS) for QinQ Deployments

## 1. Overview

Add a per-port aggregate shaper to the existing CAKE plugin. The aggregate gates the total egress throughput of all subscriber schedulers on a physical or bond interface, with fair queuing across subscribers when the port is congested. Child schedulers auto-attach by walking the VPP interface hierarchy. The aggregate token bucket is lockless (atomic operations), allowing all worker threads to participate without thread pinning or handoff. Deployments without aggregates are unaffected.

## 2. References

- IEEE 802.1ad -- Provider Bridges (QinQ)
- IEEE 802.1Q -- VLAN tagging
- RFC 8290 -- The Flow Queue CoDel Packet Scheduler (FQ-CoDel structural reference)
- ITU-T G.984/G.987 -- GPON/XGS-PON (aggregate bandwidth context for PON deployments)
- `context/specs/cake-scheduler/IMPLEMENTATION_SPEC.md` -- existing CAKE design

## 3. Current State

The CAKE scheduler is a flat, single-level design. Each subscriber gets an independent `cake_sched_t` instance with:
- Its own token bucket (`rate_ns_per_byte`, `global_shaper_time_ns`)
- Per-flow DRR + COBALT AQM within the subscriber
- Owner-thread model with CAS claim + handoff for cross-worker packets

There is no concept of a parent scheduler, aggregate rate limiter, or per-port shaping. The `IMPLEMENTATION_SPEC.md` for cake-scheduler explicitly defers hierarchical scheduling:

> "Hierarchical scheduling: No aggregate/per-VLAN/per-OLT-port scheduling. Each subscriber gets an independent scheduler instance. H-QoS across subscribers is a separate feature."

### The Problem

In QinQ deployments, subscribers on a physical port collectively oversubscribe the port's capacity. Without an aggregate shaper:

1. N subscribers each shaped to X Mbps can collectively push N*X into a port with capacity << N*X
2. The downstream equipment or NIC tail-drops excess packets randomly
3. No fair queuing across subscribers at the aggregate level
4. Bursty subscribers steal bandwidth from well-behaved ones
5. AQM benefits of per-subscriber CAKE are negated by uncontrolled aggregate congestion

## 4. Design

### 4.1 Architecture

```
              ┌────────────────────────────────────────────┐
              │           cake_aggregate_t                  │
              │      Physical/bond port shaper              │
              │  Lockless atomic token bucket: 10G/40G      │
              │  All workers participate, no thread pinning  │
              └──────┬───────┬───────┬──────────┬──────────┘
                     │       │       │          │
        ┌────────────┘       │       │          └────────────┐
        ▼                    ▼       ▼                       ▼
  ┌───────────┐      ┌────────────┐ ┌────────────┐   ┌───────────┐
  │S-VLAN 100 │      │S-VLAN 200  │ │S-VLAN 201  │   │S-VLAN N   │
  │C-VLAN subs│      │C-VLAN subs │ │C-VLAN subs │   │C-VLAN subs│
  └──┬────┬───┘      └──┬────┬────┘ └──┬────┬────┘   └──┬────┬───┘
     ▼    ▼              ▼    ▼         ▼    ▼            ▼    ▼
   CAKE  CAKE          CAKE  CAKE    CAKE  CAKE        CAKE  CAKE
   sub1  sub2          sub3  sub4    sub5  sub6        subN  subN+1
```

Two levels:
- **Leaf** (existing): per-subscriber CAKE scheduler. Unchanged internal behavior (per-flow FQ, COBALT AQM, DRR, DiffServ tins, token-bucket shaping). Single-owner thread with handoff.
- **Parent** (new): per-port lockless token bucket. One aggregate per physical or bond interface. All workers check it atomically on every dequeue. No thread pinning, no handoff, no DRR list.

### 4.2 Why Lockless

The per-subscriber CAKE scheduler has rich mutable state (flow ring buffers, COBALT state machines, DRR deficit lists, host tracking tables, set-associative lookups) that requires single-thread ownership. Making it lockless would be impractical.

The aggregate is fundamentally simpler: one token bucket and counters. A single `atomic_fetch_add` on the shaper timestamp per dequeued packet is cheap and correct across all workers. This lets VPP's RSS distribute traffic naturally without funneling an entire port's worth of traffic through one worker.

### 4.3 Aggregate Data Structure

```c
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 rate_bytes_per_sec;
  u64 rate_ns_per_byte;
  u64 global_shaper_time_ns;    /* atomically updated by all workers */

  u32 sw_if_index;              /* physical or bond interface */
  u32 agg_index;

  u32 buffer_limit;
  u32 buffer_usage;             /* atomically updated by all workers */

  u64 shaped_pkts;              /* relaxed atomic */
  u64 shaped_bytes;             /* relaxed atomic */
  u64 backpressure_events;      /* relaxed atomic */
} cake_aggregate_t;
```

All mutable fields accessed from multiple workers use atomic operations:
- `global_shaper_time_ns`: CAS loop for token bucket advancement
- `buffer_usage`: `__atomic_fetch_add` / `__atomic_fetch_sub`
- Stats counters: `__atomic_fetch_add` with `__ATOMIC_RELAXED`

### 4.4 Child Scheduler Extensions

Add to `cake_sched_t`:

```c
u32 aggregate_index;    /* ~0 if standalone (no parent) */
```

No DRR deficit, no linked list pointers, no draining state. The child simply knows its parent aggregate index.

### 4.5 Global State Extensions

Add to `cake_main_t`:

```c
cake_aggregate_t *aggregates;             /* pool */
u32 *agg_index_by_sw_if_index;           /* physical/bond sw_if_index -> pool index */
```

No per-thread aggregate bitmaps needed. Workers check the aggregate inline during dequeue.

### 4.6 Auto-Attach via Interface Hierarchy Walk

When `cake_sched_enable_disable` creates a new per-subscriber scheduler, it walks the VPP interface hierarchy to find a parent aggregate:

```c
u32 current = sw_if_index;
u32 agg_idx = ~0;

while (1)
{
  vnet_sw_interface_t *swif =
    vnet_get_sw_interface (vnet_get_main (), current);
  u32 parent = swif->sup_sw_if_index;

  if (parent == current)
    break;

  if (parent < vec_len (cm->agg_index_by_sw_if_index))
    {
      agg_idx = cm->agg_index_by_sw_if_index[parent];
      if (agg_idx != ~0)
        break;
    }

  current = parent;
}

cs->aggregate_index = agg_idx;
```

This walks C-VLAN sub-interface -> S-VLAN sub-interface -> physical/bond, stopping at the first interface that has an aggregate. No explicit attach API needed. The subscriber has no idea about the aggregate; the plugin discovers it automatically.

On `cake_sched_enable_disable(is_enable=false)`, just clear `cs->aggregate_index`. No detach API needed. The aggregate has no child list to update.

### 4.7 Token Bucket -- Lockless Dequeue Gate

After the per-subscriber scheduler dequeues a packet (existing CAKE logic), the dequeue path checks and advances the aggregate token bucket atomically:

```c
if (cs->aggregate_index != ~0)
{
  cake_aggregate_t *agg =
    pool_elt_at_index (cm->aggregates, cs->aggregate_index);
  u32 adj_len = cake_overhead_adjust (cs, pkt_len);
  u64 cost_ns = (u64) adj_len * agg->rate_ns_per_byte;

  u64 now_ns = (u64) (vlib_time_now (vm) * 1e9);
  u64 old_time, new_time;

  do
    {
      old_time = __atomic_load_n (&agg->global_shaper_time_ns,
                                  __ATOMIC_ACQUIRE);

      /* burst cap: don't accumulate credit beyond now */
      if (old_time < now_ns)
        old_time = now_ns;

      new_time = old_time + cost_ns;

      /* if the aggregate is ahead of now, we're over rate -- drop back */
      if (old_time > now_ns)
        {
          /* aggregate exhausted, stop dequeuing this subscriber */
          return 0;
        }
    }
  while (!__atomic_compare_exchange_n (&agg->global_shaper_time_ns,
                                       &old_time, new_time, 1,
                                       __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE));

  __atomic_fetch_add (&agg->shaped_pkts, 1, __ATOMIC_RELAXED);
  __atomic_fetch_add (&agg->shaped_bytes, adj_len, __ATOMIC_RELAXED);
}
```

When the aggregate is not congested (common case), the CAS succeeds on first try -- one atomic operation per packet. When congested, workers naturally back off because `old_time > now_ns` causes them to stop dequeuing.

### 4.8 Enqueue Backpressure

On the enqueue path, check the aggregate buffer limit:

```c
if (cs->aggregate_index != ~0)
{
  cake_aggregate_t *agg =
    pool_elt_at_index (cm->aggregates, cs->aggregate_index);
  u32 usage = __atomic_load_n (&agg->buffer_usage, __ATOMIC_RELAXED);

  if (usage + pkt_len > agg->buffer_limit)
    {
      cobalt_queue_full (...);
      __atomic_fetch_add (&agg->backpressure_events, 1,
                          __ATOMIC_RELAXED);
      drop;
    }

  __atomic_fetch_add (&agg->buffer_usage, pkt_len, __ATOMIC_RELAXED);
}
```

Discharge on every buffer-free path via `cake_agg_discharge()`:

```c
static_always_inline void
cake_agg_discharge (cake_main_t *cm, cake_sched_t *cs, u32 pkt_len)
{
  if (cs->aggregate_index != ~0)
    {
      cake_aggregate_t *agg =
        pool_elt_at_index (cm->aggregates, cs->aggregate_index);
      __atomic_fetch_sub (&agg->buffer_usage, pkt_len, __ATOMIC_RELAXED);
    }
}
```

### 4.9 Aggregate Lifecycle

**Create:** Control plane calls `osvbng_cake_aggregate_create` with the physical/bond `sw_if_index` and rate. Under worker barrier (infrequent control-plane op). Initializes the token bucket with `global_shaper_time_ns = now`.

**Delete:** Control plane calls `osvbng_cake_aggregate_delete`. Under worker barrier. Any active child schedulers that reference this aggregate will see `aggregate_index` pointing to a freed pool entry -- so delete must first scan schedulers and clear their `aggregate_index` fields.

**No attach/detach API.** Children auto-discover their aggregate during `cake_sched_enable_disable` and auto-clear on disable.

### 4.10 Fairness Under Congestion

Without explicit DRR across children, fairness when the aggregate is congested comes from two mechanisms:

1. **Per-subscriber token bucket.** Each subscriber is individually rate-limited. A subscriber shaped to 100Mbps cannot take more than 100Mbps regardless of aggregate state.

2. **Natural worker distribution.** VPP's RSS distributes packets across workers. When the aggregate token bucket is ahead of `now_ns`, all workers stop dequeuing simultaneously. Since subscribers are spread across workers, no single subscriber gets preferential access to the aggregate token bucket.

This provides approximate fairness. It is not perfect DRR -- a subscriber that happens to be the only one on a lightly-loaded worker gets slightly more CAS wins than subscribers sharing a busy worker. In practice, with 4+ workers and 100+ subscribers, the distribution is fair enough. Perfect per-subscriber aggregate fairness would require the thread-pinned DRR model which defeats VPP's threading.

## 5. Configuration

### 5.1 VPP Plugin Config (Generic)

```
set cake aggregate <physical-or-bond-interface> rate <kbps>
set cake aggregate <physical-or-bond-interface> disable

show cake aggregate [<interface>]
```

### 5.2 Binary API (Generic)

```
osvbng_cake_aggregate_create   -- create per-port aggregate shaper
osvbng_cake_aggregate_delete   -- delete per-port aggregate shaper
osvbng_cake_aggregate_dump     -- query aggregate state and statistics
```

### 5.3 osvbng Go Control Plane Config

```yaml
interfaces:
  TenGigabitEthernet0/0/0:
    qos-policy: gpon-aggregate

qos-policies:
  gpon-aggregate:
    cir: 10000000          # 10G port rate in kbps
    scheduler:
      aggregate: true
```

The Go layer applies `aggregate_create` to the interface's `sw_if_index` at startup. Per-subscriber schedulers auto-discover it via the interface hierarchy.

## 6. File Plan

| File | Action | Purpose |
|------|--------|---------|
| `src/osvbng_qos_sched.h` | Modify | Add `cake_aggregate_t` (lockless fields); add `aggregate_index` to `cake_sched_t`; add `aggregates`, `agg_index_by_sw_if_index` to `cake_main_t`; add `cake_agg_discharge()` inline with atomics |
| `src/osvbng_qos_sched.c` | Modify | Implement `cake_aggregate_create()`, `cake_aggregate_delete()` under worker barrier; add interface hierarchy walk in `cake_sched_enable_disable()`; add aggregate CLI commands |
| `src/osvbng_qos_sched.api` | Modify | Add `osvbng_cake_aggregate_create`, `osvbng_cake_aggregate_delete`, `osvbng_cake_aggregate_dump` API messages |
| `src/osvbng_qos_sched_api.c` | Modify | Add API handlers for aggregate messages |
| `src/cake_dequeue.c` | Modify | Add lockless aggregate token bucket gate after per-subscriber dequeue; add `cake_agg_discharge()` on all buffer-free paths |
| `src/cake_enqueue.c` | Modify | Add aggregate buffer backpressure check with atomic buffer_usage |
| `src/osvbng_qos_sched_error.def` | Modify | Add aggregate-specific error counters |

## 7. Implementation Order

### Phase 1: Data Structures and Aggregate Lifecycle
- Add `cake_aggregate_t` with atomic fields
- Add `aggregate_index` to `cake_sched_t`
- Implement `cake_aggregate_create()` / `cake_aggregate_delete()` under worker barrier
- Add interface hierarchy walk in `cake_sched_enable_disable()` for auto-attach
- Clear `aggregate_index` on scheduler disable
- Add CLI and binary API
- **Testable:** Create aggregate on physical interface, enable subscriber scheduler on sub-interface, verify auto-attach via `show cake scheduler` showing aggregate_index

### Phase 2: Lockless Dequeue Gate
- Add atomic CAS token bucket check after per-subscriber dequeue
- Burst cap: clamp `global_shaper_time_ns` to `now_ns` when behind
- Stop dequeuing when aggregate is ahead of now
- Add `cake_agg_discharge()` on dequeue transmit and AQM drop paths
- **Testable:** 4 subscribers at 500Mbps each on a 1G aggregate. Verify total throughput capped at 1G. Verify single subscriber at 500Mbps on 10G aggregate achieves full 500Mbps.

### Phase 3: Enqueue Backpressure
- Add atomic `buffer_usage` check on enqueue
- Charge on enqueue, discharge on all buffer-free paths (dequeue, AQM drop, overflow drop, teardown)
- **Testable:** Set aggregate buffer_limit to 1MB, flood traffic, verify buffer_usage stays bounded

### Phase 4: Metrics
- Add per-aggregate counters (atomic relaxed)
- Add aggregate state to dump API and CLI
- **Testable:** Verify shaped_pkts/bytes increment, backpressure_events increment on overflow

## 8. Attribute Mappings

### API Parameter Mapping

| API Field | C Field | Type | Description |
|-----------|---------|------|-------------|
| `sw_if_index` | `agg->sw_if_index` | `u32` | Physical or bond interface |
| `rate_bytes_per_sec` | `agg->rate_bytes_per_sec` | `u64` | Aggregate shaping rate |
| `buffer_limit` | `agg->buffer_limit` | `u32` | Max aggregate buffered bytes (0 = auto) |

## 9. Testing

### Shaping Correctness
- 10 subscribers at 1G each on a 5G aggregate: verify total capped at 5G
- 2 subscribers at 100Mbps on a 10G aggregate: each achieves 100Mbps (aggregate not bottleneck)
- Single subscriber at 500Mbps on 1G aggregate: achieves 500Mbps (subscriber rate is bottleneck)
- Standalone subscriber (no aggregate on port): identical behavior to pre-HQoS

### Multi-Worker Verification
- 4-worker VPP, aggregate on physical port
- Verify all workers dequeue traffic (no single-worker bottleneck)
- Verify aggregate rate is correct across workers (atomic CAS convergence)
- Verify no buffer_usage drift under sustained load

### Buffer Backpressure
- Set buffer_limit, verify enqueue drops when exceeded
- Verify buffer_usage accounting: charge on enqueue, discharge on every free path, no drift

### Auto-Attach
- Create aggregate on physical port, then enable subscriber schedulers on sub-interfaces
- Verify subscribers auto-discover aggregate via interface hierarchy
- Disable subscriber scheduler, verify aggregate_index cleared
- Delete aggregate, verify all child schedulers' aggregate_index cleared

## 10. Not In Scope

- **Per-subscriber DRR at the aggregate level.** Fairness is approximate via natural RSS distribution and per-subscriber rate limiting. Perfect per-subscriber aggregate fairness would require thread pinning which defeats VPP's threading model.
- **Per-S-VLAN aggregates.** The aggregate is per physical/bond port. All S-VLANs on the port share it. Per-S-VLAN shaping would require the thread-pinned model or per-S-VLAN atomic token buckets (future extension if needed).
- **Ingress HQoS.** Upload direction aggregate shaping is out of scope.
- **More than two hierarchy levels.** Two levels (port aggregate + subscriber) covers the QinQ use case.
- **Weighted fairness.** All subscribers compete equally for aggregate capacity, subject to their individual rate limits. Rate-proportional weighting is a future extension.
