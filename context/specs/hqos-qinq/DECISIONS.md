# Decisions: hqos-qinq

## Design Revision (Post Phase 5 v1)

After implementation review, the original thread-pinned DRR model was replaced with a lockless per-port aggregate model. The original design pinned all children of an aggregate to one worker thread, which defeats VPP's RSS distribution and creates a single-worker bottleneck for multi-gigabit aggregates.

### Key design changes:
1. **Aggregate scope: per physical/bond port** (was per S-VLAN). All S-VLANs on the port share one aggregate at the port rate.
2. **Lockless atomic token bucket** (was single-owner thread). All workers check and advance the aggregate atomically via CAS. No thread pinning, no handoff overhead for the aggregate.
3. **Auto-attach via interface hierarchy walk** (was explicit attach/detach API). `cake_sched_enable_disable` walks `sup_sw_if_index` up to the physical parent. No attach/detach API needed.
4. **No DRR child list** (was doubly-linked list with draining state). The aggregate has no knowledge of individual children. Fairness comes from per-subscriber rate limits + natural RSS distribution.
5. **No per-thread aggregate bitmaps** (was `active_agg_bitmap`). Workers check the aggregate inline during dequeue, gated by the atomic token bucket.
6. **osvbng config: interface-level** (was subscriber-group or child policy reference). `interfaces.X.qos-policy: aggregate-name` applied once per port.

## Accepted (from Codex Phase 3)

### Lifecycle mutations must run under worker barrier
- **Source:** CODEX
- **Severity:** CRITICAL
- **Resolution:** Still applies. `aggregate_create` and `aggregate_delete` run under worker barrier. The barrier scope is smaller now (no DRR list to protect), but still needed for pool allocation and `agg_index_by_sw_if_index` updates.

### Unified drop helper for aggregate buffer accounting
- **Source:** GEMINI
- **Severity:** CRITICAL
- **Resolution:** Still applies. `cake_agg_discharge()` now uses `__atomic_fetch_sub` instead of plain subtraction. Called on all buffer-free paths.

### Aggregate token bucket burst cap
- **Source:** GEMINI
- **Severity:** HIGH
- **Resolution:** Still applies. Burst cap in the CAS loop: `if (old_time < now_ns) old_time = now_ns;`

## No Longer Applicable

### Replace two-phase dequeue with unified interleaved loop (CODEX)
- **Rationale:** No separate aggregate dequeue phase exists. The aggregate check is inline within the existing per-subscriber dequeue path. No new loop, no cursors, no starvation possible.

### Detach must use draining state (CODEX)
- **Rationale:** No detach API exists. Children auto-clear `aggregate_index` on scheduler disable. No draining state needed.

### Explicit thread placement API (CODEX)
- **Rationale:** No thread pinning. All workers participate via lockless atomics. No placement needed.

### Active children list to skip idle subscribers (GEMINI)
- **Rationale:** No child list exists. The aggregate has no knowledge of children. Workers check the aggregate inline during their existing per-subscriber dequeue loop.

### Worker barrier for attach/detach thread safety (CODEX + GEMINI)
- **Rationale:** No attach/detach API exists. Auto-attach during `cake_sched_enable_disable` (already under barrier for pool allocation). Auto-clear on disable (same).

## Rejected

### Weighted DRR in Phase 1
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Rationale:** No DRR at the aggregate level. Fairness is approximate via per-subscriber rate limits + RSS distribution.

### IPv6 metric consistency
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Rationale:** All counters are u64 and protocol-agnostic. No change needed.

### Aggregate lookup optimization
- **Source:** GEMINI
- **Severity:** LOW
- **Rationale:** `aggregate_index` cached in `cake_sched_t`. No per-packet lookup.
