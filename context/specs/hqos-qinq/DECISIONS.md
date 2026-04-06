# Decisions: hqos-qinq

## Accepted

### Lifecycle mutations must run under worker barrier to protect DRR list integrity
- **Source:** CODEX
- **Severity:** CRITICAL
- **Resolution:** All aggregate lifecycle operations (create, attach, detach, delete) now run under `vlib_worker_thread_barrier_sync()` / `vlib_worker_thread_barrier_release()`. This pauses all worker threads during the mutation, preventing the dequeue loop from walking the DRR list concurrently. Acceptable cost since these are infrequent control-plane operations.

### Replace two-phase dequeue with unified interleaved loop and persistent cursors
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Removed the two-phase (standalone then aggregate) dequeue structure. Replaced with a single interleaved loop that alternates between standalone and aggregate processing using persistent per-thread cursors (`standalone_cursor`, `agg_cursor`). Each aggregate also maintains a persistent `drr_cursor` so DRR across children does not restart from `child_head` on every node invocation. This prevents standalone schedulers from starving aggregates (or vice versa) and ensures head-of-line fairness within aggregates.

### Detach must use draining state to prevent packets escaping aggregate shaping
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Detach no longer immediately unlinks the child and clears `aggregate_index`. Instead, the child enters a draining state (`agg_draining = 1`): it remains in the aggregate's DRR list, stops accepting new enqueues via the aggregate path, and continues to drain through aggregate shaping. When backlog reaches zero, the dequeue loop completes the detach (removes from DRR list, clears `aggregate_index`, discharges `buffer_usage`). This ensures buffer accounting stays correct and no packets escape aggregate rate control.

### Explicit thread placement API for aggregate load balancing
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** `osvbng_cake_aggregate_create` now accepts an optional `owner_thread` parameter. When set, the aggregate is pinned to that worker from creation (no first-packet CAS race). When `~0` (default), falls back to first-packet CAS. The Go control plane can implement least-loaded placement by tracking per-thread aggregate counts. The spec explicitly documents that one aggregate maps to one worker's capacity as a design constraint, and that operators should distribute aggregates across workers.

### Worker barrier for attach/detach thread safety (duplicate of Codex CRITICAL)
- **Source:** GEMINI
- **Severity:** CRITICAL
- **Resolution:** Already addressed by Codex finding above. Gemini independently identified the same cross-thread migration hazard. Both agree: worker barrier on all lifecycle mutations.

### Unified drop helper for aggregate buffer accounting
- **Source:** GEMINI
- **Severity:** CRITICAL
- **Resolution:** Added `cake_agg_discharge()` helper that all buffer-free paths must call. All five existing CAKE buffer-free paths (dequeue transmit, AQM drop, overflow drop, teardown drain, handoff congestion) must be audited during implementation to ensure they call this helper. Prevents accounting drift where `agg->buffer_usage` permanently overestimates, causing permanent backpressure.

### Active children list to avoid iterating idle subscribers
- **Source:** GEMINI
- **Severity:** HIGH
- **Resolution:** Added `active_child_head`/`active_child_tail`/`n_active_children` to `cake_aggregate_t`. The DRR round iterates the active list only. Children move to the active list on first enqueue and are removed when backlog reaches zero. An aggregate with 1000 attached children but 2 active only visits 2 per dequeue invocation. Satisfies the "CPU cycles matter" first-class requirement.

### Aggregate token bucket burst cap
- **Source:** GEMINI
- **Severity:** HIGH
- **Resolution:** Added burst cap: `if (now_ns > agg->global_shaper_time_ns) agg->global_shaper_time_ns = now_ns;` Prevents unbounded credit accumulation during idle periods that would cause a line-rate burst when traffic resumes. Same pattern as the existing per-subscriber CAKE shaper.

## Rejected

### Weighted DRR in Phase 1
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Rationale:** Equal-quantum DRR is sufficient for Phase 1. The data structures already support per-child quantum, and the spec documents weighted DRR as a future extension (section 4.10). Adding rate-proportional quantum during attach is low-effort but adds a behavioral dimension that needs its own testing. Kept as Phase 2 enhancement.

### IPv6 metric consistency
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Rationale:** All aggregate counters are already `u64` in the spec. Counters are protocol-agnostic (they count all packets regardless of IP version). No separate IPv6 counters needed; the dual-stack requirement is satisfied by the per-subscriber CAKE scheduler which already handles IPv4 and IPv6 identically.

### Aggregate lookup optimization
- **Source:** GEMINI
- **Severity:** LOW
- **Rationale:** Already addressed. The child's `aggregate_index` field caches the aggregate pool index, so the `agg_index_by_sw_if_index` lookup only happens during attach (control plane), not on the per-packet hot path.

### Unsafe cross-thread migration
- **Source:** GEMINI
- **Severity:** CRITICAL
- **Rationale:** Duplicate of Codex CRITICAL finding. Already resolved via worker barrier. Listed under Accepted as a merged finding.
