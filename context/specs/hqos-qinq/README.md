# QoS: Hierarchical QoS (HQoS) for QinQ Deployments

**What:** Per-S-VLAN aggregate shaper that gates the total egress throughput of all subscriber (C-VLAN) CAKE schedulers sharing an outer VLAN, with DRR across children for fair bandwidth distribution when the aggregate link is congested.

**Issue:** [#1](https://github.com/veesix-networks/osvbng-vpp-plugin-qos/issues/1)

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Spec Draft | **Complete** |
| Phase 2 | Spec Refinement (Gemini) | Not started |
| Phase 3 | Spec Critique (Codex) | **Complete** |
| Phase 4 | Spec Finalization | Not started |
| Phase 5 | Implementation | Not started |
| Phase 6 | Code Review | Not started |

## Key Context Files

- [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md) -- Technical specification
- [spec-reviews/CODEX.md](spec-reviews/CODEX.md) -- Phase 3 architectural critique
- [../cake-scheduler/IMPLEMENTATION_SPEC.md](../cake-scheduler/IMPLEMENTATION_SPEC.md) -- Parent CAKE scheduler spec (leaf level)
- [../full-qos/IMPLEMENTATION_SPEC.md](../full-qos/IMPLEMENTATION_SPEC.md) -- Full QoS pipeline spec

## Codebase Entry Points

### Plugin source (`src/`)

- `src/osvbng_qos_sched.h` -- Core data structures (to be extended with `cake_aggregate_t`)
- `src/cake_dequeue.c` -- Dequeue node (to be extended with aggregate DRR loop)
- `src/cake_enqueue.c` -- Enqueue node (to be extended with aggregate activation + buffer backpressure)
- `src/osvbng_qos_sched.c` -- Plugin core (to be extended with aggregate lifecycle)
- `src/osvbng_qos_sched.api` -- Binary API (to be extended with aggregate messages)

### Key existing data structures

- `cake_sched_t` -- Per-subscriber scheduler (becomes leaf level)
- `cake_main_t` -- Global plugin state (extended with aggregate pool)
- `cake_per_thread_t` -- Per-worker state (extended with `active_agg_bitmap`)

## Phase 2 Prompt (Gemini -- Spec Refinement)

> Read `context/PROCESS.md` for the workflow overview.
>
> Execute Phase 2 (spec refinement) for `context/specs/hqos-qinq/`.
>
> The spec describes a two-level hierarchical scheduler extension to an existing VPP CAKE plugin. A parent aggregate shaper per S-VLAN gates egress throughput of all subscriber (C-VLAN) schedulers sharing that outer VLAN. DRR across children for fairness.
>
> **Key areas to focus on:**
> - **DRR correctness:** Is deficit round robin correctly specified for the aggregate level? Does the quantum/deficit handling correctly ensure fairness across children with varying packet sizes and rates?
> - **Token bucket interaction:** Two token buckets in series (child + aggregate). Are there edge cases where the interaction produces unexpected behavior (e.g., aggregate token bucket starving a child that has tokens, or a child draining tokens faster than expected)?
> - **Thread safety:** The spec pins all children to the aggregate's owner thread. Is this sufficient? Are there race conditions during attach/detach while traffic is flowing?
> - **Buffer accounting:** Aggregate buffer_usage is maintained via charge/discharge on enqueue/dequeue. Can this drift over time? What happens if a child is forcibly torn down with packets queued?
> - **Fairness under asymmetric load:** If only 2 of 20 children are active, do they correctly get up to aggregate_rate/2 each? Does DRR correctly handle idle children without wasting scheduling rounds?

## Phase 3 Prompt (Codex -- Spec Critique)

> Read `context/PROCESS.md` for the workflow overview.
>
> Execute Phase 3 (spec critique) for `context/specs/hqos-qinq/`.
>
> The spec extends the existing CAKE VPP plugin (`src/`) with a two-level HQoS aggregate scheduler. The existing codebase has per-subscriber CAKE scheduling working. This spec adds per-S-VLAN aggregate shaping on top.
>
> **Key areas to focus on:**
> - **Dequeue loop structure:** The spec adds a second dequeue phase for aggregates. How does this interact with the existing budget management (`VLIB_FRAME_SIZE`)? Can aggregate processing starve standalone schedulers or vice versa?
> - **Owner-thread pinning:** All children of an aggregate are forced to one worker thread. With hundreds of subscribers per S-VLAN, does this create a thread imbalance problem? What if multiple aggregates pin to the same thread?
> - **DRR list mutation during dequeue:** Attach/detach modify the aggregate's child DRR list. If these happen concurrently with the dequeue loop (even on the same thread via API call), is the linked list safe?
> - **Memory overhead:** One `cake_aggregate_t` per S-VLAN. With thousands of S-VLANs, what is the memory impact? Is pool allocation appropriate?
> - **Buffer accounting races:** `agg->buffer_usage` is modified on both enqueue and dequeue. Even with single-thread ownership, are there paths where enqueue and dequeue interleave (e.g., enqueue inline within dequeue's re-injection)?
> - **Aggregate teardown with packets in flight:** What happens if `aggregate_delete` is called while children still have queued packets? The spec requires `n_children == 0`, but what about the timing between detach and drain?

## Prompt to Resume

> Read `context/SUMMARY.md` for project state, then `context/specs/hqos-qinq/README.md` for current status. Phases 1 and 3 are complete. Next: optionally send to Gemini (Phase 2), then finalize the spec in Phase 4 using `spec-reviews/CODEX.md` and any Gemini review artifact.
