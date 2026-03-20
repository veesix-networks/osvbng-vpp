# QoS: Full Ingress/Egress QoS

**What:** Overhaul per-subscriber QoS from minimal policer-only to full pipeline: configurable algorithms, dynamic ad-hoc rates, DSCP marking, live policy updates, show/oper commands, Prometheus metrics, and future CAKE-equivalent scheduling.

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Spec Draft | **Complete** |
| Phase 2 | Spec Refinement (Gemini) | **Complete** |
| Phase 3 | Spec Critique (Codex) | **Complete** |
| Phase 4 | Spec Finalization | **Complete** |
| Phase 5 | Implementation | Not started |
| Phase 6 | Code Review | Not started |

## Key Decisions (Phase 4)

- **Per-session QoS state:** `SubscriberPolicerState` in VPP southbound tracks policy name, policer index, applied rates, and ad-hoc flag per subscriber — enables bulk update queries and show commands without modifying session models
- **No PolicerAdd migration:** Keep `PolicerAddDel` (already returns `PolicerIndex`), avoid mixed-mode lifecycle complexity
- **Concurrency:** All policer ops serialize through `policerMu`; bulk update holds lock for entire snapshot+update loop
- **Failure model:** Best-effort bulk updates with logging; partial application visible via `show qos.subscriber`
- **RFC validation:** PIR >= CIR (RFC 2698), CBS/EBS > 0 (RFC 2697), burst >= MTU warnings enforced in conf handler

## Key Context Files

- [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md) — Final spec
- [DECISIONS.md](DECISIONS.md) — Design decisions from Gemini/Codex reviews
- [spec-reviews/CODEX.md](spec-reviews/CODEX.md) — Codex critique (all items accepted)

## Codebase Entry Points

- `pkg/config/qos/qos.go` — Policy config struct
- `pkg/southbound/vpp/qos.go` — VPP policer integration
- `pkg/config/servicegroup/servicegroup.go` — Service group QoS block
- `pkg/svcgroup/resolver.go` — Service group resolution with AAA overrides
- `internal/subscriber/component.go` — Session activation/release QoS lifecycle
- `pkg/aaa/attributes.go` — QoS AAA attribute constants
- `pkg/deps/deps.go` — Dependency injection (ConfDeps needs Southbound for bulk updates)
- `pkg/vpp/binapi/policer/` — VPP policer API bindings
- `pkg/vpp/binapi/qos/` — VPP QoS marking API bindings

## Prompt to Resume

> Read `context/PROCESS.md` for the workflow overview and `context/SUMMARY.md` for project state. The finalized spec is at `context/specs/full-qos/IMPLEMENTATION_SPEC.md` with decisions in `context/specs/full-qos/DECISIONS.md`. Execute Phase 5 (implementation) starting with Phase 1 (Enhanced Policing + Ad-hoc Rates).
