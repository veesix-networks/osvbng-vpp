# Decisions: qos/full-qos

## Accepted

### No durable per-session QoS identity
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Added a `PolicerEntry` struct in the VPP southbound that tracks per-subscriber per-direction: policy name (or empty for ad-hoc), applied CIR/EIR, policer index, and policer name. The existing `policerNames map[uint32][2]string` becomes `policerState map[uint32]*SubscriberPolicerState`. This is the source of truth for "which subscribers use policy X" — the conf handler queries it for bulk updates, the show handler queries it for per-subscriber display. No changes to `pkg/models/session.go` needed; QoS state lives in the VPP adapter alongside the policer lifecycle it manages.

### Live policy updates race with session activation/release
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** All policer operations (`ApplyQoS`, `UpdateQoS`, `RemoveQoS`, and the bulk update loop) serialize through a single `policerMu` mutex. The conf handler's bulk update takes the lock for the entire snapshot-and-update loop: snapshot the set of subscribers using the target policy, then update each one, all under the lock. `ApplyQoS` and `RemoveQoS` already hold `policerMu`. This prevents a session from activating with stale rates while a policy update is in progress. The lock scope is bounded — only VPP API calls for the affected subscribers, not the entire config commit.

### Mid-bulk PolicerUpdate failure leaves partial state
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Best-effort with visibility. The conf handler will: (1) attempt all PolicerUpdate calls, (2) track successes and failures, (3) log each failure with subscriber identity and error, (4) return success if at least one update succeeded (the policy template itself is still validly changed), (5) return error only if ALL updates failed (systemic VPP issue). Partial application is visible via `show qos.subscriber` which reads the actual policer state from VPP. Rollback of the conf handler restores the policy template but does NOT reverse already-applied VPP updates — those subscribers are on the new rate, which is the safer direction (they got the intended change). This matches the standard BNG model where bulk operations are best-effort with monitoring.

### PolicerAdd migration unnecessary — keep PolicerAddDel
- **Source:** CODEX
- **Severity:** MEDIUM
- **Resolution:** Dropped the PolicerAddDel → PolicerAdd migration from Phase 1. `PolicerAddDelReply` already returns `PolicerIndex` — the current code just ignores it. The fix is to record the returned index from the existing API call. This avoids mixed-mode lifecycle complexity (PolicerAdd for creation but PolicerDel for deletion, while still using name-based PolicerInput/PolicerOutput for binding). The spec's file plan for `pkg/southbound/vpp/qos.go` is updated accordingly.

## Accepted from Gemini Refinement

### RFC conformance validation requirements
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Resolution:** Added RFC conformance requirements to section 4.3: PIR >= CIR for RFC 2698, burst sizes >= MTU for all types, CBS or EBS > 0 for RFC 2697. These become validation rules in the conf handler.

### DSCP marking pipeline clarification
- **Source:** GEMINI
- **Severity:** MEDIUM
- **Resolution:** Section 4.5 updated with explicit BNG implementation logic: which interface direction gets Record vs Mark, how map_id binding works, and that only QOS_SOURCE_IP is in scope. Burst size defaults updated from `cir * 1000 / 8` to 100ms burst (`cir * 1000 / 8 * 0.1`).

### Reference list corrections
- **Source:** GEMINI
- **Severity:** LOW
- **Resolution:** RFC 4115 title corrected, RFC 2474 and RFC 2597 added as relevant DiffServ references. CAKE reference removed from RFC list (not an RFC).
