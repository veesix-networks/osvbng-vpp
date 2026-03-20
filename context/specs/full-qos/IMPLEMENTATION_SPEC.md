# Implementation Spec: Full QoS — Ingress/Egress Policing, Marking, Dynamic Rates, and Scheduling

## 1. Overview

Overhaul the existing per-subscriber QoS system from a minimal policer-only implementation into a full-featured QoS pipeline supporting: configurable policer algorithms, dynamic rate changes (via AAA ad-hoc rates and future CoA), DSCP recording/marking via VPP's QoS APIs, per-subscriber policer statistics with Prometheus export, show/oper commands, and a conf handler for live policy management. A future phase introduces CAKE-equivalent per-subscriber scheduling via a custom VPP plugin to address bufferbloat.

## 2. References

- RFC 2697 — Single Rate Three Color Marker (srTCM)
- RFC 2698 — Two Rate Three Color Marker (trTCM)
- RFC 4115 — A Differentiated Service Two-Rate, Three-Color Marker
- RFC 2474 — Definition of the Differentiated Services Field (DS Field)
- RFC 2475 — An Architecture for Differentiated Services
- RFC 2597 — Assured Forwarding PHB Group
- RFC 8290 — The Flow Queue CoDel Packet Scheduler and Active Queue Management Algorithm
- VPP policer API v3.0.0 (`policer.api.json`)
- VPP QoS API v1.1.1 (`qos.api.json`)

## 3. Current State

The existing QoS system (v0.2.0) provides:

- **Config:** Named policies under `qos-policies` with CIR/EIR/CBS/EBS and 3-color actions (`pkg/config/qos/qos.go`)
- **Service group binding:** `ingress-policy` / `egress-policy` names in service group QoS block (`pkg/config/servicegroup/servicegroup.go`)
- **VPP integration:** Per-subscriber VPP policers created at session activation, removed at release (`pkg/southbound/vpp/qos.go`). Uses v1 name-based APIs due to upstream VPP v2 reply bug.
- **AAA:** Policy name overrides via `qos.ingress-policy` / `qos.egress-policy` attributes (`pkg/aaa/attributes.go`)
- **Subscriber activation:** `internal/subscriber/component.go` looks up policies by name from config and calls `ApplyQoS()`

### Limitations

1. **No dynamic rates** — `UploadRate`/`DownloadRate` fields exist in service group config and AAA attributes but are never consumed. Policers are always created from named policy templates.
2. **No policer statistics** — `PolicerDump` API returns bucket state but is never called. No show commands, no Prometheus metrics.
3. **No conf handler** — `qos-policies` are parsed from YAML but have no conf handler for live add/modify/delete.
4. **No policer update** — Changing a policy requires session re-activation. `PolicerUpdate` API exists but is unused.
5. **No DSCP marking pipeline** — VPP's `QosRecord`/`QosMark`/`QosEgressMap` APIs are available but unused.
6. **Fixed algorithm** — Hardcoded to 2R3C RFC 2698. No support for 1R2C, 1R3C RFC 2697, 2R3C RFC 4115, or MEF 5.
7. **No rate limiting by raw rate** — No way to say "100 Mbps download" without pre-defining a named policy.
8. **No scheduling/shaping** — Policers drop excess traffic (policing). No queuing, no AQM, no bufferbloat mitigation.
9. **No show/oper commands** — No `qos.policies`, `qos.subscriber`, or policer reset operations.

## 4. Design

### 4.1 Architecture

The QoS pipeline has three layers, implemented in phases:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Policing (Phases 1-3)                         │
│  VPP policer per subscriber per direction               │
│  Rate from: named policy OR ad-hoc rate OR AAA override │
│  Algorithm: configurable (1R2C, srTCM, trTCM, etc.)    │
│  Stats: PolicerDump → show + Prometheus                 │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│  Layer 2: DSCP Marking (Phase 4)                        │
│  VPP QosRecord on ingress → read DSCP from IP header    │
│  VPP QosEgressMap → remap QoS values on egress          │
│  VPP QosMark on egress → write DSCP to IP header        │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│  Layer 3: Scheduling/AQM (Phase 5 — future)             │
│  Custom VPP plugin: per-subscriber FQ-CoDel shaper      │
│  CAKE-equivalent: per-flow fairness + AQM + shaping     │
│  Replaces egress policer with queuing discipline         │
└─────────────────────────────────────────────────────────┘
```

### 4.2 Dynamic Rate Resolution

When a subscriber session activates, the QoS rate is resolved through a priority chain:

1. **Ad-hoc rate** (highest priority): `UploadRate`/`DownloadRate` from AAA attributes (`qos.upload-rate`/`qos.download-rate`) or service group config. These create an ephemeral policer with default actions (conform=transmit, exceed=drop, violate=drop) at the specified kbps rate.
2. **Named policy override**: `qos.ingress-policy`/`qos.egress-policy` from AAA attributes.
3. **Service group policy**: `ingress-policy`/`egress-policy` from the service group config.

Ad-hoc rates take precedence because they're the mechanism for per-subscriber rate differentiation from RADIUS without pre-defining every speed tier as a named policy.

### 4.3 Policy Configuration Enhancements

Extend `qos.Policy` with:
- `type` field: policer algorithm selection (default: `2r3c-rfc2698`)
- `color-aware` field: color-blind vs color-aware mode (default: false)
- `rate-type` field: `kbps` or `pps` (default: `kbps`)

**RFC Conformance Requirements:**
- **RFC 2698 (trTCM):** The Peak Information Rate (PIR) MUST be equal to or greater than the Committed Information Rate (CIR). (RFC 2698 §2). In this spec, `eir` maps to PIR for this type.
- **RFC 2697/2698/4115:** Committed Burst Size (CBS) and Excess/Peak Burst Size (EBS/PBS) SHOULD be configured to be equal to or greater than the maximum possible IP packet size (MTU) in the stream. (RFC 2698 §2, RFC 4115 §2).
- **RFC 2697 (srTCM):** At least one of CBS or EBS MUST be larger than 0. (RFC 2697 §2).

### 4.4 Per-Session QoS State Tracking

The VPP southbound layer maintains a `SubscriberPolicerState` per subscriber interface that tracks:

```
policerState map[uint32]*SubscriberPolicerState  // keyed by swIfIndex

SubscriberPolicerState {
    Ingress *PolicerEntry
    Egress  *PolicerEntry
}

PolicerEntry {
    PolicyName   string  // empty for ad-hoc rate subscribers
    Name         string  // VPP policer name (sub_{swIfIndex}_{in|out})
    PolicerIndex uint32  // returned by PolicerAddDel reply
    CIR          uint32  // applied CIR in kbps
    EIR          uint32  // applied EIR in kbps
    IsAdhoc      bool    // true if created from UploadRate/DownloadRate
}
```

This replaces the current `policerNames map[uint32][2]string`. The richer state enables:
- **Conf handler:** Query "all subscribers using policy X" by scanning `policerState` for matching `PolicyName`
- **Show handler:** Display per-subscriber applied rates and source (named policy vs ad-hoc)
- **Bulk update:** Use stored `PolicerIndex` for `PolicerUpdate` calls
- **Ad-hoc exclusion:** Subscribers with `IsAdhoc=true` are excluded from named policy bulk updates

### 4.5 Policer Update Flow

When a `qos-policies.<name>` conf handler fires (policy modified):
1. Lock `policerMu` for the entire operation
2. Snapshot the set of `swIfIndex` values where `PolicyName == <name>` and `IsAdhoc == false`
3. For each, call `PolicerUpdate` with the new parameters using the stored `PolicerIndex`
4. Track successes and failures
5. Unlock `policerMu`

**Concurrency model:** All policer operations (`ApplyQoS`, `UpdateQoS`, `RemoveQoS`, bulk update) serialize through `policerMu`. This prevents a session from activating with stale rates while a policy update is in progress, and prevents `RemoveQoS` from deleting a policer that is mid-update.

**Failure handling:** Best-effort with visibility. If some `PolicerUpdate` calls fail:
- Log each failure with subscriber identity and error
- Continue updating remaining subscribers
- Return success if at least one update succeeded (the policy template change is valid)
- Return error only if ALL updates failed (indicates systemic VPP issue)
- Partial state is visible via `show qos.subscriber` which reads actual VPP policer state
- Rollback restores the policy template in config but does NOT reverse already-applied VPP updates

This enables hitless rate changes for all subscribers on a policy without session disruption.

### 4.6 DSCP Marking Pipeline

VPP's QoS subsystem operates on a per-packet QoS metadata value (0-255) that flows through:
1. **Record** (`QosRecordEnableDisable`): Read QoS from packet header (IPv4/IPv6 DSCP) into VPP metadata on interface ingress.
2. **Egress Map** (`QosEgressMapUpdate`): Define a translation table (rows 0-255) that maps input QoS values to output QoS values.
3. **Mark** (`QosMarkEnableDisable`): Write the mapped QoS value back into the packet header (IPv4/IPv6 DSCP) on interface egress.

**BNG Implementation Logic:**
- **Ingress Policy (Upload):** `record-ingress: true` enables `QosRecord` on the subscriber interface. This captures the DSCP from the subscriber's CPE into VPP metadata.
- **Egress Policy (Download):** `mark-egress: true` enables `QosMark` on the subscriber interface. This sets the DSCP for packets going to the subscriber's CPE based on the VPP metadata and a mapping table.
- **Mapping:** Mapping is global but bound to the marking action via `map_id`. The spec supports defining a per-policy map which will be programmed into VPP as a unique `map_id`.
- **Protocol Source:** Only `QOS_SOURCE_IP` is in scope for this phase. MPLS/VLAN re-marking is deferred.

### 4.7 Statistics Collection

Use `PolicerDump` with `MatchNameValid=true` to query individual policers by name. The response includes:
- CIR/EIR/CBS/EBS configuration
- Current bucket levels (`CurrentBucket`, `ExtendedBucket`)
- Token rates (`CirTokensPerPeriod`, `PirTokensPerPeriod`)
- `LastUpdateTime`

VPP policer counters (conform/exceed/violate packet and byte counts) are available via the VPP stats segment, not the policer API. The show handler will use `PolicerDump` for state; Prometheus metrics will track policy-level aggregates.

### 4.8 Scheduling / AQM (Phase 5 — Future)

A custom VPP plugin (`osvbng-vpp-plugin-qos`) will implement per-subscriber egress scheduling with:
- Per-subscriber shaper (token bucket for pacing, not policing)
- FQ-CoDel AQM per subscriber (per-flow fairness within subscriber's allocation)
- Replaces the egress policer for subscribers that have scheduling enabled

This is a separate VPP plugin effort and will be spec'd in detail when Phase 4 is complete. The Go-side config will include a `scheduler` block in the QoS policy to enable it.

## 5. Configuration

### 5.1 Enhanced Policy Schema

```yaml
qos-policies:
  residential-100m:
    cir: 100000                    # kbps (required), Committed Information Rate
    eir: 100000                    # kbps (default: equal to cir). For RFC 2698 this is PIR (Peak Rate).
                                   # For RFC 4115 this is EIR (Excess Rate). PIR = CIR + EIR.
    cbs: 1250000                   # bytes (default: 100ms burst = cir * 1000 / 8 * 0.1)
                                   # SHOULD be >= MTU. Recommended: 10ms-125ms of CIR.
    ebs: 1250000                   # bytes (default: equal to cbs). For RFC 2698 this is PBS (Peak Burst).
    type: 2r3c-rfc2698             # optional, default: 2r3c-rfc2698
    color-aware: false             # optional, default: false
    rate-type: kbps                # optional, default: kbps
    conform:
      action: transmit
    exceed:
      action: drop
    violate:
      action: drop

  business-remarking:
    cir: 200000
    eir: 400000
    type: 2r3c-rfc2698
    conform:
      action: transmit
    exceed:
      action: mark-and-transmit
      dscp: 0
    violate:
      action: drop
```

**New `type` values:**
| Value | VPP Enum | Description |
|-------|----------|-------------|
| `1r2c` | `SSE2_QOS_POLICER_TYPE_API_1R2C` | Single rate, two color |
| `1r3c-rfc2697` | `SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697` | Single rate three color (srTCM) |
| `2r3c-rfc2698` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698` | Two rate three color (trTCM) — default |
| `2r3c-rfc4115` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115` | Two rate three color (RFC 4115) |
| `2r3c-mef5cf1` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1` | MEF 5 compliant |

### 5.2 Service Group QoS Block (unchanged)

```yaml
service-groups:
  residential:
    qos:
      ingress-policy: upload-50m
      egress-policy: residential-100m
      upload-rate: 0               # ad-hoc rate override (kbps), 0 = use policy
      download-rate: 0             # ad-hoc rate override (kbps), 0 = use policy
```

### 5.3 DSCP Marking Configuration (Phase 4)

```yaml
qos-policies:
  business-marked:
    cir: 200000
    conform:
      action: transmit
    exceed:
      action: drop
    violate:
      action: drop
    marking:
      record-ingress: true         # enable QosRecord on subscriber ingress
      egress-map:                   # optional DSCP remap on egress
        46: 46                     # EF → EF (preserve)
        34: 34                     # AF41 → AF41
        0: 0                       # BE → BE
        default: 0                 # everything else → BE
```

### 5.4 AAA Attributes (unchanged)

| Attribute | Type | Description |
|-----------|------|-------------|
| `qos.ingress-policy` | string | Override ingress policy name |
| `qos.egress-policy` | string | Override egress policy name |
| `qos.upload-rate` | uint64 | Ad-hoc upload rate in kbps |
| `qos.download-rate` | uint64 | Ad-hoc download rate in kbps |

## 6. File Plan

### Phase 1: Enhanced Policing + Ad-hoc Rates

| File | Action | Purpose |
|------|--------|---------|
| `pkg/config/qos/qos.go` | Modify | Add `Type`, `ColorAware`, `RateType` fields to `Policy`; add `PolicerType` enum with YAML unmarshaling; update `ToPolicerConfig()` to use new fields |
| `pkg/config/qos/adhoc.go` | Create | `NewAdhocPolicy(rateKbps uint64) *Policy` — creates a default policer from raw rate |
| `pkg/southbound/vpp/qos.go` | Modify | Replace `policerNames map[uint32][2]string` with `policerState map[uint32]*SubscriberPolicerState`; record `PolicerIndex` from existing `PolicerAddDelReply` (already returned, currently ignored); implement `UpdateQoS()` using `PolicerUpdate` by stored index; implement `DumpQoS()` using `PolicerDump`; add `GetSubscribersByPolicy(name string) []uint32` for bulk update queries |
| `pkg/southbound/sessions.go` | Modify | Add `UpdateQoS(swIfIndex uint32, ingress, egress *qos.Policy) error`, `DumpQoS(swIfIndex uint32) (*SubscriberPolicerState, error)`, and `GetSubscribersByPolicy(name string) []uint32` to `Sessions` interface |
| `internal/subscriber/component.go` | Modify | Update `activateSession()` to resolve ad-hoc rates: if `UploadRate > 0`, create ephemeral policy via `qos.NewAdhocPolicy()` and use it instead of named ingress policy (same for `DownloadRate`/egress) |

### Phase 2: Conf Handler + Live Policy Updates

| File | Action | Purpose |
|------|--------|---------|
| `pkg/handlers/conf/paths/paths.go` | Modify | Add `QoSPolicies Path = "qos-policies.<*>"` |
| `pkg/handlers/conf/qos/policies.go` | Create | Conf handler for `qos-policies.<*>`. On Apply: update policy in config, query `GetSubscribersByPolicy()` for affected subscribers, call `UpdateQoS()` for each under `policerMu` with best-effort failure handling. On Delete: check `GetSubscribersByPolicy()` returns empty, reject if subscribers active. Rollback restores old policy template. |
| `pkg/deps/deps.go` | Modify | Add `Southbound` to `ConfDeps` (already present) — the conf handler uses `Southbound.GetSubscribersByPolicy()` and `Southbound.UpdateQoS()` for bulk updates |
| `pkg/config/qos/qos.go` | Modify | Add `Validate() error` method to `Policy` enforcing RFC conformance: PIR >= CIR for RFC 2698, CBS or EBS > 0 for RFC 2697, burst >= MTU warning |

### Phase 3: Show/Oper Commands + Prometheus Metrics

| File | Action | Purpose |
|------|--------|---------|
| `pkg/handlers/show/paths/paths.go` | Modify | Add `QoSPolicies`, `QoSSubscriber`, `QoSStatistics` paths |
| `pkg/state/paths/paths.go` | Modify | Add `QoSStatistics` state path |
| `pkg/handlers/show/qos/policies.go` | Create | Show handler for `qos.policies` — lists all configured policies with current subscriber counts |
| `pkg/handlers/show/qos/subscriber.go` | Create | Show handler for `qos.subscriber` — per-subscriber policer state from `DumpQoS()` |
| `pkg/handlers/show/qos/statistics.go` | Create | Show handler for `qos.statistics` — aggregate policer stats with Prometheus export |
| `pkg/handlers/oper/qos/reset.go` | Create | Oper handler for `qos.reset` — reset policer counters via `PolicerReset` |
| `pkg/models/qos.go` | Create | Data models for QoS show responses: `PolicyInfo`, `SubscriberQoS`, `QoSStatistics` |
| `docs/configuration/qos.md` | Modify | Document new fields, ad-hoc rates, show commands |

### Phase 4: DSCP Marking Pipeline

| File | Action | Purpose |
|------|--------|---------|
| `pkg/config/qos/marking.go` | Create | `MarkingConfig` struct: `RecordIngress bool`, `EgressMap map[uint8]uint8`, `DefaultDSCP uint8` |
| `pkg/config/qos/qos.go` | Modify | Add `Marking *MarkingConfig` field to `Policy` |
| `pkg/southbound/vpp/qos_marking.go` | Create | `ApplyMarking()` / `RemoveMarking()` using VPP QosRecord, QosEgressMap, QosMark APIs |
| `pkg/southbound/sessions.go` | Modify | Add `ApplyMarking()` / `RemoveMarking()` to Sessions interface |
| `internal/subscriber/component.go` | Modify | Call `ApplyMarking()` after `ApplyQoS()` during session activation |
| `docs/configuration/qos.md` | Modify | Document DSCP marking configuration |

### Phase 5: Scheduling/AQM (future — separate spec)

| File | Action | Purpose |
|------|--------|---------|
| `osvbng-vpp-plugin-qos/` | Create (separate repo) | VPP plugin implementing per-subscriber FQ-CoDel shaper |
| `pkg/vpp/binapi/qos_sched/` | Create | Generated Go bindings for the custom plugin API |
| `pkg/config/qos/scheduler.go` | Create | `SchedulerConfig` struct |
| `pkg/southbound/vpp/qos_sched.go` | Create | VPP adapter for scheduling APIs |

## 7. Implementation Order

### Phase 1: Enhanced Policing + Ad-hoc Rates
- Extend `Policy` struct with `Type`, `ColorAware`, `RateType`
- Add `Validate()` method enforcing RFC conformance rules
- Implement `NewAdhocPolicy()` for raw rate → policer conversion
- Replace `policerNames` with `policerState` map using `SubscriberPolicerState`/`PolicerEntry` structs
- Record `PolicerIndex` from existing `PolicerAddDelReply` (keep `PolicerAddDel`, do NOT migrate to `PolicerAdd`)
- Implement `UpdateQoS()` using `PolicerUpdate` by stored index
- Implement `DumpQoS()` using `PolicerDump`
- Implement `GetSubscribersByPolicy()` scanning `policerState` for matching `PolicyName`
- Update subscriber activation to resolve ad-hoc rates (ad-hoc sets `IsAdhoc=true`, excluded from bulk updates)
- **Testable:** Apply ad-hoc rates from service group config, verify policer created with correct CIR

### Phase 2: Conf Handler + Live Policy Updates
- Add conf path for `qos-policies.<*>`
- Implement conf handler with validate/apply/rollback
- Validate: call `Policy.Validate()` for RFC conformance
- Apply: update config, then bulk-update active subscribers under `policerMu` with best-effort failure handling
- Delete: reject if `GetSubscribersByPolicy()` returns non-empty
- Rollback: restore old policy template (VPP state is NOT reversed for already-updated subscribers)
- **Testable:** Modify a policy's CIR at runtime, verify active subscriber policers update without session drop. Verify ad-hoc subscribers are unaffected by named policy changes.

### Phase 3: Show/Oper Commands + Prometheus Metrics
- Add show paths and state paths
- Implement `qos.policies` show handler
- Implement `qos.subscriber` show handler (per-subscriber policer state)
- Implement `qos.statistics` show handler with Prometheus struct tags
- Implement `qos.reset` oper handler
- Register state metric for statistics
- **Testable:** Query `show qos.policies`, verify policy list. Query `show qos.subscriber`, verify per-subscriber rates. Check Prometheus endpoint for QoS metrics.

### Phase 4: DSCP Marking Pipeline
- Add `MarkingConfig` to policy
- Implement VPP QosRecord/QosEgressMap/QosMark integration
- Wire into subscriber activation/release lifecycle
- **Testable:** Configure marking policy, verify DSCP values preserved/remapped on subscriber traffic

### Phase 5: Scheduling/AQM (future)
- Design and build VPP plugin (separate spec when ready)
- Generate Go bindings
- Integrate with subscriber lifecycle
- **Testable:** Verify per-subscriber shaping with FQ-CoDel under load, measure latency improvement vs pure policing

## 8. Attribute Mappings

### AAA → QoS Resolution

| AAA Attribute | Config Field | Resolution |
|---------------|-------------|------------|
| `qos.upload-rate` | `servicegroup.QoSConfig.UploadRate` | If > 0: `NewAdhocPolicy(rate)` → ingress policer. Overrides named policy. |
| `qos.download-rate` | `servicegroup.QoSConfig.DownloadRate` | If > 0: `NewAdhocPolicy(rate)` → egress policer. Overrides named policy. |
| `qos.ingress-policy` | `servicegroup.QoSConfig.IngressPolicy` | Policy name lookup in `cfg.QoSPolicies`. Overridden by ad-hoc rate. |
| `qos.egress-policy` | `servicegroup.QoSConfig.EgressPolicy` | Policy name lookup in `cfg.QoSPolicies`. Overridden by ad-hoc rate. |

### Policer Type String → VPP Enum

| YAML Value | Go Const | VPP Enum |
|------------|----------|----------|
| `1r2c` | `PolicerType1R2C` | `SSE2_QOS_POLICER_TYPE_API_1R2C` |
| `1r3c-rfc2697` | `PolicerType1R3CRFC2697` | `SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697` |
| `2r3c-rfc2698` | `PolicerType2R3CRFC2698` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698` |
| `2r3c-rfc4115` | `PolicerType2R3CRFC4115` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_4115` |
| `2r3c-mef5cf1` | `PolicerType2R3CMEF5CF1` | `SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_MEF5CF1` |

### Rate Type String → VPP Enum

| YAML Value | VPP Enum |
|------------|----------|
| `kbps` | `SSE2_QOS_RATE_API_KBPS` |
| `pps` | `SSE2_QOS_RATE_API_PPS` |

## 9. Testing

### Phase 1
- Deploy with service group containing `upload-rate: 50000` and no named ingress policy → verify policer created at 50 Mbps CIR
- Deploy with both ad-hoc rate and named policy → verify ad-hoc rate wins
- Deploy with `type: 1r3c-rfc2697` → verify VPP policer type matches
- Test AAA returning `qos.upload-rate=100000` → verify per-subscriber rate override

### Phase 2
- Change `qos-policies.residential-100m.cir` from 100000 to 200000 at runtime
- Verify all active subscribers on that policy see updated policer (via `PolicerDump`)
- Verify no session drops during update
- Verify subscribers with ad-hoc rates are NOT affected by the named policy update
- Delete a policy while subscribers are active → verify rejection
- Activate a new subscriber during a policy update → verify it gets the new rate (not stale)
- Validate RFC conformance: reject policy with `eir < cir` for `2r3c-rfc2698` type
- Simulate partial `PolicerUpdate` failure → verify successful subscribers updated, failures logged, commit succeeds

### Phase 3
- Query `show qos.policies` → verify all policies listed with subscriber counts
- Query `show qos.subscriber` → verify per-subscriber policer state (CIR, bucket levels)
- Check `/metrics` endpoint → verify `osvbng_qos_*` Prometheus metrics present
- Call `oper qos.reset` → verify policer counters reset

### Phase 4
- Configure policy with `marking.record-ingress: true` and egress map
- Send traffic with DSCP EF (46) → verify DSCP preserved on egress
- Send traffic with unlisted DSCP → verify remapped to `default` value
- Verify marking cleaned up on session release

## 10. Not In Scope

- **CoA (Change of Authorization)**: Dynamic mid-session rate changes via RADIUS CoA are not yet implemented in osvbng's AAA subsystem. The `UpdateQoS()` API built here will be the backend for CoA when it arrives, but CoA itself is out of scope.
- **Traffic classification / multi-class QoS**: Classify tables for matching traffic into different policer classes (e.g., voice vs data within a subscriber) are not covered. The current model is one policer per direction per subscriber.
- **Hierarchical QoS (H-QoS)**: Aggregate policers shared across multiple subscribers (e.g., per-VLAN or per-access-node rate limiting) are not covered.
- **VPP v2 policer API migration**: The upstream VPP v25.10 bug in `PolicerInputV2`/`PolicerOutputV2` reply messages blocks migration to index-based APIs for input/output binding. We keep `PolicerAddDel` for creation (it already returns `PolicerIndex`) and use `PolicerUpdate` by index for live updates. Input/output binding remains on v1 name-based APIs until VPP fixes the bug. No creation API migration (`PolicerAddDel` → `PolicerAdd`) is planned — it would add lifecycle complexity without benefit while attach/detach is stuck on v1.
- **Linux tc integration**: Not applicable — subscriber data plane traffic flows through VPP, not the Linux kernel. LCP taps are control-plane only.
