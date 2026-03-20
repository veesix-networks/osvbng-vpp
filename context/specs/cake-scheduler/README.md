# QoS: CAKE-Equivalent Per-Subscriber Scheduler

**What:** Custom VPP plugin implementing per-subscriber egress traffic scheduling with CAKE-equivalent functionality — per-flow queuing, COBALT AQM (CoDel + BLUE), DRR, DiffServ tins, triple isolation, overhead compensation, and token-bucket shaping. Dual-stack (IPv4 + IPv6). Replaces egress policers to eliminate bufferbloat while maintaining per-flow fairness.

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Spec Draft | **Complete** |
| Phase 2 | Spec Refinement (Gemini) | **Complete** |
| Phase 3 | Spec Critique (Codex) | **Complete** |
| Phase 4 | Spec Finalization | **Complete** |
| Phase 5 | Implementation | Not started |
| Phase 6 | Code Review | Not started |

## Key Context Files

- [IMPLEMENTATION_SPEC.md](IMPLEMENTATION_SPEC.md) — Final technical specification
- [DECISIONS.md](DECISIONS.md) — All review items triaged (18 findings: 7 Codex + 11 Gemini, all accepted, 0 rejected)
- [spec-reviews/CODEX.md](spec-reviews/CODEX.md) — Phase 3 architectural critique
- [spec-reviews/GEMINI.md](spec-reviews/GEMINI.md) — Phase 2 RFC compliance and algorithm review
- [../full-qos/IMPLEMENTATION_SPEC.md](../full-qos/IMPLEMENTATION_SPEC.md) — Parent QoS spec (this is Phase 5 of that spec)

## Codebase Entry Points

### Plugin source (`src/`)

- `src/osvbng_qos_sched.h` — Core data structures
- `src/cake_enqueue.c` — Enqueue node (interface-output feature arc)
- `src/cake_dequeue.c` — Dequeue node (INPUT polling)
- `src/cake_cobalt.c` — COBALT AQM (CoDel + BLUE)
- `src/cake_hash.c` — Flow hashing (IPv4 + IPv6)

### VPP upstream (pattern references)

- `vnet/interface_output.c` — Interface output feature arc
- `vnet/policer/` — Existing policer architecture
- `vnet/buffer.h` — Buffer metadata
- `vlib/node.h` — Node registration macros

### Reference Implementation

- [`dtaht/sch_cake`](https://github.com/dtaht/sch_cake) — Linux CAKE qdisc (scalar reference, ~3000 lines)

## Phase 2 Prompt (Gemini — Spec Refinement)

> Read `context/PROCESS.md` for the workflow overview.
>
> Execute Phase 2 (spec refinement) for `context/specs/cake-scheduler/`.
>
> The spec describes a custom VPP plugin implementing CAKE-equivalent per-subscriber traffic scheduling for a software BNG. Dual-stack (IPv4 + IPv6). It combines per-flow queuing with set-associative hashing, COBALT AQM (CoDel + BLUE), deficit round robin, DiffServ-aware traffic classification, triple isolation, overhead compensation for DSL/PON, and token-bucket shaping.
>
> **Key areas to focus on:**
> - RFC 8290 (FQ-CoDel) compliance: Does the FQ + AQM design correctly implement the RFC's requirements for flow isolation, sparse flow handling, and queue management?
> - RFC 8289 (CoDel) compliance: Is the CoDel algorithm correctly specified (target, interval, drop scheduling, `rec_inv_sqrt`)?
> - RFC 3168 (ECN) compliance: Is ECN marking correctly specified for both IPv4 and IPv6 (ECT check, CE marking, non-ECT handling, checksum differences)?
> - RFC 2474/2597/2598 (DiffServ): Are the DSCP-to-tin mappings reasonable? Any missing PHBs? Is IPv6 traffic class extraction correct?
> - AQM parameter defaults: Are 5ms target and 100ms interval appropriate for BNG egress?
> - Overhead compensation: Are the ATM cell rounding and framing overhead calculations correct?
> - BLUE algorithm: Is the BLUE integration with CoDel correctly specified for handling unresponsive flows?
> - IPv6: Is the dual-stack handling complete? Flow hashing with 128-bit addresses, extension header handling, flow label usage?

## Phase 3 Prompt (Codex — Spec Critique)

> Read `context/PROCESS.md` for the workflow overview.
>
> Execute Phase 3 (spec critique) for `context/specs/cake-scheduler/`.
>
> The spec describes a custom VPP plugin implementing CAKE-equivalent per-subscriber scheduling. The plugin source is in `src/`. VPP upstream source is at [fd.io VPP](https://fd.io/vpp). The osvbng Go control plane is at [osvbng](https://github.com/veesix-networks/osvbng).
>
> **Key areas to focus on:**
> - **Enqueue-dequeue pipeline**: The two-node design (enqueue on feature arc, dequeue as INPUT node) — are there race conditions? What happens if enqueue stores a buffer but the dequeue frees it before transmission?
> - **Buffer lifetime**: Packets are held in per-flow queues between enqueue and dequeue. Are VPP buffer reference counts handled correctly? Can the buffer pool run out under heavy queuing?
> - **Per-thread isolation**: The spec claims per-thread scheduler ownership. Verify this against VPP's actual thread model — what happens with multi-queue NICs? TX queue thread affinity?
> - **Memory bounds**: With 1024 flows per tin, 8 tins per subscriber, thousands of subscribers — what's the memory footprint? Is there an OOM risk?
> - **Feature arc resume**: Dequeued packets must resume the output feature arc at `interface-output-arc-end`. Does `current_config_index` survive storage in the per-flow queue?
> - **INPUT node cost when idle**: If no subscribers have scheduling enabled, does the INPUT node polling cost anything?
> - **Missing failure modes**: What happens on subscriber disconnect while packets are queued? VPP interface deletion? Worker thread rebalance?
> - **IPv6 extension headers**: The flow hashing assumes TCP/UDP ports follow the fixed 40-byte IPv6 header. What happens with hop-by-hop, routing, or fragment extension headers?

## Prompt to Resume

> Read `context/SUMMARY.md` for project state, then `context/specs/cake-scheduler/README.md` for current status. Phases 1 and 3 are complete. Next: optionally send to Gemini (Phase 2), then finalize the spec in Phase 4 using `spec-reviews/CODEX.md` and any Gemini review artifact.
