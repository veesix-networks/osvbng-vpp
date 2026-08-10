# Phase 3 COBALT Review

## Findings

### 1. The plan and the implementation spec disagree on the core COBALT contract

The Phase 3 plan and section 4.8 of the implementation spec are not describing the same design.

- `PHASE3_COBALT_PLAN.md:84-139` uses `vnet_buffer2(b)->unused[0]`, `vlib_time_now(vm)`, `u32` microseconds, `u32 p_drop`, and Linux-style backward count decay.
- `IMPLEMENTATION_SPEC.md:240-247` and `IMPLEMENTATION_SPEC.md:325-353` use `vnet_buffer2(b)->qos.bits`, `clib_cpu_time_now()`, `u64` nanoseconds, `u16 blue_drop_prob`, and prose closer to plain CoDel.

If implementation starts before those two documents are reconciled, the result will be ambiguous in data layout, timer arithmetic, and BLUE behavior.

Recommendation: make the Phase 3 plan the single source of truth, then update section 4.8 and the earlier `cake_flow_t` definition to match it before coding.

### 2. The combined ECN block would incorrectly ECN-mark BLUE drops

The plan correctly says BLUE is drop-only (`PHASE3_COBALT_PLAN.md:30-34`), but the combined block then says to ECN-mark any `should_drop` packet if it is ECN-capable (`PHASE3_COBALT_PLAN.md:50-53`).

That is not how Linux CAKE behaves. In Linux `cobalt_should_drop()`, CE marking happens only in the CoDel branch; BLUE stays a pure probabilistic drop path.

Impact: an ECN-capable UDP flow could get CE marks instead of the hard drops that BLUE is supposed to use for unresponsive traffic.

Recommendation: move ECN handling into the CoDel decision path only. Do not apply the final "ECN preference" to BLUE-triggered drops.

### 3. The BLUE description misses Linux CAKE's `queue_full()` / `queue_empty()` side effects

The plan describes `queue_full()` and `queue_empty()` as `p_drop` increment/decrement hooks (`PHASE3_COBALT_PLAN.md:31-33`, `PHASE3_COBALT_PLAN.md:235-236`), but Linux CAKE does more than that:

- `cobalt_queue_full()` also sets `dropping = true`, sets `drop_next = now`, and seeds `count = 1` if it was zero.
- `cobalt_queue_empty()` clears `dropping` and decays `count` backward when `drop_next` is due.

Those side effects are part of Linux CAKE's COBALT behavior. If Phase 3 only adjusts `p_drop`, overflow and drain handling will diverge from the reference algorithm.

Recommendation: implement `queue_full()` and `queue_empty()` as full state transitions, not just BLUE probability updates.

### 4. Reclaimed flow slots will retain stale COBALT state unless `cake_flow_reclaim()` is expanded

The current reclaim path only clears existing Phase 2 fields in `src/cake_dequeue.c:48-68`. It does not `memset()` the whole flow like the eviction path does in `src/cake_enqueue.c:53-84`.

That matters for reviewer question 6. Preserving COBALT state across `DECAYING -> BULK` reactivation is correct, but once a flow is reclaimed to `NONE`, all COBALT state must be reset. With the current code shape, reclaimed slots would otherwise carry stale `count`, `drop_next`, `p_drop`, and `dropping` into the next unrelated flow.

Recommendation: keep COBALT state across `DECAYING -> BULK`, but fully reset it on reclaim and eviction.

### 5. Hardcoding `mtu_time_us` to 1514 will mis-tune COBALT on jumbo or overhead-adjusted links

`PHASE3_COBALT_PLAN.md:183-186` computes `mtu_time_us` from a fixed 1514-byte packet. That is too simplistic for this plugin:

- subscriber interfaces may use jumbo MTUs
- wire size is already affected by `overhead_bytes`, `mpu`, and ATM/PTM handling in `cake_overhead_adjust()` (`src/osvbng_qos_sched.h:167-176`)

`mtu_time` is part of CAKE's non-starvation/adaptive threshold. Underestimating it makes the AQM more aggressive than intended on large-packet or overhead-heavy links.

Recommendation: derive `mtu_time_us` from the actual interface MTU, then run that through the same wire-size adjustment logic the shaper uses. Use 1514 only as a fallback if the MTU is unavailable.

### 6. `u32` microseconds are fine, but only if every time comparison is wrap-safe

The plan already notes that unsigned subtraction is safe for sojourn (`PHASE3_COBALT_PLAN.md:101-106`), but the algorithm prose still talks in terms of raw comparisons like `now >= drop_next` (`PHASE3_COBALT_PLAN.md:22-24`).

With `u32` microseconds, wrap happens every ~71 minutes. Raw relational comparisons will break across wrap. The implementation must use signed deltas, e.g.:

```c
if ((i32) (now_us - drop_next_us) >= 0)
```

Recommendation: keep `u32` microseconds, but make wrap-safe delta arithmetic an explicit implementation requirement in the plan.

## Answers To The 6 Reviewer Questions

### Q1. Is `vnet_buffer2(b)->unused[0]` safe for the enqueue timestamp?

Yes, for this scheduler-owned lifetime it is the best choice.

- VPP explicitly exposes `vnet_buffer2(b)->unused[5]` as spare opaque2 space in `vnet/buffer.h:518-536`.
- `qos.bits` is not spare metadata; it is reserved for QoS record/mark handoff in `vnet/buffer.h:478-487`.
- In the current plugin, nothing between enqueue and dequeue runs other feature-arc nodes on the queued packet. Wrong-worker packets are handed off by buffer index (`src/cake_enqueue.c:181-194`, `src/cake_handoff.c:26-45`), and queued packets are stored in the ring by buffer index (`src/cake_enqueue.c:257-258`) until dequeue resolves the same buffer again (`src/cake_dequeue.c:156-160`, `src/cake_dequeue.c:235-239`).

So the timestamp survives both the ring-buffer path and the owner-thread handoff path.

The only caveat: do not treat `unused[0]` as metadata that must survive after dequeue reinjection. Later output features could legally reuse opaque2. That is fine because COBALT only needs the timestamp until dequeue.

### Q2. Should `mtu_time_us` use the actual interface MTU or hardcode 1514?

Use the actual serialized maximum packet size for that scheduler, not a hardcoded 1514.

Best choice:

1. Get the interface MTU.
2. Convert that to on-wire bytes with the same overhead/MPU/ATM logic used by the shaper.
3. Compute `mtu_time_us` from that adjusted byte count.

If the interface MTU cannot be obtained reliably, fall back to 1514. But that should be the fallback, not the primary rule.

### Q3. Is `u32` microseconds sufficient, or should this use `u64` nanoseconds?

`u32` microseconds are sufficient for a 5 ms target.

- 1 microsecond resolution is 0.02% of the target.
- The queue sojourn and CoDel interval here are millisecond-scale, not nanosecond-scale.
- Keeping COBALT in `u32` microseconds saves per-flow space and keeps `cake_flow_t` within one cache line.

I would keep `u32` microseconds, with two conditions:

- use wrap-safe delta arithmetic everywhere
- document that the queue residence time must stay well below the wrap interval

If you want a single timebase across shaping and AQM, `u64` nanoseconds is cleaner, but it is not required for correctness here.

### Q4. Should Phase 3 implement the adaptive `mtu_time * bulk_flows * 2` threshold now?

Yes.

If the stated goal is "CAKE-equivalent" COBALT, this should be in Phase 3, not deferred. It is part of what makes CAKE avoid overreacting on lightly-loaded or low-rate links. The plan already includes it in `over_target` (`PHASE3_COBALT_PLAN.md:20`); that is the right direction.

Using only `sojourn > target` would be simpler, but it would not be CAKE-equivalent and would likely be too aggressive at low rates.

### Q5. Is `random_u32()` adequate for BLUE?

Yes.

`random_u32()` in VPP is a cheap 32-bit LCG in `vppinfra/random.h:45-73`. That is good enough for BLUE's per-dequeue probability check. BLUE does not need a cryptographic or high-quality Monte Carlo generator.

The important part is seeding:

- keep one seed per thread, not per flow
- initialize it from something less predictable than just `thread_index + 1`

I would use `random_default_seed() ^ thread_index` or similar. That is still cheap and avoids identical startup streams across runs.

### Q6. Should COBALT state reset on `DECAYING -> BULK` reactivation?

No. Preserve it across reactivation, reset it only when the flow is truly gone.

That matches Linux CAKE's intent:

- preserve state across `DECAYING -> BULK`
- reset on reclaim/eviction/`NONE`

For this codebase, that means:

- do nothing special in the current `DECAYING -> BULK` transition at `src/cake_enqueue.c:280-289`
- fully clear COBALT state in both `cake_flow_reclaim()` and `cake_flow_evict()`

## RFC 8289 Compliance Check

The Phase 3 plan is reasonably aligned with CoDel's control intent, but it should be described as a Linux CAKE / COBALT adaptation, not a literal RFC 8289 implementation.

Aligned with RFC 8289:

- sojourn time is measured on dequeue
- the first signal is delayed by one interval after sustained overload
- subsequent signals follow the `interval / sqrt(count)` control law
- low-rate non-starvation protection exists via the `mtu_time` inhibit

Important nuance:

- RFC 8289's pseudocode tracks the local minimum with `first_above_time_`
- Linux CAKE/COBALT folds that logic into `drop_next`, `count`, and backward decay

That is acceptable if CAKE equivalence is the goal. It does mean the current implementation spec prose (`IMPLEMENTATION_SPEC.md:327-329`) should be updated to reflect the Linux/COBALT behavior instead of plain RFC CoDel wording.

## BLUE Integration Check Against Linux CAKE

What matches Linux CAKE in the plan:

- per-flow `p_drop`
- `queue_full()` increases it
- `queue_empty()` decreases it
- every dequeue can trigger an additional probabilistic drop
- BLUE is drop-only, not ECN

What still needs to be tightened to match Linux CAKE:

- `queue_full()` must also force COBALT into dropping state and seed `count`
- `queue_empty()` must clear dropping state and decay `count` if `drop_next` is due
- the final ECN block must not convert BLUE drops into CE marks

## Data Structure Layout / Cache Efficiency

Current `cake_flow_t` in `src/osvbng_qos_sched.h:57-70` is compact and hot-path friendly. On a 64-bit target it is 40 bytes.

The planned layout in `PHASE3_COBALT_PLAN.md:145-169` should still fit in one 64-byte cache line. The net increase is about 16 bytes, not 24, because the new fields consume existing padding in the current layout.

That is acceptable.

Practical guidance:

- keep the per-flow COBALT state in `cake_flow_t`
- keep time fields in `u32` microseconds if staying with the current plan
- do not add more cold fields to `cake_flow_t` in Phase 3 unless necessary

## Enqueue Timestamp Survivability Through Ring Buffer And Handoff

The enqueue timestamp survives correctly.

- Wrong-worker packets are not cloned or rewritten; they are handed off by buffer index (`src/cake_handoff.c:44-45`).
- The ring stores the same buffer index (`src/cake_enqueue.c:257-258`).
- Dequeue reads the same buffer back from the ring (`src/cake_dequeue.c:156-160`, `src/cake_dequeue.c:235-239`).

So the timestamp will survive both:

- owner-thread handoff
- ring-buffer residence

The plan's placement of the timestamp write after local enqueue is also sensible, because it avoids storing timestamp metadata on packets that never enter the scheduler queue.

## Recommendation

Proceed with the Phase 3 direction, but make these changes before implementation starts:

1. Reconcile `IMPLEMENTATION_SPEC.md` with the Phase 3 plan.
2. Restrict ECN marking to the CoDel branch only.
3. Implement Linux-style `queue_full()` / `queue_empty()` side effects, not just `p_drop` updates.
4. Derive `mtu_time_us` from actual serialized MTU, not fixed 1514.
5. Make wrap-safe time comparisons explicit in the plan.
6. Reset COBALT state on reclaim and eviction, while preserving it across `DECAYING -> BULK`.

## External References

- Linux CAKE `sch_cake.c`: https://raw.githubusercontent.com/dtaht/sch_cake/master/sch_cake.c
- RFC 8289 CoDel: https://www.rfc-editor.org/rfc/rfc8289.html
