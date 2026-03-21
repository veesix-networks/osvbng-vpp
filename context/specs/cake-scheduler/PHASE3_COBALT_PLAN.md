# Phase 3 Implementation Plan: COBALT AQM (CoDel + BLUE)

**Date:** 2026-03-21
**Author:** Claude
**Status:** Pending Codex + Gemini review before implementation

## Overview

Implement COBALT active queue management in the CAKE scheduler dequeue path. COBALT combines CoDel (signals congestion to responsive TCP flows via drop/ECN) and BLUE (catches unresponsive UDP flows via probabilistic drop). This is what makes CAKE actually eliminate bufferbloat — keeping queue delay near the 5ms target instead of growing unbounded.

## Algorithm Reference

Based on Linux CAKE `sch_cake.c` `cobalt_should_drop()` (lines 560-640).

### CoDel Component

Per-flow state tracks sojourn time and drops at increasing frequency when queue delay exceeds target:

1. On dequeue: `sojourn = now - enqueue_timestamp`
2. `over_target = sojourn > target_us AND sojourn > mtu_time_us * bulk_flows * 2 AND sojourn > mtu_time_us * 4`
3. If `over_target` and not already dropping: enter dropping state, set `drop_next = now + interval`
4. If `over_target` and dropping and `count > 0` and `now >= drop_next`: drop/ECN-mark, increment count, `drop_next = drop_next + interval * rec_inv_sqrt(count)`
5. If NOT `over_target`: exit dropping state
6. When not dropping but `next_due` (count > 0 and now >= drop_next): decrement count backward toward 0 (windowed decay)

### BLUE Component

Per-flow probabilistic drop for unresponsive flows:

1. `p_drop` is a u32 (0 to ~0U, mapping to probability 0.0 to 1.0)
2. On queue overflow (`cobalt_queue_full`): `p_drop += p_inc` (clamped at ~0U)
3. On queue drain to empty (`cobalt_queue_empty`): `p_drop -= p_dec` (clamped at 0)
4. Per-dequeue: `drop |= (random_u32(&seed) < p_drop)`
5. BLUE does NOT use ECN — only drops. ECN is CoDel-only.

### Combined Decision

```
should_drop = false

// CoDel decision
if (over_target && dropping && next_due):
    should_drop = true (or ECN mark if capable)
    advance count + drop_next

// BLUE decision (additive)
if (p_drop > 0):
    should_drop |= (random < p_drop)

// ECN preference
if (should_drop && ecn_capable):
    mark_ecn(packet)
    should_drop = false  // marked, don't drop

if (should_drop):
    free_buffer(packet)
    return  // don't re-inject
```

### rec_inv_sqrt (Newton-Raphson)

Fixed-point Q0.32 reciprocal of sqrt(count):

```c
// new_invsqrt = (invsqrt / 2) * (3 - count * invsqrt^2)
static void cobalt_newton_step(u32 *rec_inv_sqrt, u32 count) {
    u32 invsqrt = *rec_inv_sqrt;
    u32 invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
    u64 val = (3LL << 32) - ((u64)count * invsqrt2);
    val >>= 2;
    val = (val * invsqrt) >> (32 - 2 + 1);
    *rec_inv_sqrt = val;
}
```

Cache first 16 values at plugin init (4 Newton steps each for accuracy). Beyond 16: single Newton step per count increment.

CoDel control law: `drop_next = drop_next + (interval * rec_inv_sqrt) >> 32`

## VPP-Specific Adaptations

### Enqueue Timestamp

Store `now_us` (u32, microsecond resolution) at enqueue time. Options considered:

- **Option A: `vnet_buffer2(b)->unused[0]`** — VPP buffer opaque2 has 5 unused u32 fields. We claim `unused[0]` for the enqueue timestamp. u32 microseconds gives ~71 minutes of range. Zero overhead (single store on enqueue, single load on dequeue).

- **Option B: Side array indexed by ring position** — separate `u32 timestamps[CAKE_FLOW_RING_SIZE]` per flow. Extra 512 bytes per active flow. Avoids touching buffer opaque.

- **Option C: `vnet_buffer2(b)->qos.bits`** — repurpose the QoS bits field. May conflict with VPP's QoS record/mark pipeline.

**Recommendation:** Option A. `vnet_buffer2(b)->unused[0]` is the cleanest — it's explicitly unused, survives the enqueue→dequeue journey (buffer stays in the ring), and adds zero memory overhead.

**Define for clarity:**
```c
#define cake_buffer_enqueue_time(b) (vnet_buffer2(b)->unused[0])
```

### Time Source

Use `vlib_time_now(vm)` converted to microseconds:
```c
u32 now_us = (u32)(vlib_time_now(vm) * 1e6);
```

`vlib_time_now` returns f64 seconds since VPP start. Converting to u32 microseconds gives ~71 minutes before wrap. For sojourn time calculation, wrapping is handled by unsigned subtraction: `sojourn = now_us - enqueue_us` works correctly even across wrap.

### ECN Marking (Dual-Stack)

**IPv4:** VPP provides `ip4_header_set_ecn_w_chksum(ip4, IP_ECN_CE)` at `vnet/ip/ip4_packet.h:298`. This does incremental checksum update — no full recompute.

ECN-capable check: `ip4_header_get_ecn(ip4) != IP_ECN_NON_ECN` (ECT(0) or ECT(1)).

**IPv6:** No VPP helper exists. Direct manipulation:
```c
u32 vtcfl = clib_net_to_host_u32(ip6->ip_version_traffic_class_and_flow_label);
u8 tc = (vtcfl >> 20) & 0xff;
u8 ecn = tc & 0x03;
// ECN-capable: ecn != 0
// Set CE: tc = (tc & ~0x03) | 0x03
vtcfl = (vtcfl & ~(0xffU << 20)) | ((u32)new_tc << 20);
ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32(vtcfl);
```

No checksum update needed for IPv6 (no header checksum).

### PRNG for BLUE

VPP provides `random_u32(u32 *seed)` in `vppinfra/random.h`. Linear congruential generator, fast, adequate for probabilistic drop decisions.

Per-thread seed stored in `cake_per_thread_t`:
```c
typedef struct {
    uword *active_bitmap;
    u32 random_seed;
} cake_per_thread_t;
```

Seed initialized to `thread_index + 1` (non-zero) at enable time.

## Data Structure Changes

### cake_flow_t — add COBALT state

```c
typedef struct {
    u32 *ring;
    u32 head;
    u32 tail;

    i32 deficit;
    u32 next;
    u32 prev;

    u32 backlog_bytes;
    u8 flow_state;
    u8 set_index;
    u8 dropping;           /* CoDel dropping state */
    u8 ecn_marked;         /* last packet was ECN-marked */

    /* CoDel state */
    u32 codel_count;       /* drop count (for interval scaling) */
    u32 rec_inv_sqrt;      /* Newton-Raphson cache, Q0.32 */
    u32 drop_next_us;      /* next CoDel drop time (microseconds) */

    /* BLUE state */
    u32 p_drop;            /* drop probability (0 to ~0U) */
    u32 blue_timer_us;     /* last BLUE update time */
} cake_flow_t;
```

### cake_sched_t — add COBALT params

```c
/* Inside cake_sched_t, after existing fields: */
u32 target_us;          /* CoDel target sojourn time (default 5000 = 5ms) */
u32 interval_us;        /* CoDel interval (default 100000 = 100ms) */
u32 mtu_time_us;        /* time to send one MTU at configured rate */
u32 p_inc;              /* BLUE probability increment */
u32 p_dec;              /* BLUE probability decrement */
```

`mtu_time_us` is calculated at enable time:
```c
cs->mtu_time_us = (u32)((1514ULL * 1000000ULL) / rate_bytes_per_sec);
```

Default BLUE parameters (from Linux CAKE):
```c
cs->p_inc = (u32)(1.0 / 256 * ~0U);   /* ~0.4% per event */
cs->p_dec = (u32)(1.0 / 4096 * ~0U);  /* ~0.024% per event */
```

### cake_tin_t — add ECN counter

```c
u64 ecn_marks;   /* packets ECN CE-marked instead of dropped */
```

### cake_per_thread_t — add PRNG seed

```c
u32 random_seed;
```

## File Changes

### osvbng_qos_sched.h

- Add COBALT fields to `cake_flow_t`
- Add COBALT params to `cake_sched_t`
- Add `ecn_marks` to `cake_tin_t`
- Add `random_seed` to `cake_per_thread_t`
- Add `cake_buffer_enqueue_time()` macro
- Add `cobalt_rec_inv_sqrt_cache[]` extern
- Add inline: `cake_cobalt_newton_step()`, `cake_cobalt_invsqrt()`, `cake_cobalt_control()`

### cake_cobalt.c

- Implement `cobalt_rec_inv_sqrt_cache[16]` with init function
- Move from stub to actual implementation
- `cake_cobalt_cache_init()` called from plugin init

### cake_enqueue.c

- Add `cake_buffer_enqueue_time(b0) = now_us` after storing buffer in ring

### cake_dequeue.c

- After popping packet from ring, before re-injection:
  - Compute `sojourn_us = now_us - cake_buffer_enqueue_time(b)`
  - Call inline `cake_cobalt_should_drop()` with sojourn, flow state, tin params
  - If drop: `vlib_buffer_free_one()`, update counters, continue to next packet
  - If ECN mark: call `ip4_header_set_ecn_w_chksum()` or IPv6 equivalent
- On flow queue drain (empty): call `cake_cobalt_queue_empty()` to decay BLUE
- On buffer overflow drop at enqueue: call `cake_cobalt_queue_full()` to increase BLUE

### osvbng_qos_sched.c

- Initialize COBALT params at enable time (target, interval, mtu_time, p_inc, p_dec)
- Call `cake_cobalt_cache_init()` in plugin init
- Initialize per-thread random seeds
- Show command: add ECN marks counter
- Reset stats: add ECN marks

### osvbng_qos_sched_error.def

- Add `DROPPED_AQM` counter (distinct from overflow drops)
- Add `ECN_MARKED` counter

## Implementation Order

1. Data structures (header) — COBALT fields, params, timestamp macro
2. rec_inv_sqrt cache (cake_cobalt.c) — Newton-Raphson init
3. Enqueue timestamp — single line addition
4. COBALT should_drop inline (header) — core algorithm
5. Dequeue integration — call should_drop, handle drop/ECN/continue
6. BLUE queue_full/queue_empty — overflow and drain callbacks
7. ECN marking — IPv4 and IPv6
8. Enable path — param calculation
9. Show/stats — ECN marks display
10. Error counters — AQM drops, ECN marks

## Testing

From the spec:
1. iperf3 + concurrent ping at subscriber rate → ping RTT stays near 5ms target (not 100ms+)
2. ECN-capable flow → verify CE marks in received packets, zero drops
3. Non-ECN UDP flood → verify BLUE kicks in, drops proportionally
4. Compare latency under load: CAKE scheduler vs no scheduler → expect 10-50x latency reduction

Practical test with containerlab:
```bash
# Terminal 1: downstream iperf3 at 100 Mbps shaped
docker exec corerouter1 iperf3 -c 10.255.0.2 -t 30

# Terminal 2: concurrent ping to measure latency under load
docker exec subscriber ping 10.0.0.2 -i 0.1

# Without COBALT: expect 100-500ms ping RTT under load
# With COBALT: expect 5-20ms ping RTT under load
```

## Questions for Reviewers

1. Is `vnet_buffer2(b)->unused[0]` safe to use for enqueue timestamp on the `ip4-output` feature arc? Could any other feature arc node between enqueue and dequeue overwrite this field?

2. Should `mtu_time_us` use the actual interface MTU from `vnet_sw_interface_get_mtu()` or hardcode 1514? The subscriber interface MTU may differ (e.g., 9000 for jumbo frames).

3. Linux CAKE uses `ktime_t` (nanoseconds) throughout. We're using `u32` microseconds for COBALT timing. Is microsecond resolution sufficient for the 5ms target, or should we use `u64` nanoseconds to match the shaper's `global_shaper_time_ns`?

4. The Linux COBALT `over_target` check includes `sojourn > mtu_time * bulk_flows * 2` — this makes the target adaptive based on the number of active bulk flows. Should we implement this from Phase 3, or use the simpler `sojourn > target` check and add the adaptive threshold later?

5. For the BLUE PRNG: VPP's `random_u32()` is a 32-bit LCG. Linux CAKE uses `prandom_u32()` which is also an LCG. Is this adequate, or should we use a better PRNG to avoid correlated drops across flows?

6. Should COBALT state (`codel_count`, `rec_inv_sqrt`, `dropping`, `p_drop`) be reset when a flow transitions from DECAYING back to BULK (re-activated)? Linux CAKE preserves CoDel state across flow re-activation but resets it on flow reclamation (NONE). What's the correct behavior?
