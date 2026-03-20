# Implementation Spec: CAKE-Equivalent Per-Subscriber Scheduler — VPP Plugin

## 1. Overview

Custom VPP plugin (`osvbng-vpp-plugin-qos`) implementing per-subscriber egress traffic scheduling with CAKE-equivalent functionality: per-flow queuing with set-associative hashing, COBALT AQM (CoDel + BLUE), deficit round robin, DiffServ-aware traffic classification (tins), triple isolation (per-flow + per-host fairness), link-layer overhead compensation, and token-bucket shaping with nanosecond precision. Replaces egress policers for subscribers with scheduling enabled, eliminating bufferbloat while maintaining per-flow fairness within each subscriber's rate allocation.

## 2. References

- RFC 8290 — The Flow Queue CoDel Packet Scheduler and Active Queue Management Algorithm
- RFC 8289 — Controlled Delay Active Queue Management (CoDel)
- RFC 2474 — Definition of the Differentiated Services Field (DS Field)
- RFC 2597 — Assured Forwarding PHB Group
- RFC 2598 — An Expedited Forwarding PHB
- RFC 3168 — The Addition of Explicit Congestion Notification (ECN) to IP
- RFC 8311 — Relaxing Restrictions on ECN
- `dtaht/sch_cake` — Linux CAKE qdisc reference implementation
- `components/qos/full-qos/IMPLEMENTATION_SPEC.md` — Parent QoS spec (this is Phase 5)
- VPP `src/vnet/interface_output.c` — Interface output feature arc
- VPP `src/vnet/policer/` — Existing policer architecture (pattern reference)
- VPP `src/vnet/buffer.h` — Buffer metadata (opaque/opaque2 space)
- VPP `src/vlib/node.h` — Node types including `VLIB_NODE_TYPE_SCHED`
- VPP `src/vlib/tw_funcs.h` — Timing wheel for scheduled node activation
- VPP `src/vppinfra/bihash_template.h` — Hash table for flow lookup
- VPP `src/vppinfra/pool.h` — Pool allocator for flow/queue state

## 3. Current State

See `components/qos/SUMMARY.md` and `components/qos/full-qos/IMPLEMENTATION_SPEC.md`.

The existing QoS system uses VPP policers (2R3C token bucket) for per-subscriber rate enforcement. Policers are **policing** — excess packets are dropped immediately at the point of metering. There is no queuing, no pacing, no AQM, and no per-flow fairness. The full-qos spec (Phases 1-4) adds configurable algorithms, dynamic rates, DSCP marking, and live updates. Phase 5 was left as "future — separate spec" — this is that spec.

### The BNG as the Optimal CAKE Deployment Point

In an ISP access network, the BNG is the gateway between the subscriber's CPE and the core network. It is the single most impactful place to deploy intelligent queue management because it sits at the convergence of three critical factors:

1. **The BNG controls the download bottleneck.** The subscriber's access link (DSL/GPON/DOCSIS) is almost always the narrowest point in the path. The BNG is the last device where packets can be shaped *before* entering that constrained link. Without egress shaping here, packets queue in the DSLAM/OLT's large, dumb FIFO buffers — the primary source of bufferbloat in access networks.

2. **The BNG has authoritative rate and access-technology knowledge.** It knows each subscriber's provisioned speed tier (from RADIUS/service group config) and the access technology framing (ATM for ADSL, PTM for VDSL2, GEM for GPON). This makes it the only device in the path that can shape at the *exact* link rate with *exact* overhead compensation. A CPE running SQM must guess and shape conservatively below sync rate — wasting 5-15% of available capacity. The BNG wastes nothing.

3. **The BNG enforces QoE regardless of CPE capability.** ISPs cannot control CPE firmware. Most vendor-supplied residential gateways have no SQM/CAKE support. By deploying CAKE at the BNG, every subscriber gets bufferbloat mitigation and per-flow fairness on the download path — no CPE upgrade, no truck roll, no customer action required.

**Quality of Experience (QoE) impact:** Bufferbloat is the dominant cause of poor interactive performance (gaming, video calls, web browsing) for broadband subscribers under load. A household streaming 4K Netflix while someone games experiences 200-500ms added latency with traditional policer-based QoS. CAKE at the BNG reduces this to 5-10ms — a transformative QoE improvement that directly reduces churn and support calls.

**Egress-only is correct for the BNG.** Upload bufferbloat is the CPE's problem — by the time upload packets reach the BNG, they've already traversed the access link queue. The BNG can only police upload traffic (enforce rate), not reshape it. The ideal architecture is BNG-side CAKE for download + CPE-side SQM for upload. This spec covers the BNG side. The existing policer infrastructure (full-qos Phases 1-4) handles ingress rate enforcement.

### Operational Visibility as a First-Class Requirement

A persistent problem with vendor BNG platforms is poor operational metrics — operators get aggregate counters at best, with no per-subscriber insight into what the QoS system is actually doing. This plugin treats observability as a day-1 requirement, not a future enhancement. Every scheduler instance exposes per-tin metrics (packets, bytes, drops, ECN marks, peak/average queue delay, flow counts by state) via both VPP CLI and binary API, feeding directly into Prometheus export and operator dashboards. An operator must be able to answer "why is subscriber X's latency high?" by querying scheduler stats — not by guessing or opening a support case with the vendor.

### Why Scheduling Over Policing

Policing drops packets at the metering point without regard to queue state, flow behavior, or sojourn time. This causes:

1. **Bufferbloat**: Downstream buffers (DSLAM, OLT, CPE) absorb bursts the policer permits, adding 50-500ms latency.
2. **Flow unfairness**: A single TCP flow consuming all bandwidth starves other flows. Policers are flow-blind.
3. **Unresponsive flow damage**: UDP gaming/VoIP traffic has no congestion response. Policers drop it proportionally to all traffic rather than targeting the queue-building flows.
4. **Sawtooth throughput**: TCP reacts to policer drops with multiplicative decrease, creating throughput oscillation instead of steady-state pacing.

CAKE-equivalent scheduling solves all four: shaping paces transmission to prevent downstream bufferbloat, FQ gives each flow its fair share, COBALT AQM signals congestion early (via ECN or targeted drops) to responsive flows, and BLUE handles unresponsive flows via probabilistic dropping.

### VPP Constraints

The Linux CAKE implementation (`sch_cake.c`) is ~3000 lines of scalar C operating on one packet at a time via the kernel qdisc `enqueue`/`dequeue` interface. VPP requires:

1. **Vector processing**: Process batches of 1-256 packets per node invocation, not one-at-a-time.
2. **Dual-loop pattern**: Process 2+ packets per inner loop iteration with prefetch for cache efficiency.
3. **MARCH variants**: Generate AVX2/AVX-512/NEON SIMD variants via `VLIB_NODE_FN()` for flow hashing and classification.
4. **No kernel dependencies**: Replace `skb`, `qdisc`, `Qdisc_ops`, `netlink`, `ktime`, `kvzalloc` with VPP equivalents.
5. **Feature arc integration**: Hook into VPP's `interface-output` feature arc, not Linux TC.
6. **Per-thread isolation**: Each worker thread owns its scheduler state — no cross-thread locking in the data plane.
7. **Binary API**: Configuration via VPP binary API messages, not netlink.

## 4. Design

### 4.1 Architecture

```
                          VPP Packet Processing Pipeline
                          ─────────────────────────────

  ip4/ip6-lookup → ip4/ip6-rewrite → interface-output feature arc
                                      │
                              ┌───────▼────────┐
                              │  cake-enqueue   │  ← VNET_FEATURE on interface-output arc
                              │  (enqueue node) │
                              └───────┬────────┘
                                      │ buffers stored in per-subscriber queues
                                      │
                              ┌───────▼────────┐
                              │ cake-dequeue    │  ← VLIB_NODE_TYPE_INPUT (polling)
                              │ (dequeue node)  │     checks shaper timing, drains queues
                              └───────┬────────┘
                                      │ re-injects to interface-output arc
                                      │ with CAKE_BUFFER_F_SCHEDULED flag
                                      │
                              ┌───────▼────────┐
                              │  cake-enqueue   │  sees flag → clears it →
                              │  (passthrough)  │  vnet_feature_next() → continues arc
                              └───────┬────────┘
                                      │
                              ┌───────▼────────┐
                              │ span-output,    │  ← remaining output features
                              │ ipsec-if-output,│     (NOT skipped)
                              │ arc-end, TX     │
                              └───────────────┘
```

**Two-node design:**

1. **`cake-enqueue`** — Feature arc node on `interface-output`. Intercepts packets destined for scheduler-enabled interfaces. Classifies packets into tins and flows, stores buffer indices in per-flow queues, timestamps packets. Packets that belong to non-scheduled interfaces pass through untouched.

2. **`cake-dequeue`** — `VLIB_NODE_TYPE_INPUT` polling node (starts `DISABLED`, switched to `POLLING` when first scheduler activates). On each main loop iteration, checks the active scheduler bitmap for the current thread. For each scheduler whose shaper timer has expired, runs the CAKE dequeue algorithm (tin selection → flow selection → COBALT AQM → deficit accounting), assembles a vector of buffer indices, and re-injects them into the `interface-output` feature arc with the `CAKE_BUFFER_F_SCHEDULED` flag set. The enqueue node sees this flag on the second pass, clears it, and calls `vnet_feature_next()` to continue through remaining output features (span, ipsec, etc.) — no features are skipped.

### 4.2 Why INPUT Node Instead of SCHED Node

The VPP timing wheel (`VLIB_NODE_TYPE_SCHED`) has 10µs tick granularity and is designed for infrequent events (session expiry, protocol timers). A per-subscriber scheduler at 1 Gbps needs to transmit a 1500-byte packet every ~12µs. With thousands of subscribers, the timing wheel would be overwhelmed with timer reschedules.

An `INPUT` node in polling mode runs every main loop iteration (~1-10µs depending on load). It checks a bitmap of "active schedulers" and processes only those with pending work and expired shaper timers. This is the same pattern used by device drivers and the snort plugin for dequeue processing.

**Idle cost management**: The dequeue node is registered with `VLIB_NODE_STATE_DISABLED` by default. When the first scheduler is enabled on any thread, the enable path calls `vlib_node_set_state(vm, cake_dequeue_node.index, VLIB_NODE_STATE_POLLING)`. When the last scheduler is disabled, it sets the node back to `VLIB_NODE_STATE_DISABLED`. This means zero dispatch overhead when no subscribers have scheduling enabled — the node is not called at all.

### 4.3 Per-Subscriber Scheduler Instance

Each subscriber with scheduling enabled gets a `cake_sched_t` instance:

```c
typedef struct {
  /* Shaper state */
  u64 rate_bytes_per_sec;           /* configured rate */
  u64 rate_ns_per_byte;             /* precomputed: 1e9 / rate_bytes_per_sec */
  u64 global_shaper_time_ns;        /* next allowed transmit time (global) */
  u64 last_dequeue_time_ns;         /* last dequeue timestamp */

  /* Tin state — lazily allocated on first packet to each DSCP class.
   * Pointer array, not embedded: tins[i] is NULL until first use.
   * This avoids ~320 KiB of static allocation per subscriber in diffserv4. */
  cake_tin_t *tins[CAKE_MAX_TINS];
  u8 tin_cnt;                       /* max tin count for this mode (1, 3, 4, or 8) */
  u8 tin_mode;                      /* besteffort, diffserv3, diffserv4, diffserv8 */
  u8 tins_allocated;                /* count of non-NULL tins */

  /* Per-interface binding */
  u32 sw_if_index;                  /* subscriber interface */
  u32 sched_index;                  /* self-index in pool */

  /* Overhead compensation */
  i16 overhead_bytes;               /* per-packet add (Ethernet/ATM/PTM framing) */
  u8 atm_mode;                      /* 0=none, 1=ATM (53-byte cell rounding), 2=PTM */
  u8 mpu;                           /* minimum packet unit (e.g., 64 for Ethernet) */

  /* Buffer limit — dual admission control */
  u32 buffer_limit;                 /* max total queued bytes across all tins */
  u32 buffer_usage;                 /* current total queued bytes */
  u32 queued_buffers;               /* current total queued buffer objects */

  /* Flags */
  u32 flags;                        /* CAKE_FLAG_WASH_DSCP, CAKE_FLAG_SPLIT_GSO, etc. */
} cake_sched_t;
```

### 4.4 Tin (Traffic Class) Structure

Each tin implements DRR scheduling across its flows:

```c
#define CAKE_QUEUES         1024    /* flows per tin */
#define CAKE_SET_WAYS       8       /* set-associative ways */
#define CAKE_MAX_TINS       8

typedef struct {
  /* Flow queues — pool-allocated, only active flows consume memory.
   * Default limit: 256 for besteffort/diffserv3, 1024 configurable.
   * Set-associative tags stored separately for O(1) lookup. */
  cake_flow_t *flows;             /* pool allocator */
  u32 flow_tags[CAKE_QUEUES];    /* set-associative tag → flow pool index (~0 = empty) */
  u32 flow_count;                 /* active flows */
  u32 flow_limit;                 /* max flows for this tin */

  /* DRR lists — doubly-linked via flow.next/prev indices */
  u32 new_flow_head;                /* sparse/new flow list head */
  u32 old_flow_head;                /* bulk/old flow list head */
  u32 decaying_flow_head;           /* decaying flow list head */

  /* Tin-level shaper */
  u64 tin_rate_ns_per_byte;         /* per-tin rate (subset of global) */
  u64 tin_shaper_time_ns;           /* next allowed transmit for this tin */

  /* DRR quantum */
  u32 quantum;                      /* base deficit quantum (MTU-scaled) */
  u32 flow_quantum;                 /* per-flow quantum (adjusted by host count) */

  /* DiffServ parameters */
  u8 tin_index;                     /* priority index (0=highest) */

  /* Statistics */
  u64 packets;
  u64 bytes;
  u64 drops;
  u64 ecn_marks;
  u32 peak_queue_delay_us;
  u32 avg_queue_delay_us;
  u32 sparse_flow_count;
  u32 bulk_flow_count;
} cake_tin_t;
```

### 4.4a Buffer Ownership Invariant

Queued packets have a strict ownership model:

1. **Enqueue consumes the buffer.** The enqueue node removes the buffer index from the frame and stores it in the flow queue. It does NOT forward the buffer to any next node. The scheduler is the sole owner from that point — no other VPP node holds a reference to the buffer.

2. **Exactly one of five paths frees a queued buffer:**
   - **Dequeue transmit** — buffer re-injected to the output feature arc.
   - **COBALT AQM drop** — `vlib_buffer_free_one()` called by the dequeue node.
   - **Buffer overflow drop** — `vlib_buffer_free_one()` called by the enqueue node when `buffer_limit` or `max_queued_buffers` is exceeded.
   - **Subscriber teardown / interface delete** — the disable path walks all tins and flows, freeing every queued buffer before releasing the scheduler.
   - **Handoff congestion drop** — if cross-thread handoff fails, the buffer is freed immediately.

3. **Global admission control.** In addition to the per-subscriber `buffer_limit` (bytes), a global `max_queued_buffers` watermark (default: 25% of VPP's buffer pool size) prevents the scheduler from exhausting the buffer pool. When the global count is reached, new enqueues are dropped regardless of per-subscriber limits. This is critical because small packets pin full buffer objects — byte-only limits don't bound actual buffer-pool pressure.

### 4.5 Flow Structure

Each flow within a tin:

```c
typedef struct {
  /* Packet queue — circular buffer of u32 buffer indices */
  u32 *queue;                       /* vec of buffer indices */
  u32 head;                         /* dequeue position */
  u32 tail;                         /* enqueue position */

  /* DRR state */
  i32 deficit;                      /* remaining deficit (bytes) */
  u32 next;                         /* next flow in DRR list (index) */
  u32 prev;                         /* prev flow in DRR list (index) */

  /* COBALT AQM state */
  u64 codel_drop_next_ns;           /* next CoDel drop/mark time */
  u64 blue_drop_next_ns;            /* next BLUE probability update */
  u32 codel_count;                  /* CoDel drop count (for interval calc) */
  u16 codel_rec_inv_sqrt;           /* reciprocal sqrt cache */
  u16 blue_drop_prob;               /* BLUE drop probability (0-65535) */
  u8 codel_dropping;                /* in CoDel dropping state */
  u8 ecn_enabled;                   /* ECN marking enabled for this flow */

  /* Host tracking (for triple isolation) */
  u16 src_host_idx;                 /* index into host table */
  u16 dst_host_idx;                 /* index into host table */

  /* Queue state */
  u32 backlog_bytes;                /* bytes in this flow's queue */
  u8 flow_state;                    /* CAKE_FLOW_NONE/SPARSE/BULK/DECAYING */
  u8 set_index;                     /* set-associative set this flow belongs to */
} cake_flow_t;

enum {
  CAKE_FLOW_NONE = 0,
  CAKE_FLOW_SPARSE,
  CAKE_FLOW_BULK,
  CAKE_FLOW_DECAYING,
};
```

### 4.6 Flow Classification — Set-Associative Hashing

Linux CAKE uses set-associative hashing with 8-way sets for collision-resistant flow mapping. In VPP, the enqueue node classifies packets:

1. **Detect IP version** from the first nibble of the packet header (`ip_version_and_header_length >> 4` for IPv4, or check for 0x6).
2. **Extract 5-tuple** from IPv4 or IPv6 + TCP/UDP headers (vectorized across batch). For IPv6, use `ip6_header_t.src_address` / `dst_address` (128-bit each). The IPv6 flow label (20 bits from `ip_version_traffic_class_and_flow_label`) MUST be included in the hash input (RFC 8290 RECOMMENDS). This is critical for encrypted traffic (QUIC, WireGuard) where L4 ports may not be visible.
3. **IPv6 extension header walk**: For IPv6, the L4 header may not immediately follow the fixed 40-byte header. Use VPP's `ip6_locate_header()` or equivalent to skip hop-by-hop, routing, destination option, and fragment extension headers to locate the actual L4 protocol and ports. For non-first fragments (where L4 ports are unavailable), fall back to hashing on src/dst address + fragment ID — this groups fragments of the same datagram into the same flow queue.
4. **Compute hash**: `clib_xxhash()` on 5-tuple (VPP's standard fast hash). IPv6 hashes over more key material (32 bytes of addresses vs 8) but the xxhash output is the same 32-bit value.
5. **Set index**: `hash % (CAKE_QUEUES / CAKE_SET_WAYS)` = set base.
6. **Probe 8 ways**: Check `flow_tags[base..base+7]` for matching hash tag.
   - **Hit**: Use existing flow.
   - **Miss, empty slot**: Allocate new flow in that slot.
   - **Miss, full set**: Evict oldest flow (LRU within set), reassign.

This avoids bihash overhead for the hot path — the flow table is a fixed-size array per tin with O(1) set-associative lookup. The 8-way set reduces collision probability to <0.01% for typical subscriber flow counts (<100 concurrent flows).

**SIMD optimization**: The 8-way tag comparison can use a single `u8x8` vector compare on architectures with NEON/SSE. On x86 with AVX2, 8 tag comparisons become one `_mm256_cmpeq_epi32` + `_mm256_movemask_epi8`.

### 4.7 DiffServ Tin Mapping

CAKE maps DSCP values to tins. The mapping is a 64-entry lookup table (DSCP is 6 bits). DSCP extraction is IP-version-aware:

- **IPv4**: `dscp = ip4->tos >> 2` (bits 7-2 of the ToS byte)
- **IPv6**: `dscp = (ip6->ip_version_traffic_class_and_flow_label >> 22) & 0x3f` (bits 27-22 of the first 32-bit word, which contains the 8-bit traffic class in bits 20-27)

The same 64-entry lookup table is used for both IPv4 and IPv6 — DSCP semantics are identical across IP versions (RFC 2474).

```c
/* diffserv4 mode (default for BNG) — 4 tins */
static const u8 cake_dscp_to_tin_diffserv4[64] = {
  [0]  = 0,  /* BE → Best Effort */
  [8]  = 0,  /* CS1 → Best Effort (bulk) */
  [10] = 0, [12] = 0, [14] = 0,  /* AF1x → Best Effort */
  [16] = 1,  /* CS2 → Video Streaming */
  [18] = 1, [20] = 1, [22] = 1,  /* AF2x → Video Streaming */
  [24] = 1,  /* CS3 → Video Streaming */
  [26] = 2, [28] = 2, [30] = 2,  /* AF3x → Low Latency */
  [32] = 2,  /* CS4 → Low Latency */
  [34] = 2, [36] = 2, [38] = 2,  /* AF4x → Low Latency */
  [40] = 3,  /* CS5 → Voice */
  [46] = 3,  /* EF → Voice */
  [48] = 3,  /* CS6 → Voice */
  [56] = 3,  /* CS7 → Voice */
};
/* Tin weights: BE=16, Video=4, LowLat=1, Voice=1 (bandwidth share) */
/* Tin priorities: Voice > LowLat > Video > BE (strict in shaped mode) */
```

Modes supported:
- **besteffort**: 1 tin, all traffic equal.
- **diffserv3**: 3 tins (Bulk, Best Effort, Voice). Good for residential.
- **diffserv4**: 4 tins (Bulk/BE, Video, Low Latency, Voice). Default.
- **diffserv8**: 8 tins (full precedence mapping). For business services.

### 4.8 COBALT AQM Algorithm

COBALT combines CoDel (for responsive TCP flows) and BLUE (for unresponsive UDP flows):

**CoDel component:**
1. On dequeue, compute sojourn time: `sojourn = now - enqueue_timestamp`.
2. If `sojourn < target` (default 5ms): exit dropping state, reset count.
3. If `sojourn >= target` for longer than `interval` (default 100ms): enter dropping state.
4. In dropping state: drop/ECN-mark at increasing frequency: `next_drop = now + interval / sqrt(count)`.
5. The `rec_inv_sqrt` field caches the Newton-Raphson approximation of `1/sqrt(count)` for efficiency.

**BLUE component:**
1. Track `drop_prob` (u16, 0-65535 maps to 0.0-1.0).
2. On queue overflow or persistent delay: `drop_prob += BLUE_FREQ_INCREASE` (every `blue_timer` interval).
3. On queue drain below target: `drop_prob -= BLUE_FREQ_DECREASE`.
4. Per-dequeue: generate random u16 via `clib_random_u32()` (proper PRNG, seeded per-thread — NOT `now_us ^ bi` which is predictable and causes synchronized drops), drop if `random < drop_prob`.
5. BLUE catches unresponsive flows that don't react to CoDel signals.

**Combined logic:**
```
should_drop = codel_should_drop(sojourn, now) OR blue_should_drop(random, drop_prob)
if (should_drop && ecn_capable):
    mark_ecn(packet)  // CE codepoint
    should_drop = false
if (should_drop):
    drop(packet)
```

**VPP adaptation:**
- `enqueue_timestamp` stored in `vnet_buffer2(b)->qos.bits` (repurposed, 32-bit, microsecond resolution sufficient for 5ms target).
- `clib_cpu_time_now()` provides sub-nanosecond cycle counter; convert to microseconds via precomputed shift.
- Newton-Raphson `rec_inv_sqrt` uses the same lookup table as Linux CAKE (first 16 values cached, compute beyond).
- **ECN (dual-stack)**: The ECN bits occupy the same position within the traffic class / ToS byte for both IP versions (bits 1-0). For IPv4: `ip4->tos & 0x03`, CE marking via `ip4_header_checksum_update()` (incremental, not full recompute). For IPv6: `(ntohl(ip6->ip_version_traffic_class_and_flow_label) >> 20) & 0x03`, CE marking updates the traffic class field directly (no checksum — IPv6 has none). Both paths MUST be implemented from day 1 — IPv6 is a first-class requirement, not a follow-up.

### 4.9 Deficit Round Robin Scheduling

Within each tin, flows are scheduled via weighted DRR:

1. **Flow lists**: Three doubly-linked lists per tin: `new_flows`, `old_flows`, `decaying_flows`.
2. **New flow arrives**: Added to `new_flows` list with full quantum.
3. **Dequeue priority**: `decaying_flows` → `new_flows` → `old_flows`.
4. **Deficit accounting**: Each flow gets `deficit += quantum` per round. Dequeue packets until `deficit < 0` or queue empty.
5. **Flow transitions**:
   - `new → old`: After first deficit exhaustion.
   - `old → decaying`: When queue empties but flow recently active.
   - `decaying → removed`: After decay timeout.
6. **Sparse flow optimization**: Flows with ≤1 packet in queue get immediate service with bonus quantum (no DRR overhead for interactive traffic).

**Triple isolation adaptation**: The quantum for each flow is adjusted by the number of flows from the same source/destination host: `flow_quantum = base_quantum / max(src_host_flows, dst_host_flows)`. This prevents a single host with many flows from getting more than its fair share.

### 4.10 Token Bucket Shaping

Rate enforcement uses a dual token bucket (per-tin and global):

```c
/* Per-packet cost calculation (with overhead compensation) */
static inline u32
cake_overhead_adjust(cake_sched_t *cs, u32 pkt_len)
{
  i32 adjusted = (i32)pkt_len + cs->overhead_bytes;
  if (adjusted < cs->mpu)
    adjusted = cs->mpu;
  if (cs->atm_mode == 1)  /* ATM cell rounding */
    adjusted = ((adjusted + 47) / 48) * 53;
  return (u32)adjusted;
}

/* Shaper check */
u64 cost_ns = (u64)adjusted_len * cs->rate_ns_per_byte;
cs->global_shaper_time_ns += cost_ns;
tin->tin_shaper_time_ns += (u64)adjusted_len * tin->tin_rate_ns_per_byte;
```

The dequeue node only transmits when `now_ns >= global_shaper_time_ns`. A failsafe clamps `global_shaper_time_ns` to `now + 1.5 * interval` to prevent clock drift accumulation.

### 4.11 Overhead Compensation for DSL/PON Subscribers

Critical for BNG deployments where subscribers are on DSL (ATM) or GPON (GEM):

| Mode | Overhead | Description |
|------|----------|-------------|
| `none` | 0 | Raw Ethernet (datacenter, direct fiber) |
| `ethernet` | +14 | Ethernet header (already in packet but needed if shaping at L3) |
| `docsis` | +18 | Cable modem DOCSIS framing |
| `dsl-pppoe-ptm` | +27 | PPPoE over PTM (VDSL2 typical): +2 PTM + 6 SAP + 5 SNAP + 14 Ethernet |
| `dsl-pppoe-atm` | +32 | PPPoE over ATM (ADSL typical): +8 AAL5 + 10 LLC + 14 Ethernet, ATM cell rounding |
| `gpon` | +4 | GPON GEM framing overhead |

ATM mode applies 48→53 byte cell tax: each packet is rounded up to the next 48-byte boundary, then 5 bytes of ATM overhead per cell are added. This accurately models the actual link capacity consumed.

### 4.12 Enqueue Path — Vector Processing

The enqueue node processes a vector of packets in the standard VPP dual-loop:

```
cake_enqueue_node(frame):
  for each packet batch (2 at a time, with 2-ahead prefetch):
    0. If CAKE_BUFFER_F_SCHEDULED flag set → clear flag, vnet_feature_next(), continue
       (this is a dequeued packet re-entering the arc — pass through)
    1. Check sw_if_index[VLIB_TX] → scheduler lookup
       - If no scheduler for this interface → vnet_feature_next(), continue
    2. Detect IP version (first nibble: 4=IPv4, 6=IPv6)
    3. Read DSCP from IP header (IPv4: tos>>2, IPv6: traffic class>>2) → tin lookup
       - Lazily allocate tin if first packet to this DSCP class
    4. Extract 5-tuple (IPv6: walk extension headers to find L4) → hash → set-associative flow lookup
       - If flow miss + set full → evict LRU flow
    5. Store enqueue timestamp: vnet_buffer2(b)->qos.bits = now_us (32-bit µs)
    6. Append buffer index to flow queue (vec_add1)
    7. Update backlog: flow.backlog_bytes += packet_len
    8. Update buffer_usage: sched.buffer_usage += truesize; sched.queued_buffers++
    9. Admission control: if buffer_usage > buffer_limit OR global_queued_buffers > max_queued_buffers
       → drop from longest queue (steal from fattest flow), vlib_buffer_free_one()
    10. Update flow state: if new flow → add to new_flows list
    11. Mark scheduler as active in thread bitmap
  end
  /* Scheduled packets are CONSUMED — not forwarded to any next node.
   * Buffer indices are owned by the scheduler. Enqueue returns frame->n_vectors
   * but enqueues zero buffers to next for consumed packets. */
```

**Key vectorization points:**
- Step 1: `sw_if_index` lookup vectorized — batch load `sw_if_index[VLIB_TX]` for all packets, partition into scheduled/passthrough sets.
- Step 2-3: IP version detection + DSCP extraction — branch-free: load first 4 bytes, shift for version nibble, then version-dependent DSCP mask. Four packets in parallel with prefetch.
- Step 4: Hash computation — `clib_xxhash` is already SIMD-friendly. IPv6 hashes more key material but same output path.

### 4.13 Dequeue Path — Polling

The dequeue node runs as a `VLIB_NODE_TYPE_INPUT` node:

```
cake_dequeue_node(frame):
  now_ns = vlib_time_now(vm) * 1e9
  budget = VLIB_FRAME_SIZE  /* max 256 packets per invocation */

  for each active scheduler (from active_bitmap):
    if now_ns < sched.global_shaper_time_ns:
      continue  /* shaper not ready */

    while budget > 0:
      /* Tin selection: strict priority in shaped mode */
      tin = select_active_tin(sched)  /* highest priority with packets */
      if tin == NULL:
        clear_active_bit(sched)
        break

      if now_ns < tin.tin_shaper_time_ns:
        try next lower priority tin (or break if none)

      /* Flow selection: DRR within tin */
      flow = select_flow(tin)  /* decaying → new → old */
      if flow == NULL:
        continue to next tin

      /* Dequeue one packet */
      bi = flow.queue[flow.head++]
      b = vlib_get_buffer(vm, bi)

      /* COBALT AQM check */
      enqueue_time_us = vnet_buffer2(b)->qos.bits
      sojourn_us = now_us - enqueue_time_us
      if cobalt_should_drop(flow, sojourn_us, now_ns):
        if ecn_capable(b) && !already_marked:
          set_ecn_ce(b)
        else:
          drop(b)
          continue

      /* Overhead-adjusted length for shaper */
      adj_len = cake_overhead_adjust(sched, packet_len)

      /* Update shapers */
      sched.global_shaper_time_ns += adj_len * sched.rate_ns_per_byte
      tin.tin_shaper_time_ns += adj_len * tin.tin_rate_ns_per_byte

      /* Deficit accounting */
      flow.deficit -= adj_len
      if flow.deficit <= 0:
        move_to_next_flow(tin, flow)

      /* Add to output vector */
      to_next[n_dequeued++] = bi
      budget--

    /* Clamp shaper: prevent runaway drift */
    sched.global_shaper_time_ns = min(sched.global_shaper_time_ns,
                                       now_ns + interval_ns * 3 / 2)

  /* Batch output: collect all dequeued buffer indices into a local vector first,
   * then do a single vlib_get_next_frame / vlib_put_next_frame outside the loop.
   * Per-packet frame acquisition is prohibited — it defeats vector processing. */
  bulk re-inject collected buffers to interface-output arc with CAKE_BUFFER_F_SCHEDULED flag
```

**Output path**: Dequeued packets are re-injected into the `interface-output` feature arc with `CAKE_BUFFER_F_SCHEDULED` set in the buffer flags. When the enqueue node encounters a packet with this flag, it clears the flag and calls `vnet_feature_next()` to continue through remaining output features (span-output, ipsec-if-output, etc.). This ensures no output features are skipped and the feature config index used is always live at the time of actual transmission — not a stale one from when the packet was originally enqueued.

### 4.14 Per-Thread Isolation

VPP's TX queue model allows multiple worker threads to transmit to the same interface via different TX queues, and TX queue placement can change at runtime via `sw_interface_set_tx_placement`. The scheduler must match this model.

**Design: per-thread, per-interface scheduler instances.** Each worker thread that can send to a scheduler-enabled interface gets its own `cake_sched_t` instance with independent flow tables, shapers, and queues. State is keyed by `(sw_if_index, thread_index)`:

- `cake_main.per_thread[thread_index].schedulers` — pool of `cake_sched_t` for this thread.
- `cake_main.per_thread[thread_index].active_bitmap` — bitmap of schedulers with queued packets.
- `cake_main.sched_index_by_sw_if_index[sw_if_index][thread_index]` — maps interface + thread to pool index.

**Rate splitting:** Each per-thread instance is configured with `total_rate / n_threads_for_interface`. This is approximate (threads may not be equally loaded) but avoids cross-thread locking. The aggregate shaper across all threads converges to the configured rate.

**TX queue placement changes:** When TX queue placement changes for an interface, the scheduler drains and frees instances on threads that no longer have queues for that interface, and creates new instances on newly assigned threads. This is a control-plane operation (not hot path) — it happens via the binary API or CLI, not per-packet.

**Enqueue thread affinity:** The enqueue node runs on whatever worker thread processes the packet. Since it hooks the `interface-output` feature arc, VPP's existing TX thread affinity ensures the packet is already on the correct thread in the common case. No cross-thread handoff is needed in typical BNG deployments.

### 4.15 Binary API

```
/* osvbng_qos_sched.api */

/** Enable/disable per-subscriber CAKE scheduler */
autoreply define cake_sched_enable_disable {
  u32 client_index;
  u32 context;
  vl_api_interface_index_t sw_if_index;
  bool is_enable;

  /* Rate (bytes/sec). 0 on disable. */
  u64 rate_bytes_per_sec;

  /* Tin mode: 0=besteffort, 1=diffserv3, 2=diffserv4, 3=diffserv8 */
  u8 tin_mode;

  /* Overhead compensation */
  i16 overhead_bytes;       /* per-packet add/subtract */
  u8 atm_mode;             /* 0=none, 1=ATM, 2=PTM */
  u8 mpu;                  /* minimum packet unit */

  /* Buffer limit (bytes). 0 = auto-calculate from rate * RTT. */
  u32 buffer_limit;

  /* Target RTT for AQM (microseconds). 0 = 5000 (5ms default). */
  u32 target_us;

  /* CoDel interval (microseconds). 0 = 100000 (100ms default). */
  u32 interval_us;

  /* Flags */
  u32 flags;  /* CAKE_FLAG_WASH_DSCP=1, CAKE_FLAG_ACK_FILTER=2, CAKE_FLAG_SPLIT_GSO=4 */
};

/** Dump per-subscriber scheduler state */
define cake_sched_dump {
  u32 client_index;
  u32 context;
  vl_api_interface_index_t sw_if_index;  /* ~0 for all */
};

define cake_sched_details {
  u32 context;
  vl_api_interface_index_t sw_if_index;
  u64 rate_bytes_per_sec;
  u8 tin_mode;
  u8 tin_cnt;
  u32 buffer_usage;
  u32 buffer_limit;

  /* Per-tin stats (up to 8 tins) */
  u64 tin_packets[8];
  u64 tin_bytes[8];
  u64 tin_drops[8];
  u64 tin_ecn_marks[8];
  u32 tin_peak_delay_us[8];
  u32 tin_avg_delay_us[8];
  u32 tin_sparse_flows[8];
  u32 tin_bulk_flows[8];
};

/** Reset scheduler statistics */
autoreply define cake_sched_reset_stats {
  u32 client_index;
  u32 context;
  vl_api_interface_index_t sw_if_index;
};
```

### 4.16 ECN Handling

ECN support follows RFC 3168 and RFC 8311:

1. **Check ECN capability**: IP header ECT(0) or ECT(1) bits set.
2. **Mark instead of drop**: When COBALT decides to drop, if packet is ECN-capable, set CE (Congestion Experienced) codepoint instead of dropping.
3. **Non-ECT packets**: Always dropped (never marked) — they didn't opt into ECN.
4. **Statistics**: Track ECN marks separately from drops per tin.

### 4.17 WASH Mode (DSCP Reset)

When `CAKE_FLAG_WASH_DSCP` is set, DSCP is zeroed on egress after tin classification. This prevents downstream equipment from re-classifying based on the subscriber's chosen DSCP while still using DSCP for internal prioritization. For IPv4, this clears `ip4->tos` bits 7-2 (preserving ECN bits 1-0) and recomputes the header checksum. For IPv6, this clears the DSCP bits in the traffic class field (preserving ECN bits). IPv6 has no header checksum to update.

## 5. Configuration

### 5.1 Go-Side Configuration Schema

Extension to the existing QoS policy in `pkg/config/qos/qos.go`:

```yaml
qos-policies:
  residential-100m:
    cir: 100000                      # existing policer fields (used when scheduler not enabled)
    conform:
      action: transmit
    exceed:
      action: drop
    violate:
      action: drop
    scheduler:                       # NEW: CAKE scheduler config
      enabled: true                  # enable scheduling (replaces egress policer)
      rate: 100000                   # rate in kbps (overrides cir for shaping)
      tin-mode: diffserv4            # besteffort | diffserv3 | diffserv4 | diffserv8
      overhead:
        mode: dsl-pppoe-ptm         # none | ethernet | docsis | dsl-pppoe-ptm | dsl-pppoe-atm | gpon
        manual-bytes: 0             # manual override (adds to mode-derived overhead)
        mpu: 64                     # minimum packet unit
      aqm:
        target-ms: 5                # CoDel target (default 5ms)
        interval-ms: 100            # CoDel interval (default 100ms)
      buffer-limit: 0               # bytes (0 = auto: rate * interval * 1.5)
      wash-dscp: false              # zero DSCP on egress
      ack-filter: false             # filter redundant pure ACKs
      split-gso: true               # split GSO/GRO segments before queuing
```

### 5.2 Service Group Integration

```yaml
service-groups:
  residential-ftth:
    qos:
      egress-policy: residential-100m    # policy with scheduler.enabled=true
      ingress-policy: upload-50m         # ingress remains policer-only
```

When `scheduler.enabled=true` in the egress policy, the Go component calls `CakeSchedEnableDisable` instead of creating an egress VPP policer. The ingress direction is unaffected (continues to use policer).

### 5.3 AAA Integration

| Attribute | Description |
|-----------|-------------|
| `qos.egress-policy` | Can reference a scheduler-enabled policy |
| `qos.download-rate` | Ad-hoc rate. If service group policy has `scheduler.enabled=true`, creates ad-hoc scheduler at this rate with default parameters. |

## 6. File Plan

### VPP Plugin: `src/`

| File | Purpose |
|------|---------|
| `src/CMakeLists.txt` | Build config: `add_vpp_plugin(osvbng_qos_sched SOURCES ... MULTIARCH_SOURCES cake_enqueue.c cake_dequeue.c cake_hash.c)` |
| `src/osvbng_qos_sched.api` | Binary API definitions (enable/disable, dump, reset) |
| `src/osvbng_qos_sched.h` | Core data structures: `cake_sched_t`, `cake_tin_t`, `cake_flow_t`, `cake_main_t`, inline helpers |
| `src/osvbng_qos_sched.c` | Plugin init, API handlers, feature arc registration, per-interface enable/disable, CLI commands |
| `src/cake_enqueue.c` | `cake-enqueue` node: MULTIARCH, interface-output feature arc, dual-stack classification + queuing (VLIB_NODE_FN) |
| `src/cake_dequeue.c` | `cake-dequeue` node: MULTIARCH, INPUT polling node, shaper + DRR + AQM dequeue (VLIB_NODE_FN) |
| `src/cake_hash.c` | MULTIARCH: Flow hashing + set-associative lookup, IPv4/IPv6 5-tuple extraction, DSCP→tin mapping tables |
| `src/cake_cobalt.c` | COBALT AQM: CoDel + BLUE combined algorithm, rec_inv_sqrt, ECN marking (IPv4 + IPv6) |
| `src/cake_overhead.c` | Overhead compensation: ATM cell rounding, PTM, mode presets |

### Go Side: [osvbng](https://github.com/veesix-networks/osvbng) (modifications)

| File | Action | Purpose |
|------|--------|---------|
| `pkg/config/qos/scheduler.go` | Create | `SchedulerConfig` struct, overhead mode enum, validation |
| `pkg/config/qos/qos.go` | Modify | Add `Scheduler *SchedulerConfig` field to `Policy` |
| `pkg/vpp/binapi/qos_sched/` | Create (generated) | Go bindings for `osvbng_qos_sched.api` |
| `pkg/southbound/vpp/qos_sched.go` | Create | VPP adapter: `EnableScheduler()`, `DisableScheduler()`, `DumpScheduler()` |
| `pkg/southbound/sessions.go` | Modify | Add `EnableScheduler()` / `DisableScheduler()` to `Sessions` interface |
| `internal/subscriber/component.go` | Modify | If egress policy has `scheduler.enabled`, call `EnableScheduler()` instead of `ApplyQoS()` for egress |
| `pkg/handlers/show/qos/scheduler.go` | Create | Show handler for `qos.scheduler` — per-subscriber scheduler state |
| `pkg/models/qos.go` | Modify | Add `SchedulerInfo` model for show output |
| `docs/configuration/qos.md` | Modify | Document scheduler configuration, overhead modes |

## 7. Implementation Order

### Phase 1: Plugin Skeleton + Shaper Only (no AQM, no DiffServ)

**Goal:** Single tin, single FIFO per subscriber, token-bucket shaping only. Proves the enqueue→store→dequeue→output pipeline works.

1. Create `osvbng-vpp-plugin-qos/` repo with CMakeLists, plugin.c, API file.
2. Implement `cake_sched_t` with single tin, single flow (FIFO mode).
3. Implement `cake-enqueue` node on `interface-output` arc — store buffers in FIFO.
4. Implement `cake-dequeue` INPUT node — drain FIFO at configured rate.
5. Implement `CakeSchedEnableDisable` API handler.
6. CLI: `set cake scheduler <interface> rate <kbps>` / `show cake scheduler [<interface>]`.
7. **Testable:** Enable scheduler on an interface at 100 Mbps. iperf3 should show ~100 Mbps throughput with smooth pacing (no sawtooth). Latency under load should be bounded by buffer size.

### Phase 2: Per-Flow Queuing + DRR

**Goal:** Flow classification and fair queuing within a single tin.

1. Implement flow hashing (`cake_hash.c`) with set-associative lookup.
2. Implement per-flow queues in `cake_flow_t`.
3. Implement DRR scheduling (new/old/decaying lists).
4. Implement sparse flow optimization.
5. Implement buffer limit enforcement (drop from longest queue).
6. **Testable:** Run 10 concurrent iperf3 flows to one subscriber. Each flow should get ~1/10 of the rate. A single aggressive flow should not starve others.

### Phase 3: COBALT AQM

**Goal:** Active queue management to control latency.

1. Implement CoDel algorithm in `cake_cobalt.c`.
2. Implement BLUE algorithm.
3. Implement combined COBALT drop/mark decision.
4. Implement ECN marking (CE codepoint).
5. Implement `rec_inv_sqrt` Newton-Raphson cache.
6. Store enqueue timestamp in buffer metadata.
7. **Testable:** Generate sustained load to one subscriber. Measure RTT via ping alongside: should stay near target (5ms) instead of growing unbounded. Compare with policer-only (latency should be dramatically lower under load).

### Phase 4: DiffServ Tins

**Goal:** Priority traffic classes.

1. Implement DSCP→tin mapping tables for all modes.
2. Implement per-tin shaping (bandwidth shares).
3. Implement tin selection in dequeue (strict priority in shaped mode).
4. Implement WASH mode.
5. **Testable:** Send EF-marked VoIP traffic alongside bulk download. VoIP latency should remain <1ms even at full subscriber rate. Bulk traffic gets remaining bandwidth.

### Phase 5: Overhead Compensation + Modes

**Goal:** Accurate shaping for DSL/PON subscribers.

1. Implement ATM cell rounding.
2. Implement PTM overhead.
3. Implement overhead mode presets.
4. Implement MPU enforcement.
5. **Testable:** Configure `dsl-pppoe-atm` mode at 24 Mbps (typical ADSL2+). Actual throughput should match physical line rate accounting for ATM cell tax. Without compensation, shaping would be too generous by ~10%.

### Phase 6: Triple Isolation + Host Fairness

**Goal:** Per-host fairness prevents multi-flow hosts from dominating.

1. Implement host tracking table (src/dst hash → host entry).
2. Implement quantum adjustment by host flow count.
3. **Testable:** Two hosts behind same subscriber CPE (NAT). Host A runs 10 flows, host B runs 1 flow. Both hosts should get ~50% of bandwidth (not 10:1).

### Phase 7: Go Integration

**Goal:** Wire into osvbng subscriber lifecycle.

1. Generate Go binapi bindings.
2. Implement `SchedulerConfig` struct and validation.
3. Implement southbound adapter.
4. Wire into subscriber activation (scheduler replaces egress policer when enabled).
5. Implement show handler.
6. Update documentation.
7. **Testable:** Full end-to-end: configure scheduler-enabled policy, bring up subscriber, verify scheduling active via `show cake scheduler`, run traffic test.

### Phase 8: ACK Filtering + GSO Splitting (optional)

**Goal:** Reduce ACK-induced queuing and handle offloaded segments.

1. Implement ACK filtering (detect redundant pure ACKs, drop older ones).
2. Implement GSO segment splitting before queuing.
3. **Testable:** Asymmetric link (fast down, slow up). With ACK filter, download throughput should improve slightly as ACK queue pressure is reduced.

## 8. Attribute Mappings

### Overhead Mode → Parameters

| Mode | `overhead_bytes` | `atm_mode` | `mpu` |
|------|-----------------|------------|-------|
| `none` | 0 | 0 | 0 |
| `ethernet` | 14 | 0 | 64 |
| `docsis` | 18 | 0 | 64 |
| `dsl-pppoe-ptm` | 27 | 2 | 64 |
| `dsl-pppoe-atm` | 32 | 1 | 64 |
| `gpon` | 4 | 0 | 64 |

### DiffServ Mode → Tin Configuration

| Mode | Tins | Names | Rate Shares |
|------|------|-------|-------------|
| `besteffort` | 1 | BE | 100% |
| `diffserv3` | 3 | Bulk, Best Effort, Voice | 6.25%, 93.75%, 31.25% (min guarantee) |
| `diffserv4` | 4 | Bulk, Best Effort, Video, Voice | 6.25%, 50%, 25%, 18.75% |
| `diffserv8` | 8 | CS0-CS7 per precedence | Equal (12.5% each) |

Note: Tin shares describe guaranteed minimums. Unused capacity is redistributed via DRR.

### Scheduler Config → VPP API

| YAML Field | API Field | Transform |
|------------|-----------|-----------|
| `rate` | `rate_bytes_per_sec` | `rate_kbps * 1000 / 8` |
| `tin-mode` | `tin_mode` | Enum: besteffort=0, diffserv3=1, diffserv4=2, diffserv8=3 |
| `overhead.mode` | `overhead_bytes`, `atm_mode`, `mpu` | Lookup table above |
| `overhead.manual-bytes` | `overhead_bytes` | Added to mode-derived value |
| `aqm.target-ms` | `target_us` | `* 1000` |
| `aqm.interval-ms` | `interval_us` | `* 1000` |
| `buffer-limit` | `buffer_limit` | Pass through (0 = auto) |
| `wash-dscp` | `flags` | Bit 0 |
| `ack-filter` | `flags` | Bit 1 |
| `split-gso` | `flags` | Bit 2 |

## 9. Testing

### Phase 1 (Shaper)
- Enable scheduler at 100 Mbps on one interface. iperf3 TCP → verify ~100 Mbps throughput.
- Enable at 10 Mbps. Verify throughput matches. Verify pacing (no burst-then-pause pattern in tcpdump).
- Disable scheduler. Verify packets flow at line rate (no queuing).
- Enable on interface, send no traffic for 60s, then burst → verify no stale token accumulation (failsafe clamp works).

### Phase 2 (FQ + DRR)
- 10 parallel iperf3 TCP flows → each gets ~1/10 of rate (±5%).
- 1 UDP flood + 1 TCP flow → TCP gets ~50% (not starved by UDP).
- Short HTTP requests alongside bulk download → HTTP completion time near ideal (sparse flow optimization).

### Phase 3 (COBALT AQM)
- iperf3 + concurrent ping at subscriber rate → ping RTT stays near 5ms target (not 100ms+).
- ECN-capable flow → verify CE marks in received packets, zero drops.
- Non-ECN UDP flood → verify BLUE kicks in, drops proportionally.
- Compare latency under load: CAKE scheduler vs policer-only → expect 10-50x latency reduction.

### Phase 4 (DiffServ)
- EF-marked traffic (VoIP) + BE bulk → EF gets strict priority, <1ms latency.
- AF-marked traffic (video) + BE bulk → AF gets guaranteed share, low jitter.
- All BE traffic in diffserv4 mode → behaves identically to besteffort mode (no priority differentiation).

### Phase 5 (Overhead)
- ATM mode at 24 Mbps: send 64-byte packets → actual link consumption matches ATM cell-rounded rate.
- PTM mode at 100 Mbps: verify overhead bytes added to shaper calculation.
- Throughput test: with overhead compensation, subscriber gets exactly the configured rate at the application layer.

### Phase 7 (Go Integration)
- Configure scheduler-enabled policy in YAML, activate subscriber → verify `show cake scheduler` shows active scheduler.
- AAA returns `qos.download-rate=50000` with scheduler-enabled service group → verify ad-hoc scheduler at 50 Mbps.
- Release subscriber → verify scheduler state cleaned up (no memory leak).
- Live policy change (rate 100→200 Mbps) → verify scheduler updated without session drop.

## 10. Not In Scope

- **Ingress scheduling**: Only egress (download toward subscriber) is scheduled. Ingress (upload from subscriber) continues to use policers. Ingress scheduling would require intercepting on the `ip4-unicast`/`ip6-unicast` arc after sub-interface classification, which is architecturally different.
- **NAT-aware flow hashing**: Linux CAKE uses conntrack to de-NAT flow keys for hosts behind CPE NAT. This requires integration with the CGNAT plugin's session table, which is a separate effort.
- **Hardware offload**: No NIC-level scheduling offload. This is a software scheduler running in VPP's dataplane.
- **Hierarchical scheduling**: No aggregate/per-VLAN/per-OLT-port scheduling. Each subscriber gets an independent scheduler instance. H-QoS across subscribers is a separate feature.
- **BQL (Byte Queue Limits)**: Linux BQL integration is not applicable — VPP manages its own TX queues. The CAKE scheduler itself provides the queuing discipline.
- **Linux tc integration**: Not applicable — subscriber data plane traffic flows through VPP, not the Linux kernel.
- **CoA-triggered rate changes**: The API supports rate changes, but RADIUS CoA is not yet in osvbng. When CoA lands, it calls `CakeSchedEnableDisable` with the new rate.
- **Dedicated-core scheduling model**: The current design runs enqueue and dequeue on the same worker cores as DPDK RX polling (inline model). A dedicated-core model — where CAKE dequeue runs on separate cores like the old VPP HQoS — is a potential future optimization for very high throughput deployments. However, this requires careful investigation of NUMA topology (cross-socket buffer access latency, hugepage allocation per NUMA node), VPP's frame queue handoff performance across NUMA boundaries, and whether the cache penalty of cross-core buffer sharing outweighs the CPU headroom gained. This is explicitly deferred until real profiling data exists — we will not spec a cross-NUMA design without evidence that it's actually faster than the inline model.

## Acknowledgments

The algorithms and design in this spec are derived from the Linux CAKE qdisc (`sch_cake.c`), a landmark piece of work in the fight against bufferbloat. The original authors of the CAKE qdisc:

- **Dave Taht** (dave.taht@gmail.com) — Co-creator of CAKE and tireless advocate for bufferbloat solutions. Dave spent over a decade pushing the networking world to take latency seriously, co-founding the Bufferbloat Project, driving FQ-CoDel and CAKE into the Linux kernel, and evangelizing SQM to ISPs and equipment vendors. He passed away in 2024. This implementation exists because of the path he cleared. His work improved the internet for millions of people who will never know his name. It is our duty to carry Dave's name forward — every packet this scheduler paces, every millisecond of latency it eliminates, is built on the foundation he laid. The best way to honor his legacy is to ship what he spent his life advocating for: bufferbloat-free internet access for everyone.
- **Jonathan Morton** (chromatix99@gmail.com) — Primary author of the CAKE algorithm and implementation. Designed the set-associative hashing, DiffServ tin system, COBALT AQM, triple isolation, and overhead compensation that make CAKE uniquely effective for access network scheduling.
- **Toke Hoiland-Jorgensen** (toke@toke.dk) — Key contributor to CAKE and FQ-CoDel. Instrumental in getting CAKE merged into the Linux kernel mainline.
- **Sebastian Moeller** (moeller0@gmx.de) — Contributor with deep work on overhead compensation, DSL framing models, and real-world testing on access networks.
- **Kevin Darbyshire-Bryant** (kevin@darbyshire-bryant.me.uk) — Contributor to the CAKE implementation and testing.
- **Ryan Mounce** (ryan@mounce.com.au) — Contributor to CAKE development and testing.

CAKE is licensed under GPL-2.0+. This VPP plugin is a clean-room reimplementation of the algorithms described in the CAKE source code and associated publications, adapted for VPP's vector processing architecture. No code is copied from `sch_cake.c`.

**Note:** This project is primarily LLM-driven. We make every effort to ensure all references and attributions are correct and complete, but if we have missed or misattributed anyone's contribution, please open an issue or pull request and we will correct it immediately.
