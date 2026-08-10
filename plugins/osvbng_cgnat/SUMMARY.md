# osvbng-vpp-plugin-cgnat — SUMMARY

Carrier-Grade NAT (CGN, RFC 6888) VPP plugin for the osvbng BNG. Translates
subscriber-side flows from RFC 6598 shared address space (default
`100.64.0.0/10`) to operator-allocated outside addresses. PBA (Port Block
Allocation) mode and Deterministic mode.

For audit history and the architectural decisions that got us here, see
[AUDIT.md](AUDIT.md). The headline one is Finding #8 — a per-worker session
pool with frame-queue handoff was tried (the D15 amendment to osvbng-context
#153) and reverted, because handoff cost dominates translate cost in BNG-PPS
workloads.

---

## Architecture

**Single shared session pool.** Every VPP worker can run `cgnat-in2out` and
`cgnat-out2in` against the same `cm->sessions` pool. The receiving worker
processes the packet locally — no handoff, no frame queue, no cold-worker
wakeup penalty. Because RX-active workers are always hot, latency stays
sub-millisecond per translate even on a 12-worker box at low PPS.

Bihashes (`session_table_in2out`, `session_table_out2in`, `frag_aux`,
`inside_lookup`) are multi-writer-safe via VPP's per-bucket RW locks.
Bihash values are plain pool indices into `cm->sessions`.

**Cross-worker safety:** translate writes to `s->last_active`,
`s->total_pkts`, `s->total_bytes`, `s->tcp_flags`, `s->tcp_state` are
non-atomic. If two workers translate packets of the same session
concurrently, counters can under-count and TCP state can briefly mis-
compute. No crash, no translation incorrectness. If you need
counter-accurate or TCP-state-correct multi-worker behaviour, switch
counters to `__atomic_fetch_add(RELAXED)` and gate TCP state with a
per-session `clib_spinlock_t`. Per-mapping `m->lock` already covers
`next_port` / `port_reuse_timestamps[]` / `session_count` — those are
slow-path only and contention is microscopic.

---

## Datapath

### In2out (subscriber → outside)

```
subscriber pkt on subscriber sw_if (ipoe_session* / pppoe_session*)
  → ip4-unicast feature arc:
      ip4-sv-reassembly-feature        # populates vnet_buffer.ip.reass.*
      cgnat-in2out                     # feature directly (no handoff)
        ↓ session miss
      cgnat-in2out-slowpath            # port_alloc, session_create
  → ip4-lookup → ip4-rewrite → outside iface
```

### Out2in (reply → subscriber)

```
reply pkt on outside iface
  → ip4-unicast feature arc:
      ip4-sv-reassembly-feature        # populates reass.*  (WILL be CLOBBERED — see below)
  → ip4-lookup
  → FIB hit on outside-prefix → cgnat-outside DPO → cgnat-out2in
        ↓ session miss
      cgnat-out2in-slowpath            # ICMP-error inner-rewrite, fragment aux lookup
  → ip4-lookup → ip4-rewrite → subscriber iface
```

---

## Node table

| Node | VLIB type | What it does |
|---|---|---|
| `cgnat-in2out` | INTERNAL | Subscriber-side fast path. Session lookup, translate, ⟶ `ip4-lookup`. Registered as feature on `ip4-unicast` after `ip4-sv-reassembly-feature`. |
| `cgnat-in2out-slowpath` | INTERNAL | New flow: `cgnat_port_alloc` under mapping lock, `cgnat_session_create`, install in2out + out2in bihashes, translate. Also handles in2out ICMP-error inner-rewrite and non-first fragment branch. `n_next_nodes = 2` (DROP, LOOKUP only). |
| `cgnat-out2in` | INTERNAL | Outside-side fast path. Session lookup, translate, ⟶ `ip4-lookup`. Reached via the `cgnat-outside` DPO, not a feature. |
| `cgnat-out2in-slowpath` | INTERNAL | ICMP-error inner-rewrite (D4); fragment aux lookup (D14); drop with NO_SESSION otherwise. `n_next_nodes = 2`. EIF (Endpoint-Independent Filtering) outside-initiated session create is deferred. |
| `cgnat-expire-process` | PROCESS | Centralised on main thread, walks `cm->sessions` every 10s, reaps expired entries. |

The DPO type `cgnat-outside` (registered in `cgnat_dpo_module_init`) wires
outside-prefix FIB entries to `cgnat-out2in` via `cgnat_dpo_ip4_nodes[]`.

---

## State ownership

| Struct | Lives in | Mutator | Synchronisation |
|---|---|---|---|
| `cgnat_session_t` | `cm->sessions` (shared pool) | Any worker (fast path + slow path) | bihash lookup; counter writes non-atomic; per-session lock not yet added |
| `cgnat_mapping_t` | `cm->mappings` (shared pool) | Main thread (config) + any worker (port_alloc, port_free, session_count++/--) | `clib_spinlock_t m->lock` for the worker-mutated fields |
| `cgnat_pool_t` | `cm->pools` (shared pool) | Main thread only | None needed (immutable after config-apply) |
| `cgnat_frag_rewrite_t` | `cm->frag_rewrite_pool` (shared) | Any worker (slow-path session create / delete) | `cm->frag_rewrite_lock` spinlock; slow path only |
| `session_table_in2out` | bihash 16/8 on `cm` | Any worker (slow-path session create / delete) | bihash per-bucket RW |
| `session_table_out2in` | bihash 16/8 on `cm` | Same | bihash per-bucket RW |
| `frag_aux` | bihash 16/8 on `cm` | Any worker (slow-path) | bihash + `frag_rewrite_lock` |
| `inside_lookup` | bihash 8/8 on `cm` | Main thread (binapi config) | bihash per-bucket RW |

---

## Lessons learned — don't re-learn these

Captured across the audit work (see [AUDIT.md](AUDIT.md) for full details).

### `ip4-lookup` clobbers `vnet_buffer.ip.reass.l4_*_port`

`vnet/buffer.h` has a union where `flow_hash` (written by `ip4-lookup`)
aliases `reass.l4_src_port`, `reass.l4_dst_port`, `reass.ip_proto`. Any
node downstream of `ip4-lookup` that reads `reass.l4_*_port` reads garbage.

**Affects out2in fast path** (reached via DPO after `ip4-lookup`):
`cgnat_out2in_ports_from_reass` reads L4 ports directly from the packet's
L4 header, NOT from reass. Fragment / truncation / `icmp_type_or_tcp_flags`
bits live at non-overlapping offsets and remain reliable.

**In2out is unaffected** — the feature runs on the `ip4-unicast` arc
*before* `ip4-lookup`, so reass is still valid.

### Node-graph next_node dedup leaves `~0` slots → init segfault

`vlib_node_add_named_next_with_slot` dedups by target node name. If a
`.next_nodes[]` array references the same target node in two slots (e.g.
both `[DROP] = "error-drop"` and `[HAIRPIN] = "error-drop"`), the second
registration returns the existing slot and leaves the requested slot at
`~0`. `vlib_node_main_init` then dereferences that `~0` and segfaults.

**Rule:** every slot in `.next_nodes[]` MUST resolve to a unique target
node. Don't use `"error-drop"` for "this slot should be unreachable" —
either omit the slot (cap `n_next_nodes`) or route to a real distinct
node. See `cgnat-in2out-slowpath` and `cgnat-out2in-slowpath` —
both capped to `n_next_nodes = 2` for exactly this reason.

### Checksum delta polarity

`cgnat_flow_csum_calc` and `cgnat_frag_rewrite_acquire` both compute the
delta as `old - new` and translate applies via `ip_csum_add_even`. nat44-ed
uses the opposite convention (`new - old` + `ip_csum_sub_even`); either is
correct in isolation, but mixing them produces a checksum off by
`2 * delta` and every packet drops at the next hop with `InHdrErrors`.
Don't flip one without flipping the matching site.

### ICMP error inner-rewrite touches `src_port`, not `dst_port`

The inner header in an ICMP error is a copy of the ORIGINAL outbound
packet. The remote correlates the error back to its probe by
`inner.dst_port` — we must NOT rewrite that. The NATed value is
`inner.src_port` (in2out) or the symmetric flip on the o2i side.

Required for `traceroute`, `tracepath`, PMTUd to work through the NAT.

### Don't reintroduce the per-worker pool + handoff model

Tested, broken at low PPS, reverted. See [AUDIT.md](AUDIT.md) Finding #8
for the analysis. Short version: handoff costs ~30ms per packet on a
multi-worker box where the session-owning worker is cold (descheduled by
KVM between packets). nat44-ed has the same exposure; its benchmark
numbers come from setups where every worker stays hot at line rate, which
isn't a BNG-PPS profile.

If a future workload genuinely needs per-worker session locality (carrier
line rate, > 10M PPS), the handoff can come back — but only with hot-worker
benchmarks and host-side pinning / C-state disabling that aren't required
under the current model.

---

## Binapi (operator-facing)

Defined in `osvbng_cgnat.api`, handled in `osvbng_cgnat_api.c`. All handlers
run on the main thread.

| Message | Purpose |
|---|---|
| `osvbng_cgnat_pool_add_del[_v2]` | Add/del a NAT pool (block size, max blocks/sub, timeouts). `_v2` adds 5-slot `timeouts[]` with the `other` slot for non-port L4 protocols. |
| `osvbng_cgnat_pool_update[_v2]` | Mutate soft-drift fields on an existing pool. |
| `osvbng_cgnat_pool_dump` / `_details` | List configured pools. |
| `osvbng_cgnat_set_outside_fib` | Move a pool's outside VRF; rejects with `INSTANCE_IN_USE` if live sessions reference the old fib. |
| `osvbng_cgnat_pool_outside_interface_add_del` | Refcnt-enable `ip4-sv-reassembly-feature` on each outside iface. |
| `osvbng_cgnat_add_del_subscriber_mapping` | Add/del a subscriber's (inside_ip, fib) → (outside_ip, port_block_start, port_block_end). |
| `osvbng_cgnat_mapping_dump` | List subscriber mappings. |
| `osvbng_cgnat_add_del_bypass_prefix` | Add a FIB drop-source for prefixes that should never be NATed. |
| `osvbng_cgnat_session_dump_v2` | Paginated session dump with filtering by inside_ip / outside_ip / remote_ip / ports / proto. Cursor is a plain `cm->sessions` pool index. |
| `osvbng_cgnat_session_count` | Sum of live sessions. |
| `osvbng_cgnat_clear_sessions` | Reap all sessions for a pool / inside_ip / inside_fib. |

---

## Error counters

| Counter | Increments when | Indicates |
|---|---|---|
| `TRANSLATED` | every successfully NATed packet | normal |
| `NO_MAPPING` | in2out, packet's inside_ip not in any mapping | unmapped subscriber |
| `NO_SESSION` | out2in lookup miss with no recovery | unsolicited reply or stale outside packet |
| `SESSION_CREATE` | slow path created a new session | normal first-packet |
| `PORT_EXHAUSTED` | `cgnat_port_alloc` returned 0 (block full, all in cooldown) | subscriber needs more port blocks or `block-size` is too small |
| `SESSION_LIMIT` | per-subscriber session cap hit | tune `max-sessions-per-subscriber` |
| `BYPASSED` | packet matched a bypass prefix | normal for operator-configured exceptions |
| `NO_POOL` | mapping's pool_index dangling | reconciler bug or torn-down pool with active sessions |
| `COOLDOWN` | port_alloc skipped a port in RFC 6056 reuse cooldown | normal, informational |
| `NO_REASS_METADATA` | sv-reass didn't populate | sv-reass misconfig; fail-closed drop |
| `FRAGMENT_DROP` | non-first IP fragment with no aux record | mostly the sentinel for routing to slowpath; real drops only if the aux record was already evicted |
| `BAD_ICMP_TYPE` | ICMP type is neither echo nor error | drop early instead of creating a (0,0,ICMP) degenerate session |

---

## Build / test

- `make build-release` (in the plugin tree) — builds the `.so` and copies it to
  `../osvbng/test-infra/vpp-plugins/`.
- `make docker-local` (in the osvbng tree) — bakes the updated `.so` into the
  BNG container image.
- `scripts/run-qa-tests.sh -t 08-cgnat-ipoe-pba -r 1` — canonical QA pass for
  the IPoE PBA path. Bidirectional UDP and raw-TCP CGN streams validated
  end-to-end. Currently passes at any worker count (1 or 12 verified).

---

## Open follow-ups

1. **EIF (Endpoint-Independent Filtering) origination** — out2in slowpath
   should create a new session from an outside-initiated packet when the
   pool's filtering mode allows. Currently drops with NO_SESSION.
2. **Deterministic-mode outside-initiated origination** — `cgnat_det_reverse`
   is wired but slow-path needs the subscriber's `sw_if_index` (best
   resolved in the Go reconciler).
3. **Hairpinning** — packets whose dst falls inside the pool's outside
   prefix should be hairpinned back as out2in rather than escaping to FIB.
4. **ALG packet inspection** — FTP / SIP / H.323 / TFTP / PPTP. `alg:`
   config currently no-ops with a WARN log.
5. **Per-protocol LRU eviction** — opportunistic eviction when a port block
   fills. Currently rejects with `PORT_EXHAUSTED`.
6. **Per-session lock + atomic counters** — for accurate TCP state / counter
   behaviour under genuine cross-worker contention (see "Cross-worker safety"
   above). Not needed for current correctness, ship when the workload
   exercises it.

---

## References

- RFC 6888 — Common Requirements for Carrier-Grade NATs
- RFC 6056 — Port Randomization
- RFC 6598 — Shared Address Space
- RFC 7422 — Deterministic Address Mapping (CGN logging reduction)
- RFC 5382 — TCP behavioural requirements for NAT
- VPP `nat44-ed` plugin — `vpp/src/plugins/nat/nat44-ed/`. Borrowed liberally
  for the audit work. Differs from us mainly in the per-worker pool + handoff
  architecture which we deliberately don't use (see Finding #8 in AUDIT.md).
