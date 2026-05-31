# nat44-ed parity audit

A line-by-line audit of the cgnat plugin against the VPP `nat44-ed` plugin
(reference: `vpp/src/plugins/nat/nat44-ed/` at v26.06). The aim is to surface
every place we lifted nat44-ed's structure but ad-hoc'd a per-protocol detail
and ended up with subtly wrong behaviour. nat44-ed is treated as the spec.

Plugin HEAD at audit start: `e13ce1a fix(handoff): out2in handoff reads ICMP
echo_id ...`.

Audit status legend:

- **match** — semantics line up with nat44-ed.
- **divergent-OK** — different idiom, same outcome, intentional.
- **divergent-BUG** — different idiom, wrong outcome.
- **missing** — nat44-ed has a helper or check we don't; some are
  defensive-nice-to-have, some are real gaps.

---

## Pair 1: csum helpers

`nat44_ed.c::nat_6t_l3_l4_csum_calc` vs `osvbng_cgnat_session.c::cgnat_flow_csum_calc`.

| nat44-ed | ours | status |
|---|---|---|
| `delta = add(new) - sub(old)` → `delta = new - old` | `delta = sub(new) + add(old)` → `delta = old - new` | divergent-OK |
| applied via `sub_even(old_csum, delta)` | applied via `add_even(old_csum, delta)` | divergent-OK |
| net result: `old_csum + (old - new)` | net result: `old_csum + (old - new)` | match |

Both produce the standard one's-complement 16-bit-word-replace incremental
checksum update. The choice of convention is arbitrary but **must be self-
consistent across every csum computation + apply pair in the plugin** — see
Finding #1 (fragment csum polarity is the place this got broken).

## Pair 2: ICMP lookup helper

`lib/inlines.h::nat_get_icmp_session_lookup_values` vs (no equivalent — inline
reads at 3 sites in our code).

| concern | nat44-ed | ours | status |
|---|---|---|---|
| ICMP echo regular | reads `reass.l4_src_port` AND `reass.l4_dst_port` (sv-reass writes both to `echo_id`) → key `(saddr, daddr, echo_id, echo_id, ICMP, fib)` | reads `reass.l4_src_port` only for in2out fast; reads from L4 header for out2in fast / handoff (ip4-lookup clobbers reass for o2i path) → key `(saddr, daddr, echo_id, 0, ICMP, fib)` | divergent-OK (self-consistent: install + lookup both use dst_port=0) |
| ICMP error inner-tuple parse | helper returns inner.dst→saddr, inner.src→daddr, inner ports/id swapped (so the outer error keys against the original session) | inline in slowpath bodies — same logic, identical for in2out and out2in slowpaths | match |
| BAD_ICMP_TYPE (not echo, not error) | drops with `BAD_ICMP_TYPE` error | falls through with `src_port=0, dst_port=0`; in slow path tries to allocate a port and create a session with proto=ICMP | divergent-BUG (Finding #4) |
| out2in handoff inner-tuple route | uses helper to compute the session-owning worker via bihash lookup on inner tuple | only handles echo request/reply at handoff; ICMP errors fall through to content hash → can land on wrong worker | divergent-BUG (Finding #2) |

## Pair 3: translate helpers

`nat44_ed.c::nat_6t_flow_ip4_translate` (with `is_icmp_inner_ip4`,
`skip_saddr_rewrite`) and `nat_6t_flow_icmp_translate` vs our
`cgnat_in2out_translate` + `cgnat_out2in_translate` + inline ICMP-error inner
rewrites in `cgnat_out2in_slowpath_node` and `cgnat_in2out_slowpath_node`.

| nat44-ed feature | ours | status |
|---|---|---|
| Direction-symmetric translate via `is_i2o` flag | Two separate functions per direction | divergent-OK |
| ICMP error: `skip_saddr_rewrite` on o2i when outer src != rewrite.saddr (router-on-path) | We never rewrite outer src on o2i (translate is direction-specific), implicit equivalent | match |
| Outer ICMP error recompute from scratch via `ip_incremental_checksum_buffer` | Same approach (recompute from scratch) | match |
| **Inner ICMP echo_id rewrite ALSO updates `inner_icmp->checksum` incrementally** | We rewrite `inner_echo->identifier` but DO NOT update `inner_icmp->checksum`. Outer ICMP csum is recomputed (covers the byte change) but the inner ICMP's own checksum is stale relative to its data. Strict stacks will reject. | divergent-BUG (Finding #3) |
| Inner IP csum incrementally updated using flow delta | Same | match |

## Pair 4: worker-index helpers (handoff)

`nat44_ed.c::nat44_ed_get_in2out_worker_index` /
`nat44_ed_get_out2in_worker_index` vs `osvbng_cgnat_handoff.c::cgnat_handoff_fn_inline`.

| nat44-ed feature | ours | status |
|---|---|---|
| In2out: hash on `(src_ip, fib)`, then optionally also do bihash lookup for active flow / dst-NAT to override hash | Just hash on `(inside_ip, fib)`. No bihash lookup. | divergent-OK (in2out is determined by inside_ip hash — both handoff and slow path use the same hash, so they always agree) |
| Out2in: ICMP echo/error — parse via `nat_get_icmp_session_lookup_values`, then bihash lookup on the resulting tuple | Handles ICMP echo (parses echo_id from L4); does NOT parse ICMP errors → content-hash fallback can land on wrong worker | divergent-BUG (Finding #2) |
| Out2in TCP/UDP: bihash lookup, route to owner; fall back to content hash on miss | Same | match (post-`0e6feeb` fix) |
| **Cache `session_index` in `vnet_buffer2(b)->nat.cached_session_index`** so receiver skips its own bihash lookup | We don't cache; receiving worker re-does the bihash lookup | missing (Finding #5 — pure perf, ~50% fewer bihash ops per handoff) |

## Pair 5: fast-path / slow-path node bodies

`nat44_ed_in2out.c::nat44_ed_in2out_fast_path_node_fn_inline` and
`nat44_ed_out2in.c::nat44_ed_out2in_fast_path_node_fn_inline` vs our
`cgnat_in2out_node` and `cgnat_out2in_node` (and slow equivalents).

| nat44-ed feature | ours | status |
|---|---|---|
| TTL=1 → emit ICMP Time Exceeded inline | Not done | divergent-OK (ip4-rewrite catches this later in the graph) |
| Per-packet `BAD_ICMP_TYPE` check before lookup | Not done | divergent-BUG (Finding #4 — covered above) |
| Use cached session_index from handoff if available, skip bihash lookup | Not done | missing (Finding #5) |
| Per-packet `nat44_session_get_timeout` check → if expired, delete inline + go slow | Not done | divergent-OK (we use centralised 10s expire walk; small race window where a packet on a just-expired session still translates) |
| `nat_6t_t_eq(&s0->o2i.match, &lookup)` defensive equality check after bihash hit | Not done; rely on `pool_is_free_index` check in `cgnat_session_from_value` | missing (Finding #6 — defends against hash collision) |
| Per-VRF session expired check | We don't have per-VRF session sets (single shared session pool) | divergent-OK |

Slow-path bodies:

| nat44-ed feature | ours | status |
|---|---|---|
| ICMP error inner-tuple lookup + rewrite | Same logic | match (modulo Finding #3 — inner ICMP csum) |
| EIF / outside-initiated session origination | Not implemented | divergent-OK (Phase 9 deferred) |
| Twice-NAT | Not implemented | divergent-OK (out of scope) |
| Unknown-proto session create | We do this in our in2out slowpath via the same `cgnat_session_create` path with `is_unk_proto` skipping port_alloc | match |
| Hairpinning | Not implemented | divergent-OK (tracked separately) |

## Pair 6: bihash add/del + value packing

`nat44_ed_inlines.h::init_ed_k / init_ed_kv / ed_value_get_*` vs
`osvbng_cgnat.h::cgnat_pack_value / cgnat_value_thread_index /
cgnat_value_entry_index`.

| nat44-ed | ours | status |
|---|---|---|
| Value: `(thread_index << 32) \| session_index` | Same | match |
| Key: 16 bytes, packs `(r_addr<<32 \| l_addr, r_port<<48 \| l_port<<32 \| fib_index<<8 \| proto)` — `fib_index` gets **24 bits** | 16 bytes, packs `(src_ip, dst_ip, src_port, dst_port, proto, _pad, fib_index_lo16)` — `fib_index` gets **16 bits** | divergent-OK (low risk; BNG fib counts << 65536 in practice) |
| Single shared `flow_hash` bihash for both directions | Two separate bihashes (in2out and out2in) | divergent-OK |
| Add/del symmetry: `nat_ed_ses_{i2o,o2i}_flow_hash_add_del` paired in `nat_ed_session_delete` | `clib_bihash_add_del_16_8` add in `cgnat_session_create` and del in `cgnat_session_delete` for both tables | match |

## Pair 7: TCP state machine

`nat44_ed_inlines.h::nat44_set_tcp_session_state` vs
`osvbng_cgnat.h::cgnat_set_tcp_session_state`.

| nat44-ed | ours | status |
|---|---|---|
| 3-state: CLOSED → ESTABLISHED → CLOSING | Same | match |
| Promote on SYN+ACK from both sides | Same | match |
| Drop to CLOSING on FIN OR RST from either side | Same | match |
| Reopen CLOSING → ESTABLISHED on fresh SYN+ACK from both sides | Same (also resets flag accumulators on transition into CLOSING) | match |
| Update LRU head on state change | We don't have LRU (deferred) | divergent-OK |
| Update timeout bucket on state change | Same | match |

## Pair 8: timeout-by-proto

`nat44_ed_inlines.h::nat44_session_get_timeout` vs
`osvbng_cgnat.h::cgnat_session_timeout` /
`cgnat_session_timeout_for_tcp`.

| nat44-ed | ours | status |
|---|---|---|
| TCP transitory vs established slot picked by state | Same | match |
| ICMP timeout | Same | match |
| UDP timeout | Same | match |
| Other (unknown-proto) → falls through to UDP | We have a dedicated CGNAT_PROTO_OTHER slot (5-slot array via `_v2` binapi) | divergent-OK (more granular; back-fills from UDP on `_v1` binapi for compat) |

## Pair 9: fragmentation aux key

`nat44_ed_inlines.h` fragment aux + cache flow vs
`osvbng_cgnat_session.c::cgnat_frag_rewrite_acquire / _release` +
`cgnat_frag_rewrite_lookup` + `osvbng_cgnat_out2in.c` / `_in2out.c` non-first
fragment branches.

| concern | nat44-ed | ours | status |
|---|---|---|---|
| Per-flow aux key | Stored on session directly | Separate `frag_rewrite_pool` keyed by `(saddr, daddr, proto, fib)` with refcount | divergent-OK |
| Refcount semantics | N/A | Acquired in session_create, released in session_delete; entries with >1 session sharing `(saddr,daddr,proto,fib)` survive any single session's death | match (correctness OK by design) |
| Csum delta sign | nat44-ed convention `new - old`, applied via `sub_even` | Our fragment record: **`new - old`** — but applied via `add_even` | **divergent-BUG (Finding #1)** |
| Both directions of aux record installed at acquire | Same (in2out + out2in keys both installed) | match |

---

## Cross-cutting

### `vnet_buffer.ip.reass.*` reads after ip4-lookup boundary

| site | field | order vs ip4-lookup | safe? |
|---|---|---|---|
| in2out fast `cgnat_in2out_ports_from_reass` | `ip_proto`, `l4_hdr_truncated`, `is_non_first_fragment`, `l4_src_port`, `l4_dst_port`, `icmp_type_or_tcp_flags` | runs BEFORE ip4-lookup (handoff is a feature on `ip4-unicast`) | ✓ |
| out2in fast `cgnat_out2in_ports_from_reass` | only `l4_hdr_truncated`, `is_non_first_fragment` | runs AFTER ip4-lookup via DPO; only reads fields at non-overlapping offsets | ✓ |
| out2in slow ICMP-error branch | `icmp_type_or_tcp_flags`, `is_non_first_fragment` | AFTER ip4-lookup; both at non-overlapping offsets | ✓ |
| out2in handoff | reads ports from L4 header directly | AFTER ip4-lookup; only reads `protocol` from IP header + raw L4 bytes | ✓ |

No clobbered reads. (Fix landed in `b7f8bd6` / `7a6665f` / `f236ddf`.)

### Checksum delta polarity at every callsite

| site | uses delta from | applies via | match polarity? |
|---|---|---|---|
| `cgnat_in2out_translate` line 116 IP | `f->l3_csum_delta` (= old-new) | `add_even` | ✓ |
| `cgnat_in2out_translate` line 124 TCP | `f->l4_csum_delta` | `add_even` | ✓ |
| `cgnat_in2out_translate` line 138 UDP | `f->l4_csum_delta` | `add_even` | ✓ |
| `cgnat_in2out_translate` line 153 ICMP | `f->l4_csum_delta` | `add_even` | ✓ |
| `cgnat_out2in_translate` lines 108/116/130/145 | `f->l3_csum_delta` / `l4_csum_delta` | `add_even` | ✓ |
| `cgnat_in2out_slowpath_node` ICMP-error (lines 453, 457) outer IP + inner IP | `s0->i2o.l3_csum_delta` | `add_even` | ✓ |
| `cgnat_out2in_slowpath_node` ICMP-error (lines 420, 427) outer IP + inner IP | `s0->o2i.l3_csum_delta` | `add_even` | ✓ |
| `cgnat_in2out_slowpath_node` fragment branch line 504 | `fr->l3_csum_delta_i2o` (= **new-old**) | `add_even` | ✗ **BUG** |
| `cgnat_out2in_slowpath_node` fragment branch line 343 | `fr->l3_csum_delta_o2i` (= **new-old**) | `add_even` | ✗ **BUG** |

→ Finding #1.

### Bihash add/del symmetry

`session_table_in2out`, `session_table_out2in`, `frag_aux` — all paired
add+del in `cgnat_session_create` / `_delete` / `_acquire` / `_release`. ✓

### Owner check coverage

| site | owner check? | safe without? |
|---|---|---|
| `cgnat_in2out_node` (fast) | ✓ before translate | — |
| `cgnat_in2out_slowpath_node` newly-created or race-existing | ✓ before translate | — |
| `cgnat_in2out_slowpath_node` ICMP-error branch | ✗ | safe today because in2out handoff hashes on `inside_ip` and the ICMP error's outer src IS inside_ip — same worker as session owner. Fragile under future handoff changes. |
| `cgnat_out2in_node` (fast) | ✓ before translate | — |
| `cgnat_out2in_slowpath_node` ICMP-error branch | ✓ before translate | — |
| Fragment branches (both dirs) | N/A | frag_rewrite_t is shared (no per-thread state); no owner concept |

### Mapping spinlock coverage

`m->lock` covers `next_port`, `port_reuse_timestamps[]`, `session_count++`,
`session_count--`. No raw access elsewhere. ✓

### `s->total_pkts` / `s->total_bytes` increment sites

`cgnat_{in2out,out2in}_translate` (each translate, once per packet) and
the slow-path ICMP-error branches (each, once per packet). Fragment slow-
path branches count `pkts_translated` (node-level only) since fragments
have no session. No double-counting found. ✓

---

## Findings

| # | severity | area | summary | fix |
|---|---|---|---|---|
| 1 | BUG-HIGH | csum | Fragment `l3_csum_delta_i2o` / `_o2i` use polarity `new-old` while translate uses `add_even` (expecting `old-new`). Non-first fragments through NAT get IP checksum off by `2 * (new-old)` and are dropped at next-hop router as malformed. | Flip the sub/add lines in `cgnat_frag_rewrite_acquire` to match `cgnat_flow_csum_calc` convention. |
| 2 | BUG-MED | handoff | Out2in handoff doesn't parse ICMP-error inner tuple; ICMP errors fall through to content hash, may land on a worker that doesn't own the original session → `WRONG_WORKER` drop. Affects traceroute, PMTUd, Dest-Unreach feedback through CGN. | In `cgnat_handoff_fn_inline (is_in2out=0)`, when the packet is an ICMP error, parse the inner header to derive the original-session tuple, do bihash lookup on `cm->session_table_out2in`, route to owner. Mirror `nat44_ed_get_out2in_worker_index`. |
| 3 | BUG-MED | icmp | When the ICMP-error inner-rewrite changes `inner_echo->identifier`, we don't update `inner_icmp->checksum`. Outer ICMP csum (which we recompute from scratch) is fine, but a strict subscriber stack that validates the inner ICMP's own checksum will reject the error. | Add an incremental update of `inner_icmp->checksum` whenever inner `echo->identifier` is rewritten. Same code path on both in2out and out2in slowpath ICMP-error branches. |
| 4 | BUG-LOW | icmp | Non-echo, non-error ICMP types (timestamp, info-request, address-mask, etc.) fall through fast path with `src_port=dst_port=0`, then slow path tries to create a degenerate session keyed `(saddr, daddr, 0, 0, ICMP, fib)` and allocates an outside port. Bandwidth wasted, ports leaked. | Add explicit BAD_ICMP_TYPE drop in fast path and slow path when icmp type is neither echo nor error. |
| 5 | MISSING | optim | Handoff doesn't cache the looked-up session_index in `vnet_buffer2(b)`. Receiving worker repeats the bihash lookup. ~50% bihash op reduction per handoff'd packet. | Define a per-buffer cache slot, set it in handoff when the bihash lookup succeeded, consume it in fast path before falling back to a fresh lookup. |
| 6 | MISSING | defensive | Bihash lookup result isn't tuple-checked against the packet — relies on `pool_is_free_index` only. Bihash collisions are vanishingly rare but possible; a hit could be the wrong session. | After session pointer resolved, verify `s->i2o.saddr/daddr/sport/dport/proto/fib` (or `o2i.*`) equal the lookup tuple. nat44-ed has `nat_6t_t_eq` for this. |
| 7 | MISSING | safety | `cgnat_in2out_slowpath_node` ICMP-error branch lacks `cgnat_session_owner_check`. Safe today (in2out handoff guarantees co-residence) but fragile. | Add the owner_check before the inner-rewrite mutations, same as the rest of the slowpath. |

### Divergent-OK (intentional or trivial)

- Csum sign convention (we use `old-new` via `add_even`; nat44-ed uses
  `new-old` via `sub_even`).
- ICMP echo key shape (we use `dst_port=0`; nat44-ed uses `dst_port=echo_id`).
- TTL=1 ICMP Time Exceeded — left to `ip4-rewrite`.
- Per-packet session expire — we use centralised 10s walk.
- `fib_index` width in bihash key — 16 bits vs nat44-ed's 24 bits (low risk).
- Out2in entry via DPO instead of feature on outside interface (intentional).
- Per-protocol LRU eviction — deferred (#156).
- Hairpinning — removed pending re-implementation.
- EIF outside-initiated session origination — deferred (Phase 9).

---

## Fix commit log

Audit findings #1, #3, #4 shipped. Findings #2 and #7 are obsolete after the
architectural revert below (no handoff exists to fix). #5 and #6 still apply
in principle but are deferred.

| finding | what | status |
|---|---|---|
| #1 | flip fragment csum delta polarity to match flow convention | shipped |
| #2 | port nat44-ed inner-tuple lookup for out2in ICMP error | obsolete (no handoff) |
| #3 | update inner ICMP checksum when rewriting inner echo identifier | shipped |
| #4 | drop unhandled ICMP types with BAD_ICMP_TYPE | shipped |
| #5 | handoff cached_session_index optimisation | obsolete (no handoff) |
| #6 | tuple-equality defensive check after bihash hit | deferred |
| #7 | owner_check in in2out slowpath ICMP error | obsolete (no owner check) |

---

## Finding #8 (architectural): handoff cold-worker latency

**Severity: BUG-HIGH (caused 30ms RTT outliers in production).**

Discovered after audit findings #1-7 shipped. With the per-worker session
pool + frame-queue handoff model (the D15 multi-worker amendment to
osvbng-context #153), every packet on a session goes through a handoff to
the session-owning worker. In a low-PPS workload (single subscriber pinging,
~1 packet/sec) on a multi-worker box (12 workers pinned to dedicated cores
in the production QEMU deployment), the session-owning worker is descheduled
by KVM between packets. When the handoff enqueues a packet to that worker's
frame queue, the packet sits there until KVM brings the vCPU back online —
typically 30ms — producing the bimodal RTT pattern (`~1ms` when the worker
happens to be alive, `~35ms` when it has to be woken).

Confirmed by reducing workers to 1: bimodal pattern disappears, RTT
consistent at ~1ms. With 12 workers the handoff routinely lands on a cold
worker.

This is the inherent cost of nat44-ed's per-worker-pool architecture in any
workload where per-worker session activity is bursty. nat44-ed itself shows
the same behaviour at low PPS; its published benchmarks are at line rate
where every worker stays hot. osvbng's actual workload mix is closer to
"thousands of subscribers, each generating modest PPS" than "single flow at
line rate," so the trade-off doesn't earn its complexity.

**Resolution: revert the multi-worker amendment.** Plugin is now back to:

- Single shared `cgnat_session_t *sessions` pool on `cgnat_main_t`
- No `cgnat-in2out-worker-handoff` / `cgnat-out2in-worker-handoff` nodes
- No frame queue init
- `cgnat-in2out` registered as the ip4-unicast feature directly
- `cgnat-outside` DPO targets `cgnat-out2in` directly
- Per-mapping spinlock retained — port allocation still needs serialising
  across workers when they all share the session pool
- Cherry-picked audit fixes that survive the architectural change (#1, #3,
  #4 above, plus the L4-from-header read in out2in for the DPO-after-
  ip4-lookup case)

Plugin remains multi-worker — every worker still runs `cgnat-in2out` and
`cgnat-out2in` independently against the shared pool — just without the
handoff that was forcing packets onto specific workers.

**Cost**: gives up per-session cache locality. Counter writes to
`s->total_pkts` / `s->total_bytes` / `s->last_active` are now best-effort
under cross-worker contention (no atomics, no lock); workloads where two
workers concurrently translate packets for the same session will see some
counter under-counting but no crash. If counter accuracy under contention
becomes a requirement we can switch to `__atomic_fetch_add(RELAXED)`.

**Gain**: predictable low-latency translation at any PPS, no cold-worker
wakeup tax, plugin is meaningfully smaller and simpler.
