# Decisions: cake-scheduler

Phase 4 finalization incorporating findings from both Codex (Phase 3, 7 findings) and Gemini (Phase 2, 11 findings). Several findings overlap — deduplicated below. All accepted, none rejected.

## Accepted

### 1. Dequeue must resume via feature arc re-injection, not hard-jump to arc-end
- **Source:** CODEX (CRITICAL) + GEMINI (implicit in buffer ownership finding)
- **Resolution:** The original design sent dequeued packets directly to `interface-output-arc-end`, skipping all remaining output features (span-output, ipsec-if-output, etc.). Redesigned: the dequeue node re-injects packets into the `interface-output` feature arc with a `CAKE_BUFFER_F_SCHEDULED` flag. The enqueue node checks this flag first — if set, clears it and calls `vnet_feature_next()` to continue through remaining features. No output features are skipped. The feature config index used is always live at transmission time, not stale from enqueue time — this also resolves the Codex finding about `current_config_index` invalidation during live feature reconfiguration.

### 2. Buffer ownership invariant — enqueue consumes, five explicit free paths
- **Source:** CODEX (CRITICAL) + GEMINI (CRITICAL)
- **Resolution:** Both reviews independently identified the use-after-free: the scaffold sent queued buffers to `error-drop` which frees them, then dequeue tried to access the freed index. Fixed: enqueue **consumes** the buffer — removes it from the frame, does NOT forward to any next node. The scheduler is the sole owner. Buffers are freed in exactly one of five paths: (1) dequeue transmit, (2) COBALT AQM drop, (3) buffer overflow drop, (4) subscriber teardown / interface delete (drains all queues), (5) handoff congestion drop.

### 3. Per-thread per-interface scheduler model (matches VPP TX queue reality)
- **Source:** CODEX (HIGH)
- **Resolution:** The original single-owner-thread model doesn't match VPP's multi-TXQ placement. Changed: scheduler state is keyed by `(sw_if_index, thread_index)`. Each worker thread gets its own instance with independent flow tables, shapers, and queues. Rate is split across threads (`total_rate / n_threads`). On TX queue placement changes, instances are drained and recreated.

### 4. Lazy tin/flow allocation + global buffer-count admission control
- **Source:** CODEX (HIGH) + GEMINI (MEDIUM)
- **Resolution:** Both reviews flagged the memory footprint (~320-640 KiB static per subscriber). Fixed: tins allocated lazily on first packet to each DSCP class. Flows use pool allocator (only active flows consume memory). Default flow limit reduced to 256 (configurable to 1024). Added dual admission control: per-subscriber byte limit + global `max_queued_buffers` watermark (default 25% of VPP buffer pool) to prevent buffer-pool exhaustion from small packets.

### 5. INPUT node disabled when idle
- **Source:** CODEX (MEDIUM) + GEMINI (implicit)
- **Resolution:** Dequeue node starts `VLIB_NODE_STATE_DISABLED`. Switched to `POLLING` on first scheduler enable, back to `DISABLED` when last scheduler removed. Zero dispatch overhead when unused.

### 6. IPv6 extension header walk for correct flow hashing
- **Source:** CODEX (MEDIUM) + GEMINI (HIGH)
- **Resolution:** Both reviews identified that assuming L4 ports follow the fixed 40-byte IPv6 header breaks on extension headers. Fixed: use `ip6_locate_header()` or equivalent to walk hop-by-hop, routing, destination option, and fragment headers. Non-first fragments (no L4 ports) fall back to src/dst address + fragment ID hash.

### 7. IPv6 flow label MUST be included in hash
- **Source:** GEMINI (MEDIUM)
- **Resolution:** RFC 8290 RECOMMENDS including the flow label. Changed from optional to MUST — the 20-bit flow label is XORed into the hash for all IPv6 packets. Critical for encrypted traffic (QUIC, WireGuard) where L4 ports may not be visible.

### 8. Dequeue frame handling must be batched
- **Source:** GEMINI (CRITICAL)
- **Resolution:** The scaffold called `vlib_get_next_frame` / `vlib_put_next_frame` inside the per-packet loop — this defeats vector processing and causes massive CPU overhead. Fixed: dequeue collects buffer indices into a local vector first, then does a single bulk frame enqueue after the per-scheduler loop.

### 9. CoDel control law must use rec_inv_sqrt, not linear divisor
- **Source:** GEMINI (HIGH)
- **Resolution:** The scaffold used `interval / (count + 1)` as a placeholder — this violates RFC 8289 and causes exponentially faster drop rates than intended. The spec already specifies Newton-Raphson `rec_inv_sqrt` (§4.8). The scaffold placeholder is explicitly wrong and must not ship. Implementation must use `cake_codel_control_law()` with the precomputed cache.

### 10. BLUE randomness must use proper PRNG
- **Source:** GEMINI (MEDIUM)
- **Resolution:** The scaffold used `now_us ^ bi` which is predictable and causes synchronized drops. Fixed: implementation must use `clib_random_u32()` or equivalent PRNG seeded per-thread.

### 11. ECN marking must use incremental checksum (IPv4)
- **Source:** GEMINI (LOW, recommendation)
- **Resolution:** Accepted. IPv4 CE marking uses `ip4_header_checksum_update()` for the 1-byte ECN change instead of full checksum recompute. IPv6 has no header checksum.

### 12. Triple isolation is Phase 6 (not missing)
- **Source:** GEMINI (HIGH)
- **Resolution:** Gemini flagged host tracking as unimplemented. This is by design — the implementation spec has 8 phases, and triple isolation is Phase 6. The host table structures and quantum adjustment are explicitly planned, not missing. No spec change needed.

### 13. DRR list rotations and scalar processing are scaffold TODOs
- **Source:** GEMINI (LOW + LOW)
- **Resolution:** Acknowledged. The scaffold demonstrates the pipeline structure, not the complete algorithm. DRR rotations are Phase 2, dual-loop vectorization is ongoing throughout. `MULTIARCH_SOURCES` in CMakeLists.txt already enables SIMD variant generation. No spec change needed.

## Rejected

(none — all findings accepted)
