# Decisions: cake-scheduler

## Accepted

### Dequeue must resume via feature arc, not hard-jump to arc-end
- **Source:** CODEX
- **Severity:** CRITICAL
- **Resolution:** Redesigned dequeue output path. The dequeue node re-injects packets into the `interface-output` feature arc using the saved `current_config_index` from the buffer, calling `vnet_feature_next()` to resume at the correct position. CAKE marks packets with a per-buffer flag (`CAKE_BUFFER_F_SCHEDULED`) so the enqueue node can distinguish already-scheduled packets from fresh ones and pass them through without re-queuing. This preserves span-output, ipsec-if-output, and any other features registered after CAKE on the interface-output arc. Spec §4.1, §4.13 updated.

### Buffer ownership invariant required for queued packets
- **Source:** CODEX
- **Severity:** CRITICAL
- **Resolution:** Added explicit buffer ownership invariant to spec §4.13. The enqueue node **consumes** the packet — it does not forward it to any next node. The buffer index is removed from the frame and stored in the flow queue. The scheduler is the sole owner from that point. Buffers are freed in exactly one of five paths: (1) dequeue transmit, (2) AQM drop, (3) buffer overflow drop, (4) subscriber teardown/interface delete, (5) handoff congestion drop. The scaffold's error-drop path is removed — enqueue returns `frame->n_vectors` but enqueues zero buffers to next nodes for scheduled packets.

### Feature config heap stale reference on reconfiguration
- **Source:** CODEX
- **Severity:** CRITICAL
- **Resolution:** The dequeue path does NOT use `current_config_index` to resume. Instead, it re-injects via a `CAKE_BUFFER_F_SCHEDULED` flag check in the enqueue node itself. When dequeue is ready to transmit, it enqueues the buffer back to the `interface-output` feature arc entry point for that interface. The enqueue node sees the flag, clears it, and calls `vnet_feature_next()` with the buffer's live (current) config index — not a stale one. This means the config index used is always fresh at the time of actual transmission, not from when the packet was originally enqueued. Spec §4.1, §4.13 updated.

### Per-thread scheduler model does not match VPP TX queue model
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Changed the scheduler ownership model. Scheduler state is keyed by `(sw_if_index, thread_index)` — each worker thread that can send to an interface gets its own scheduler instance with its own flow tables, shapers, and queues. This matches VPP's reality where multiple threads can transmit to the same interface via different TX queues. The rate for each per-thread instance is `total_rate / n_threads_for_interface`. On TX queue placement changes, existing per-thread schedulers are drained and recreated. Spec §4.14 updated.

### Memory model too large for thousands of subscribers
- **Source:** CODEX
- **Severity:** HIGH
- **Resolution:** Adopted lazy allocation for tins and flows. Tins are allocated on first packet to that DSCP class, not at scheduler creation. Flows within a tin use a pool allocator instead of a fixed 1024-element array — only active flows consume memory. Default flow table size reduced to 256 for besteffort/diffserv3 modes (1024 remains available as a config option for high-fan-out subscribers). Added a global buffer-count admission control: the scheduler tracks total queued buffer objects (not just bytes) and refuses new enqueues when a configurable `max_queued_buffers` watermark is reached (default: 25% of VPP buffer pool). Spec §4.3, §4.4, §4.5 updated.

### INPUT node should be disabled when no schedulers are active
- **Source:** CODEX
- **Severity:** MEDIUM
- **Resolution:** The dequeue node starts in `VLIB_NODE_STATE_DISABLED`. When the first scheduler is enabled on any thread, the enable path calls `vlib_node_set_state(VLIB_NODE_STATE_POLLING)`. When the last scheduler is disabled, it sets the node back to `VLIB_NODE_STATE_DISABLED`. Per-thread: the node only iterates schedulers owned by the current thread's active bitmap, so threads with no schedulers return immediately. Spec §4.2 updated.

### IPv6 extension header walk required for correct flow hashing
- **Source:** CODEX
- **Severity:** MEDIUM
- **Resolution:** Added IPv6 extension header walk to the flow hashing spec. The hash function uses VPP's `ip6_locate_header()` or equivalent to skip hop-by-hop, routing, and destination option headers to find the L4 protocol header. For fragment headers where L4 ports are not available (non-first fragments), the flow hash falls back to src/dst address + fragment ID, which groups fragments of the same datagram into the same flow queue. Spec §4.6 updated.

## Rejected

(none)
