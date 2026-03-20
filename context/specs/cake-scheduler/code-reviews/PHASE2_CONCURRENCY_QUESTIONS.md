# Phase 2 Concurrency Architecture — Open Questions

**Purpose:** Answer 5 concrete architectural questions before implementing worker-thread ownership + handoff for the CAKE scheduler. Reviewers should reference the VPP source code (v25.10-release) for their answers.

**Context:** The osvbng QoS scheduler plugin (`osvbng-vpp-plugin-qos`) implements CAKE-equivalent per-subscriber traffic scheduling as a VPP plugin. It hooks into `ip4-output` / `ip6-output` feature arcs (enqueue) and uses a `VLIB_NODE_TYPE_INPUT` polling node (dequeue). With DPDK + RSS, different flows to the same subscriber can arrive on different worker threads, creating a data race on shared scheduler state.

**Agreed design direction:**
- Per-session-interface scheduler ownership (one `cake_sched_t` per subscriber, one owner thread)
- Wrong-worker packets handed off to owner thread via frame queue
- No spinlock in the datapath
- Bounded power-of-2 ring buffer per flow (not `vec_add1`)
- Owner-thread-only mutable state (both enqueue and dequeue on same worker)

**The plugin must remain generic** — no osvbng-specific dependencies. It should work on any VPP interface type (physical, VLAN sub, tunnel/midchain, bond). osvbng-specific integration (e.g. passing owner_thread from Go control plane) happens outside the plugin.

## Questions

### Q1: Best existing VPP example of object ownership + handoff beyond policer?

We know the policer uses `clib_atomic_cmp_and_swap(&pol->thread_index, ~0, vm->thread_index)` with handoff on mismatch. What other VPP features implement the same pattern? Specifically looking for examples that:
- Own complex state (not just a token bucket counter)
- Use `vlib_buffer_enqueue_to_thread()` for handoff
- Have both an enqueue/capture path and a dequeue/release path on the same owner thread

Candidates to investigate: IP reassembly, IPsec ESP, NAT44, WireGuard, TCP host stack. Which is the closest analogue to a per-subscriber scheduler with queued packets?

### Q2: How are frame-queue congestion/drop semantics handled when handoff queues fill?

When `vlib_buffer_enqueue_to_thread()` is called and the target worker's frame queue is full:
- Does it drop the packet? Return an error? Block?
- Is there a `drop_on_congestion` parameter?
- How should our scheduler handle this? (The packet is pre-rewrite on `ip4-output` — if we drop it, the sender gets no signal. If we queue it locally, we violate single-writer.)
- What is the frame queue depth and can it be tuned?

### Q3: How are timers / pacing / INPUT node scheduling bound to a worker?

Our `cake-dequeue` is a `VLIB_NODE_TYPE_INPUT` node in `POLLING` state. It runs on ALL worker threads. We need it to only process schedulers owned by the current thread.

- Is `VLIB_NODE_TYPE_INPUT` the right type for a per-worker dequeue/pacing node?
- Should we use `VLIB_NODE_STATE_INTERRUPT` instead of `POLLING` to reduce idle overhead on non-owner workers?
- How do other VPP features (e.g. TCP timers, session layer timers) bind timer-driven work to specific workers?
- Is there a VPP mechanism to register an INPUT node that only runs on specific workers?

### Q4: How does VPP decide worker affinity for a given interface today?

When a packet enters `ip4-output` for a given `tx_sw_if_index`, which worker is it on? Specifically:
- For physical interfaces with DPDK RSS: the worker is determined by the RX queue of the ingress interface, NOT the TX interface. Different flows to the same subscriber land on different workers.
- For midchain/tunnel interfaces (IPoE/PPPoE sessions): the `tx_sw_if_index` is the session interface, but the worker is from the core-facing RX queue.
- Is there any VPP mechanism to specify "all packets for tx_sw_if_index X should be processed by worker Y"?
- Does VPP's TX queue placement (`vnet_hw_if_set_tx_queue_thread_index`) affect which worker processes the ip4-output feature arc, or only the final TX?

### Q5: Where and how can we guarantee enqueue + dequeue for a subscriber run on the same worker?

The critical invariant: the worker that enqueues packets into a subscriber's scheduler must be the same worker that dequeues them. If enqueue happens on worker 3 but dequeue happens on worker 7, we have shared mutable state.

- With handoff: enqueue always runs on the owner thread (wrong-thread packets are handed off). The dequeue INPUT node runs on all threads but only processes schedulers where `owner_thread == vm->thread_index`. Is this sufficient?
- Is there a risk that the dequeue INPUT node on the owner worker runs BETWEEN the handoff and the actual enqueue processing? (i.e., frame queue latency means the packet hasn't been enqueued yet when dequeue polls)
- Should the dequeue node use the per-thread `active_bitmap` (set by enqueue) as the only trigger, so it never looks at schedulers that haven't had packets enqueued on this thread?

## Additional Context for Reviewers

### NUMA considerations
- VPP allocates from per-NUMA heaps when configured with `buffers { default data-size 2048 }`
- Scheduler state allocated under barrier on main thread may be on wrong NUMA node for owner worker
- Cross-NUMA memory access is ~2-3x latency
- Is NUMA-local allocation important enough to address now, or defer?

### Multi-NIC topology
- BNG typically has 1 core-facing NIC (high-speed, multi-queue) and 1+ access-facing NICs
- Core-facing NIC RSS distributes downstream traffic across workers
- Access-facing NIC(s) may be on different PCIe bus / NUMA node
- The scheduler state is accessed on the core-facing RX path (downstream), not the access-facing path

### Generic plugin constraint
- The plugin API should accept an optional `owner_thread` parameter on enable
- If not specified, use CAS-on-first-touch as fallback
- The control plane (osvbng or any other) is responsible for determining the right owner thread
- The plugin should not depend on any specific interface type or session management system

## Expected Output

For each question, provide:
1. The answer with VPP source references (file:line where relevant)
2. The recommended approach for our scheduler
3. Any caveats or edge cases to watch for
