# Phase 2 Concurrency Architecture Answers (Codex)

**Author:** Codex
**Date:** 2026-03-20
**VPP tree reviewed:** `/home/brandon/osvbng-dev/vpp` (v25.10-release local source tree)

## Q1: Best existing VPP example of object ownership + handoff beyond policer?

### 1. Answer with VPP source references

The closest analogue is **IPv4 full reassembly**.

- Reassembly stores ownership in the object/hash as `memory_owner_thread_index` and immediately requests handoff if the current worker is not the owner: `vnet/ip/reass/ip4_full_reass.c:548-558`.
- New contexts are created in the current thread's per-thread pool and stamped with that worker as owner: `vnet/ip/reass/ip4_full_reass.c:583-595`.
- The fragment path writes the owner thread into buffer metadata and sends wrong-worker packets to a dedicated handoff node: `vnet/ip/reass/ip4_full_reass.c:1242-1247`, `vnet/ip/reass/ip4_full_reass.c:1259-1263`.
- The handoff node batches to `vlib_buffer_enqueue_to_thread()` and counts congestion drops: `vnet/ip/reass/ip4_full_reass.c:1911-1934`.
- Reassembly also has a separate `sendout_thread_index` and can hand the completed packet chain back out if memory-owner and sendout thread differ: `vnet/ip/reass/ip4_full_reass.c:1121-1130`.

The best **secondary** pattern is **IPsec SA ownership**.

- ESP encrypt/decrypt use CAS-on-first-touch to claim an SA runtime for a worker and mark wrong-worker packets for handoff: `vnet/ipsec/esp_encrypt.c:617-630`, `vnet/ipsec/esp_decrypt.c:1157-1170`.
- IPsec handoff then reads the target thread from buffer metadata and uses `vlib_buffer_enqueue_to_thread()` with congestion-drop accounting: `vnet/ipsec/ipsec_handoff.c:46-130`.
- IPsec also supports explicit worker binding of an SA via API/control plane: `vnet/ipsec/ipsec_sa.c:780-794`.

The **session layer** is relevant for worker affinity and timer wakeups, but it is not the closest queued-buffer ownership model because it uses per-worker event queues rather than buffer frame-queue handoff: `vnet/session/session.h:334-350`, `vnet/session/application.c:522-526`, `vnet/session/session_node.c:2180-2215`.

### 2. Recommended approach for our scheduler

Use a **hybrid of IP reassembly and IPsec**:

- Model scheduler ownership like reassembly: one owner worker for each subscriber scheduler, and all mutable queue state lives only on that worker.
- Use **optional explicit `owner_thread` at enable time** like IPsec worker binding, with **CAS-on-first-touch fallback** if not provided.
- On wrong-worker enqueue, stamp the target worker in buffer metadata and send the packet to a dedicated CAKE handoff node using `vlib_buffer_enqueue_to_thread()`.
- Keep both scheduler enqueue and scheduler dequeue on the **same owner worker**. Unlike reassembly, CAKE does not need a second sendout-thread concept if the owner is the only mutator and also runs dequeue.

### 3. Caveats / edge cases

- CAS-on-first-touch is fine as a fallback, but once claimed, the owner should be treated as immutable until an explicit disable/rebind path runs under a worker barrier.
- Reassembly is a better semantic fit than IPsec because it owns queued packet state, not just counters/replay windows.
- If you ever support live owner-thread rebalance, treat it like VPP interface runtime updates: quiesce, swap state under barrier, then release.

## Q2: How are frame-queue congestion/drop semantics handled when handoff queues fill?

### 1. Answer with VPP source references

`vlib_buffer_enqueue_to_thread()` has an explicit **`drop_on_congestion`** parameter.

- The underlying allocator checks whether the target ring is full. If `dont_wait` is true, it returns `0` immediately; otherwise it busy-waits until a slot opens: `vlib/buffer_funcs.c:257-286`.
- `vlib_buffer_enqueue_to_thread_inline()` passes `drop_on_congestion` into that allocator. If no slot is available, buffers go to a local drop list: `vlib/buffer_funcs.c:289-345`.
- If `drop_on_congestion` is `1`, those dropped buffers are freed directly in `vlib_buffer_free()` and the function returns `n_packets - n_drop`: `vlib/buffer_funcs.c:323-346`.
- If `drop_on_congestion` is `0`, the caller effectively waits/spins for ring space in the datapath: `vlib/buffer_funcs.c:272-279`.

This is exactly how the existing handoff users behave:

- Policer passes `drop_on_congestion = 1` and counts `"congestion drop"`: `vnet/policer/police_inlines.h:163-169`, `vnet/policer/node_funcs.c:301-337`.
- IP reassembly does the same: `vnet/ip/reass/ip4_full_reass.c:1928-1934`.
- IPsec does the same: `vnet/ipsec/ipsec_handoff.c:124-130`.

Queue sizing/tuning:

- If `vlib_frame_queue_main_init()` is called with `0`, it uses `FRAME_QUEUE_MAX_NELTS`, which is `64`: `vlib/threads.c:1629-1631`, `vlib/node.h:817`.
- Queue size must be a **power of 2**: `vlib/threads.c:390-394`.
- VPP also asserts the queue is at least `8 + num_threads`: `vlib/threads.c:1632-1633`.
- IPsec exposes a configurable handoff queue size and passes it into `vlib_frame_queue_main_init()`: `vnet/ipsec/ipsec.c:600-603`, `vnet/ipsec/esp_encrypt.c:1568-1577`.
- There are CLI hooks to tune queue nelts/threshold for an existing frame queue: `vlib/threads_cli.c:381-448`, `vlib/threads_cli.c:454-524`.

### 2. Recommended approach for our scheduler

Use **`drop_on_congestion = 1`** for CAKE handoff.

- Do **not** queue locally on the wrong worker. That violates single-writer ownership.
- Do **not** use the blocking/spinning mode. Stalling a worker in `ip4-output` is worse than dropping.
- If handoff is congested, free the packet, increment a dedicated `handoff_congestion_drop` counter, and optionally track this separately from normal CAKE/AQM drops.
- Expose a **power-of-2 handoff queue size** in the plugin config, defaulting to `64`, following the IPsec pattern.

### 3. Caveats / edge cases

- A handoff congestion drop happens before the packet is in the scheduler, so it is not a CAKE queue-management signal. It should have its own counter/reason.
- If you expose queue depth, validate it as a power of 2 and large enough for the worker count.
- Runtime tuning exists in VPP, but plugin-owned init-time sizing is the cleaner default.

## Q3: How are timers / pacing / INPUT node scheduling bound to a worker?

### 1. Answer with VPP source references

`VLIB_NODE_TYPE_INPUT` is a reasonable per-worker execution mechanism, but the key is that **node state is per `vlib_main` clone**, not global.

- `vlib_node_set_state(vm, ...)` operates on one thread's node runtime and updates that thread's input-node state counters: `vlib/node_funcs.h:145-178`.
- `vlib_node_set_interrupt_pending(vm, ...)` targets a specific worker `vm` and explicitly wakes that thread if needed: `vlib/node_funcs.h:216-228`.
- INPUT nodes are cloned into each worker's `vlib_main`: `vlib/threads.c:1005-1044`.

Examples of worker-bound INPUT nodes:

- `virtual-time-input` is a polling INPUT node enabled per-thread via `foreach_vlib_main()`: `vlib/time.c:12-23`, `vlib/time.c:44-49`, `vlib/time.c:63-65`.
- The session layer uses INPUT nodes in both **interrupt** and **polling** modes, and toggles state per worker: `vnet/session/session.c:2150-2179`, `vnet/session/session_node.c:1999-2017`, `vnet/session/session_node.c:2168-2177`.
- Session adaptive mode uses a **per-worker timerfd** plus `vlib_node_set_interrupt_pending()` to wake exactly one worker's INPUT node: `vnet/session/session_node.c:43-77`, `vnet/session/session_node.c:2180-2215`.
- Session time itself is stored per worker and read by thread index: `vnet/session/session.h:968-970`, `vnet/session/session.h:1101-1104`.

The current CAKE plugin already uses an INPUT node and per-thread active bitmap:

- dequeue node type/state: `src/cake_dequeue.c:340-346`
- per-thread bitmap scan: `src/cake_dequeue.c:105-121`
- enqueue-side activation: `src/cake_enqueue.c:184-189`

### 2. Recommended approach for our scheduler

Keep **`cake-dequeue` as `VLIB_NODE_TYPE_INPUT`**.

- On **non-owner workers**, leave it **`DISABLED`**.
- On **owner workers with at least one owned scheduler**, run it in **`POLLING`** mode.
- Use the per-thread active bitmap as the dequeue worklist, so the node only looks at schedulers that actually have work on that worker.

I would **not** switch the CAKE dequeuer to pure `VLIB_NODE_STATE_INTERRUPT` for Phase 2 pacing:

- interrupt mode is a good fit for message queues or coarse timerfd wakeups
- it is a worse fit for tight shaper pacing unless you add a dedicated timer source per owner worker

If idle overhead later matters, copy the session-layer pattern:

- stay `POLLING` while a worker has active schedulers or high dequeue activity
- switch to `INTERRUPT` only when mostly idle
- wake with a timerfd/eventfd on that specific worker

### 3. Caveats / edge cases

- There is **no registration-time "only run on these workers" mask** for INPUT nodes in the reviewed code. The practical mechanism is per-thread node state.
- If you keep polling on every worker and just early-exit, you still pay dispatch overhead everywhere. Disabling non-owner workers is cleaner.
- Per-worker timerfd wakeups are possible, but they are more complex than a polling dequeuer and may not be worth it until you measure idle cost.

## Q4: How does VPP decide worker affinity for a given interface today?

### 1. Answer with VPP source references

In the reviewed VPP code, the worker running `ip4-output` / `ip6-output` is the worker that is already executing the graph for that packet. For physical DPDK ingress, that comes from the **RX queue -> worker mapping**.

- DPDK input polls the RX queues assigned to the current worker thread: `plugins/dpdk/device/node.c:538-551`.
- DPDK device init registers RX queues either to explicit workers or to `VNET_HW_IF_RXQ_THREAD_ANY`: `plugins/dpdk/device/init.c:583-601`.
- RX queue placement is worker-thread state on the queue object: `vnet/interface/rx_queue.c:217-230`.

By contrast, **TX queue placement does not move the packet to another worker**. It only controls which TX queues are available to the current worker at final output.

- `interface_output.c` indexes `hi->output_node_thread_runtimes` by `vm->thread_index`: `vnet/interface_output.c:597-605`, `vnet/interface_output.c:1311-1324`.
- If the current worker has no TX queue for that interface, VPP drops with `NO_TX_QUEUE`; it does not hand off the packet: `vnet/interface_output.c:605-609`, `vnet/interface_output.c:1323-1329`.
- TX queue thread assignment just sets a bitmap on the TX queue object: `vnet/interface/tx_queue.c:109-121`.
- VPP then rebuilds the per-thread output runtimes from those bitmaps under a worker barrier: `vnet/interface/runtime.c:187-215`, `vnet/interface/runtime.c:248-312`.

So the answer to "is there a VPP mechanism to say all packets for `tx_sw_if_index X` run on worker `Y`?" is effectively **no** in the generic datapath. The reviewed code has:

- RX queue placement for ingress affinity
- TX queue availability for final output
- explicit handoff nodes where a feature wants to move work

It does **not** have a generic "pin feature arc execution by TX interface" mechanism.

### 2. Recommended approach for our scheduler

Assume that **different flows to the same subscriber can arrive on different workers**, especially with RSS on the core-facing ingress.

Therefore:

- do **not** treat `tx_sw_if_index` as a worker-affinity key
- do **not** assume TX queue placement will fix the scheduler race
- explicitly hand off wrong-worker packets to the subscriber's owner worker before mutating scheduler state

### 3. Caveats / edge cases

- On software/tunnel/midchain interfaces, there may not be a hardware TX queue restriction, but the packet still stays on the ingress-side worker unless a feature hands it off.
- If you choose an owner worker that cannot ultimately transmit on the egress interface, you can still run into final-output problems on physical interfaces. Owner selection should be compatible with the deployment topology.

## Q5: Where and how can we guarantee enqueue + dequeue for a subscriber run on the same worker?

### 1. Answer with VPP source references

Yes: **handoff + owner-thread-only dequeue + owner-thread-only activation is sufficient**.

The key VPP behavior is that a frame-queue handoff only makes the packet visible to the target worker after that worker drains its frame queue in the main loop:

- worker main loop checks frame queues and dequeues them into the target node when `check_frame_queues` is set: `vlib/main.c:1513-1534`
- `vlib_buffer_enqueue_to_thread()` sets `check_frame_queues` on the target worker when it posts a valid element: `vlib/buffer_funcs.c:315-321`

That means there is no harmful race if the owner worker's dequeue INPUT node runs between handoff posting and actual enqueue processing. At worst:

- the handoff has not yet been drained
- owner-thread enqueue has not yet appended the packet
- owner-thread dequeue sees no new work yet

The current CAKE active-bitmap pattern is the right trigger mechanism:

- enqueue sets the current thread's bitmap after queue append: `src/cake_enqueue.c:142-189`
- dequeue only scans the current thread's bitmap: `src/cake_dequeue.c:105-121`

### 2. Recommended approach for our scheduler

Use this invariant:

1. Each subscriber scheduler has exactly one `owner_thread`.
2. Wrong-worker packets are handed off before touching scheduler state.
3. Only the owner-thread enqueue path mutates per-flow rings/lists/counters.
4. Only the owner-thread dequeue INPUT node processes that scheduler.
5. Only the owner-thread enqueue path sets the owner thread's active bitmap bit.

Concretely:

- keep a per-thread active bitmap, but make it contain only schedulers owned by that thread
- in the wrong-worker path, do **not** set any active bit locally
- set the active bit only after the packet has been appended on the owner worker
- have `cake-dequeue` on each worker iterate only its local bitmap and ignore all others

This is enough to guarantee single-writer enqueue + dequeue behavior for the scheduler state.

### 3. Caveats / edge cases

- Frame-queue latency can delay when a handed-off packet becomes visible to the owner worker, but that is a latency issue, not a correctness issue.
- If a scheduler is already active, dequeue may run and drain older packets before a newly handed-off packet is enqueued. That is fine.
- Owner changes, disable, or drain/rebind operations should run under a worker barrier or equivalent quiesce path before moving/freeing state, similar to how VPP swaps TX runtimes under barrier: `vnet/interface/runtime.c:248-312`.
- NUMA-local allocation matters, but I would defer it until after ownership/handoff correctness is in place. The structure should allow future owner-thread-local allocation without redesign.

## Bottom Line

The VPP patterns point to a clear design:

- **Closest model:** IP reassembly for queued-packet ownership, with IPsec as the supporting pattern for CAS fallback and configurable handoff queues.
- **Handoff behavior:** use `vlib_buffer_enqueue_to_thread(..., drop_on_congestion = 1)` and count congestion drops.
- **Dequeue node:** keep `cake-dequeue` as an INPUT node, but disable it on non-owner workers and drive it from owner-thread-only active bitmaps.
- **Worker affinity:** RSS/RX placement determines the worker that reaches `ip4-output`; TX queue placement does not.
- **Correctness invariant:** wrong-worker packets must be handed off before enqueue, and only owner-thread enqueue should activate owner-thread dequeue.
