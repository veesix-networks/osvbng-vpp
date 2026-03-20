# Phase 2 Concurrency Architecture — Answers

## Q1: Best existing VPP example of object ownership + handoff beyond policer?

**Answer:**
The best examples of complex state ownership and thread handoff in VPP are **IP Reassembly** (`src/vnet/ip/reass/ip4_full_reass.c`) and **NAT44 Endpoint-Dependent** (`src/plugins/nat/nat44-ed/nat44_ed_handoff.c`). 

In `ip4_full_reass.c`, fragments arriving on any worker are hashed to determine a context owner thread. If `vm->thread_index` does not match the owner, the packets are handed off using `vlib_buffer_enqueue_to_thread()`. The target thread owns the complex reassembly buffer state and handles both the enqueueing (reassembly) and dequeueing (forwarding the complete packet or dropping on timeout) without any locks.

**Recommended approach:**
Adopt the NAT/Reassembly handoff pattern. 
1. Assign an `owner_thread` to each `cake_sched_t`.
2. In the `ip4-cake-enqueue` node, compare `vm->thread_index` with `cs->owner_thread`.
3. If they match, proceed with enqueue.
4. If they differ, use `vlib_buffer_enqueue_to_thread()` to send the packet to a dedicated handoff node (or directly re-enqueue to `ip4-cake-enqueue`) on the `owner_thread`.

## Q2: How are frame-queue congestion/drop semantics handled when handoff queues fill?

**Answer:**
`vlib_buffer_enqueue_to_thread()` (implemented in `src/vlib/buffer_funcs.c`) takes a `drop_on_congestion` parameter. 
- If `drop_on_congestion == 1`, VPP immediately drops the packets via `vlib_buffer_free` and increments the drop count if the target worker's frame queue is full.
- If `drop_on_congestion == 0`, the calling thread spins (blocks) in a `while` loop calling `vlib_worker_thread_barrier_check()` until a slot opens in the target frame queue.

**Recommended approach:**
Set `drop_on_congestion = 1`. Blocking a worker thread in VPP creates head-of-line blocking for all other traffic processed by that thread, which is fatal for overall router throughput. Dropping the packet serves as an immediate tail-drop signal to the TCP sender. You should track these drops with a dedicated error counter (e.g., `CAKE_ERROR_HANDOFF_CONGESTION`). The frame queue depth is typically configured via VPP startup configuration (`frame_queue_nelts`).

## Q3: How are timers / pacing / INPUT node scheduling bound to a worker?

**Answer:**
VPP registers nodes globally, but their state can be set per-worker thread. In `src/vnet/session/session.c`, the `session_queue_node` (a `VLIB_NODE_TYPE_INPUT` node) is enabled selectively on worker threads using `vlib_node_set_state(vm, node_index, state)`. Because `vlib_node_set_state` takes a `vlib_main_t *`, you can change the state on a specific thread by passing `vlib_get_main_by_index(thread_index)`.

**Recommended approach:**
Keep `cake-dequeue` as a `VLIB_NODE_TYPE_INPUT` node. Instead of iterating `foreach_vlib_main()` to set the node to `VLIB_NODE_STATE_POLLING` on all threads, call `vlib_node_set_state(vlib_get_main_by_index(cs->owner_thread), cm->dequeue_node_index, VLIB_NODE_STATE_POLLING)`. This ensures that the dequeue node consumes zero CPU on workers that do not own any schedulers.

## Q4: How does VPP decide worker affinity for a given interface today?

**Answer:**
Worker affinity on ingress is strictly determined by the hardware RX queue-to-thread mapping (`src/plugins/dpdk/device/device.c`). 
For DPDK, RSS distributes flows across multiple RX queues, which are polled by different workers. The `tx_sw_if_index` (which could be a midchain/tunnel interface) does not dictate which worker processes the `ip4-output` feature arc. The arc runs on whichever worker thread dequeued the packet from the physical NIC. `vnet_hw_if_set_tx_queue_thread_index` only controls which worker is allowed to place packets on the final hardware TX queue, not the feature arc execution.

**Recommended approach:**
We cannot force RSS or VPP to map all traffic for a specific subscriber session to a single worker before our plugin. The plugin must assume packets for the same scheduler will arrive on random workers. The handoff mechanism (Q1) is mandatory to funnel them to the `owner_thread`.

## Q5: Where and how can we guarantee enqueue + dequeue for a subscriber run on the same worker?

**Answer:**
By combining the handoff mechanism and per-thread INPUT node polling, we achieve strictly single-threaded execution for a given subscriber:
1. Wrong-thread packets are placed in the frame queue for the `owner_thread`.
2. The `owner_thread` drains its frame queue, running the `ip4-cake-enqueue` node logic.
3. The `owner_thread` subsequently runs the `cake-dequeue` INPUT node.

**Race Condition Analysis:**
There is no data race. VPP graph node dispatch is run-to-completion on a single thread. The `owner_thread` cannot run the enqueue node and the dequeue node simultaneously. 
If the dequeue INPUT node runs while packets are waiting in the frame queue (before the enqueue node processes them), the dequeue node simply sees an empty scheduler. The packets will be enqueued in the next dispatch cycle. This is standard batch-processing latency, not a concurrency bug.

**Recommended approach:**
Use the per-thread `active_bitmap` updated exclusively by the enqueue logic *after* handoff (meaning it only runs on the `owner_thread`). The dequeue node on the `owner_thread` iterates over this bitmap. This guarantees the dequeue node only touches schedulers that this thread definitively owns and has active packets for.

## Additional Context: NUMA locality

**Recommendation:**
While not strictly required for functional correctness in Phase 2, cross-NUMA memory access (allocating `cake_sched_t` on NUMA 0 while the `owner_thread` is on NUMA 1) will degrade the <500 c/v performance target. Since you will know the `owner_thread` during `cake_sched_enable_disable`, you can look up the thread's NUMA node (`vlib_get_main_by_index(owner_thread)->numa_node`) and allocate the scheduler state using `clib_mem_alloc_numa()` instead of a standard pool, or restructure the state to have thread-local components. For Phase 2, this can be deferred, but it should be a priority for Phase 3/4 tuning.