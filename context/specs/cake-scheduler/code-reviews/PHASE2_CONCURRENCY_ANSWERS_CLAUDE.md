# Phase 2 Concurrency Answers (Claude)

**Author:** Claude
**Date:** 2026-03-20
**Method:** Direct VPP v25.10 source exploration

## Q1: Best ownership + handoff example beyond policer?

**Answer: IP4 Full Reassembly** (`src/vnet/ip/reass/ip4_full_reass.c`)

Closest analogue to our scheduler because it has:
- **Shared hash table** for lookup (like our `sched_index_by_sw_if_index`)
- **Per-thread memory pools** for state (like our per-subscriber scheduler)
- **CAS-based ownership** on first packet
- **Bidirectional handoff** — lookup handoff (wrong owner) and completion handoff (send on RX thread)
- **Complex per-resource state** with queued buffers (fragments held until reassembly complete)

Key pattern at `ip4_full_reass.c:536-605`:
```c
ip4_full_reass_find_or_create(vm, node, rm, rt, kv, &do_handoff) {
  if (!clib_bihash_search_16_8(&rm->hash, &kv->kv, &kv->kv)) {
    if (vm->thread_index != kv->v.memory_owner_thread_index) {
      *do_handoff = 1;  // Not our state — handoff
      return NULL;
    }
    // ... use state owned by this thread
  }
  // New: create in this thread's pool, set owner
  reass->memory_owner_thread_index = vm->thread_index;
}
```

Handoff at `ip4_full_reass.c:1228-1264`:
```c
if (PREDICT_FALSE(do_handoff)) {
  next0 = IP4_FULL_REASS_NEXT_HANDOFF;
  vnet_buffer(b0)->ip.reass.owner_thread_index = kv.v.memory_owner_thread_index;
}
```

**Recommendation for our scheduler:** Same pattern. `cake_sched_t` has `owner_thread`. Enqueue node checks `owner_thread == vm->thread_index`. Mismatch → store owner in buffer opaque → next = HANDOFF. Handoff node uses `vlib_buffer_enqueue_to_thread()`.

## Q2: Frame queue congestion handling

**Answer:** `vlib_buffer_enqueue_to_thread()` takes `drop_on_congestion` (int, 1 = drop).

At `buffer_funcs.c:258-287`:
```c
vlib_get_frame_queue_elt(fqm, index, dont_wait) {
  if (new_tail >= fq->head + nelts) {
    if (dont_wait)
      return 0;  // NULL = congestion, caller drops
    while (new_tail >= fq->head + nelts)
      vlib_worker_thread_barrier_check();  // blocking
  }
}
```

NAT44 uses `drop_on_congestion=1` and counts drops:
```c
n_enq = vlib_buffer_enqueue_to_thread(vm, node, fq_index, from,
                                      thread_indices, frame->n_vectors, 1);
if (n_enq < frame->n_vectors)
  vlib_node_increment_counter(vm, node->node_index,
    NAT44_HANDOFF_ERROR_CONGESTION_DROP, frame->n_vectors - n_enq);
```

**Recommendation:** Use `drop_on_congestion=1`. Count drops. The packet is pre-rewrite — dropping it causes TCP retransmit, which is the correct backpressure signal.

## Q3: INPUT node worker binding

**Answer:** INPUT nodes run on ALL workers. Worker filtering is done inside the node function.

Session layer pattern at `session_input.c:372-388`:
```c
VLIB_NODE_FN(session_input_node)(vlib_main_t *vm, ...) {
  clib_thread_index_t thread_index = vm->thread_index;
  session_worker_t *wrk = session_main_get_worker(thread_index);
  session_wrk_flush_events(wrk);  // Only THIS worker's events
}
```

The INPUT node is registered `VLIB_NODE_STATE_DISABLED` and enabled to `POLLING` when needed. There is no mechanism to make it poll on only specific workers.

For waking specific workers without constant polling, use `VLIB_NODE_STATE_INTERRUPT` with `vlib_node_set_interrupt_pending()`:
```c
// Cross-thread signal:
vlib_node_set_interrupt_pending(target_vm, node_index);
// Sets atomic interrupt flag + wakes target thread
```

**Recommendation for our scheduler:**
- Keep `cake-dequeue` as `VLIB_NODE_TYPE_INPUT` in `POLLING` state
- First line of dequeue: `if (clib_bitmap_is_zero(pt->active_bitmap)) return 0;` — already implemented, workers with no owned schedulers exit immediately with ~55 cycles overhead
- Only process schedulers where `cs->owner_thread == thread_index`
- Consider switching to INTERRUPT mode in future (wake owner thread when enqueue adds to empty queue) to eliminate polling on idle workers

## Q4: Worker affinity for tx_sw_if_index

**Answer:** `ip4-output` feature arc runs on the **RX worker**, not the TX worker.

At `interface_output.c:554-616`, the output node gets `vm->thread_index` which is the thread that received the packet on the ingress interface. TX queue selection happens within the output node via per-thread runtime lookups:
```c
if (hi->output_node_thread_runtimes)
  r = vec_elt_at_index(hi->output_node_thread_runtimes, vm->thread_index);
```

DPDK RSS distributes packets across RX queues based on 5-tuple hash. Each RX queue → one worker. Different flows to the same subscriber → different workers → different threads hitting `ip4-output` → cake-enqueue for the SAME subscriber.

**This confirms the RSS data race problem.** There is no VPP mechanism to say "all packets for tx_sw_if_index X should be processed by worker Y" at the feature arc level. TX queue placement only affects the final transmit, not the output feature arc.

**Recommendation:** Handoff in cake-enqueue is the only correct approach. The plugin must redirect wrong-worker packets to the owner before touching any scheduler state.

## Q5: Guaranteeing enqueue + dequeue same worker

**Answer:** Safe. No latency risk.

Frame queue uses RELEASE/ACQUIRE barriers (`buffer_funcs.c:315-322`):
```c
// Enqueue side:
__atomic_store_n(&hf->valid, 1, __ATOMIC_RELEASE);
vlib_get_main_by_index(thread_index)->check_frame_queues = 1;

// Dequeue side (main.c:1513-1535):
if (vm->check_frame_queues) {
  frame_queue_check_counter = 100;  // Poll for 100 iterations
  vec_foreach(fqm, tm->frame_queue_mains)
    processed += (fn)(vm, fqm);
}
```

The target worker processes the frame queue on its next main loop iteration (microsecond scale). No batching delay — `valid=1` makes the frame immediately dequeueable.

With handoff:
1. Worker A receives packet for subscriber X (owned by worker B)
2. cake-enqueue on worker A: detects `owner_thread != thread_index` → handoff via frame queue
3. Worker B's main loop: `check_frame_queues` → dequeues frame → processes through cake-enqueue on worker B
4. Worker B's cake-dequeue INPUT node: polls active_bitmap → finds queued packets → dequeues

Both enqueue and dequeue mutations happen exclusively on worker B. The active_bitmap is only set by worker B's enqueue. Worker B's dequeue only sees schedulers with `owner_thread == B`.

**No race:** the frame queue dequeue happens BEFORE the main loop dispatches graph nodes. So by the time cake-enqueue runs on worker B, the buffer is fully owned by worker B.
