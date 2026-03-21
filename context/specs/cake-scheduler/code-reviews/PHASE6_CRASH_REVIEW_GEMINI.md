# Phase 6 Crash Review — Root Cause Analysis

After reviewing the code, the doubly-linked list operations and flow counts (`sparse_flow_count`, `bulk_flow_count`) are completely correct. The lists do not become circular, and DRR rotation functions correctly even for single-element lists.

The actual root cause of the deadlock is a **leak in the per-host bulk flow counter** (`tin->hosts[...].bulk_flow_count`).

When a flow transitions between states or is evicted, this counter becomes desynchronized. Under a multi-flow iperf3 load, flows frequently drain their queues (transitioning to `DECAYING`) and then receive new packets (transitioning back to `BULK`). Each cycle leaks the counter, causing `host_load` to rapidly grow past 1024 (`CAKE_QUEUES`). 

This results in an out-of-bounds read on the `cake_quantum_div` array. Reading memory past this array yields a `0`, causing `cake_quantum_for_flow()` to return a quantum of 0. Once a flow receives a quantum of 0, `flow->deficit` never becomes positive, causing the packet dequeue loop to be skipped. The scheduler infinitely rotates the flow through the DRR list without ever decrementing `budget`, leading to the worker thread barrier deadlock.

### Finding 1: host bulk_flow_count leak on DECAYING transition
**File:** `src/cake_dequeue.c`
**Line:** 308 (Inside the `if (flow->flow_state == CAKE_FLOW_BULK)` block)

**Description:**
When a `BULK` flow drains its queue, it is transitioned to `DECAYING`. The tin's global `bulk_flow_count` is correctly decremented, but the per-host counter `tin->hosts[...].bulk_flow_count` is missed. When the flow later receives a packet and returns to `BULK`, the host counter is incremented again, causing the leak.

**Fix:**
Add the host counter decrement logic when moving a flow to `DECAYING`:
```c
                  if (flow->flow_state == CAKE_FLOW_BULK)
                    {
                      flow->flow_state = CAKE_FLOW_DECAYING;
                      cake_flow_list_remove (&tin->old_flow_head,
                                             &tin->old_flow_tail, tin->flows,
                                             flow_idx);
                      cake_flow_list_append_tail (&tin->decaying_flow_head,
                                                  &tin->decaying_flow_tail,
                                                  tin->flows, flow_idx);
                      tin->bulk_flow_count--;
                      /* FIX: Decrement the host bulk flow count */
                      if (flow->dst_host_idx < CAKE_HOSTS)
                        {
                          if (tin->hosts[flow->dst_host_idx].bulk_flow_count > 0)
                            tin->hosts[flow->dst_host_idx].bulk_flow_count--;
                        }
                    }
```

### Finding 2: host bulk_flow_count leak on Eviction
**File:** `src/cake_enqueue.c`
**Line:** 52 (Inside `cake_flow_evict`, in the `else if (ef->flow_state == CAKE_FLOW_BULK)` block)

**Description:**
If a `BULK` flow is evicted due to hash collisions on the enqueue path, the `bulk_flow_count` is decremented but the host counter is again missed, causing another path for the leak.

**Fix:**
Add the host counter decrement logic when evicting a `BULK` flow:
```c
  else if (ef->flow_state == CAKE_FLOW_BULK)
    {
      cake_flow_list_remove (&tin->old_flow_head, &tin->old_flow_tail,
                             tin->flows, slot);
      tin->bulk_flow_count--;
      /* FIX: Decrement the host bulk flow count */
      if (ef->dst_host_idx < CAKE_HOSTS)
        {
          if (tin->hosts[ef->dst_host_idx].bulk_flow_count > 0)
            tin->hosts[ef->dst_host_idx].bulk_flow_count--;
        }
    }
```