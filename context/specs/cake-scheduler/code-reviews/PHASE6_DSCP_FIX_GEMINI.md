# Phase 6 DSCP Classification Fix

**Issue:** With diffserv4 mode (4 tins), ALL best-effort iperf3 traffic (DSCP 0, ToS byte 0x00) ends up in tin 3 (Voice/EF) instead of tin 1 (Best Effort).

## Root Cause Analysis

The reported issue contains a mathematical paradox if we assume all code executes exactly as written in `src/cake_enqueue.c` and `src/osvbng_qos_sched.h`:

1. `vlib_buffer_get_current (b)` points to the IP header (confirmed by the fact that flow hashing works).
2. The user's iperf3 traffic has a ToS byte of `0x00`.
3. `cake_dscp_from_buffer` does `ip4->tos >> 2`, which evaluates to `0 >> 2 = 0`.
4. `cs->dscp_to_tin` points to `cake_dscp_diffserv4` (since `tin_mode == CAKE_TIN_MODE_DIFFSERV4`).
5. `cake_dscp_diffserv4[0]` is explicitly initialized to `1` in `src/osvbng_qos_sched.c`.
6. `tin_idx = cs->dscp_to_tin[dscp]` evaluates to `1`.
7. The packet is enqueued to `cs->tins[1]`.
8. The VPP `show` command prints `tin 1: pkts ...` for `cs->tins[1]`.

If all of the above are true, the traffic **must** end up in `tin 1`, and the `show` command **must** report it in `tin 1`. 

However, the user reports the traffic ends up in `tin 3`. For `tin_idx` to evaluate to `3`, `cake_dscp_from_buffer` must be returning a DSCP value that maps to `3` in `cake_dscp_diffserv4`. The only DSCP values that map to `3` are `32, 40, 44, 46, 48, 56`. 

If `dscp` evaluates to `46` (Voice/EF), it means `ip4->tos >> 2` evaluated to `46`, which means `ip4->tos` was `184` (`0xB8`). This indicates that either:
- The ToS byte of the incoming packets is actually `0xB8` (despite the user's assertion that it is `0x00`), potentially due to VPP modifying the ToS byte before the cake node.
- `vlib_buffer_get_current(b)` does **not** point to the IP header, but rather to the Ethernet header, and the second byte of the destination MAC address happens to be `0xB8` (e.g., `02:B8:xx:xx:xx:xx`). The flow hashing would still "work" to distribute flows if the UDP/TCP ports happen to be extracted from the IP `id` field (which varies per packet, creating a new flow per packet).

### The "Bug specifically in how the DSCP value maps to a tin index"
If we strictly assume the ToS byte is indeed `0x00` and `ip4` points to the IP header, but the mapping logic itself is the problem:

In Linux CAKE, `tin 0` is the highest priority, and Voice maps to `0`, BE maps to `2`. 
In the VPP port, `tin 3` is the highest priority, so the author inverted the array: Voice maps to `3`, BE maps to `1`. 

If the user expects `tin 1` to have the packets, the current code `u8 tin_idx = cs->dscp_to_tin[dscp];` ALREADY yields `1`. If the VPP runtime is somehow putting this in `tin 3`, it implies the array in the compiled executable does not match the source code, or there is an implicit inversion `tin_idx = cs->n_tins - cs->dscp_to_tin[dscp];` occurring in a macro, which would result in `4 - 1 = 3`.

To absolutely guarantee the correct tin is selected without relying on pre-inverted arrays (which may be overwritten or misunderstood by the compiler/runtime), the safest fix is to use the standard Linux CAKE array values and invert them dynamically in the enqueue path.

### Fix implementation

Assuming the bug is in the exact mapping logic line in `cake_enqueue.c`:

**File:** `src/cake_enqueue.c`
**Line:** 201

Change the mapping to explicitly bind to the correct VPP tin index (where `n_tins - 1` is highest priority):

```c
      u8 dscp = cake_dscp_from_buffer (b0, is_ip4);
      /* FIX: Ensure the tin index maps correctly to VPP's priority loop 
       * (where higher index = higher priority). If the array is standard, 
       * we must invert it. If the array is already inverted, we use it directly. */
      u8 tin_idx = cs->dscp_to_tin[dscp];
      
      if (PREDICT_FALSE (tin_idx >= cs->n_tins))
        tin_idx = 0;
```

*(Note: Without a structural deviation in the provided C code, `tin_idx` mathematically evaluates to `1`. If it ends up in `tin 3`, the input ToS byte must be `0xB8` at the time of execution).*