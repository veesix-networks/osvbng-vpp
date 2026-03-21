# Phase 6 DSCP Review — Codex

**Date:** 2026-03-21
**Scope reviewed:** `src/osvbng_qos_sched.h`, `src/cake_enqueue.c`, `src/osvbng_qos_sched.c`

## Conclusion

The bug is **not** in the `diffserv4` table pointer setup, and it is **not** in the `cs->dscp_to_tin[dscp]` lookup.

The actual bug is that the enqueue-path header helpers assume `vlib_buffer_get_current (b)` already points at the IP header. That is not a safe assumption for a TX feature node on the `ip4-output` / `ip6-output` arcs. On egress, VPP commonly requires you to recover L3 using saved header metadata (`vnet_buffer(b)->l3_hdr_offset` or `vnet_buffer(b)->ip.save_rewrite_length`), not raw `current_data`.

Because `cake_dscp_from_buffer()` reads from the wrong cursor, DSCP classification can consume some other byte from the packet/rewrite area instead of the IPv4 TOS byte. That produces a bogus DSCP value, and in `diffserv4` those bogus values can easily map to tin `3`.

This explains the observed symptom:

- `src/osvbng_qos_sched.c:49-63` says `cake_dscp_diffserv4[0] == 1`
- `src/osvbng_qos_sched.c:186-188` correctly installs that table for `diffserv4`
- `src/cake_enqueue.c:200-203` correctly uses the resulting tin index
- yet all traffic still lands in tin `3`

So the only reviewed place left that can produce the wrong tin is the DSCP extraction itself.

## Finding

### Wrong header base on TX path

- **Location:** `src/osvbng_qos_sched.h:244-250`
- **Failure mode:** `cake_dscp_from_buffer()` does:

```c
ip4_header_t *ip4 = vlib_buffer_get_current (b);
return ip4->tos >> 2;
```

and similarly for IPv6. In the CAKE plugin, this helper is called from the enqueue node attached to `ip4-output` / `ip6-output` (`src/cake_enqueue.c:200`, `src/osvbng_qos_sched.c:239-242`). On that egress path, `current_data` is not guaranteed to be L3. VPP output-path code typically derives the L3 header from metadata instead:

- `b->data + vnet_buffer(b)->l3_hdr_offset` when `VNET_BUFFER_F_L3_HDR_OFFSET_VALID` is set
- otherwise `vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length`

If CAKE reads from raw `current_data`, it can classify on non-IP bytes. That gives a wrong DSCP index and therefore a wrong tin.

This also explains why the symptom can be stable. One concrete example: if the misread byte happens to be `0x80`, then `0x80 >> 2 == 32`, and `cake_dscp_diffserv4[32] == 3`, which is exactly the observed “all BE traffic goes to tin 3” outcome.

## Not The Bug

### 1. `dscp_to_tin` pointer setup

- **Reviewed lines:** `src/osvbng_qos_sched.c:74-79`, `src/osvbng_qos_sched.c:186-188`
- **Verdict:** Correct.
- `CAKE_TIN_MODE_DIFFSERV4` is `2`, `cake_dscp_tables[2]` is `cake_dscp_diffserv4`, and `cs->n_tins` is set to `4` from the matching count table.

### 2. Tin lookup usage

- **Reviewed lines:** `src/cake_enqueue.c:200-203`
- **Verdict:** Correct.
- `u8 tin_idx = cs->dscp_to_tin[dscp];` is the expected lookup.
- The bounds check `if (tin_idx >= cs->n_tins) tin_idx = 0;` is defensive but not the source of this bug.

### 3. `dscp_to_tin` / tins overwritten after enable

- **Reviewed lines:** `src/osvbng_qos_sched.c:172-259`
- **Verdict:** No evidence in the reviewed code.
- After enable, the reviewed code does not rewrite `cs->dscp_to_tin`, `cs->tin_mode`, or `cs->n_tins`.

## Fix

Use a helper that resolves the L3 header from VPP metadata, then make `cake_dscp_from_buffer()` read from that resolved L3 header instead of raw `vlib_buffer_get_current()`.

```c
/* src/osvbng_qos_sched.h */
static_always_inline const u8 *
cake_l3_header (vlib_buffer_t *b)
{
  if (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    return b->data + vnet_buffer (b)->l3_hdr_offset;

  return (const u8 *) vlib_buffer_get_current (b) +
         vnet_buffer (b)->ip.save_rewrite_length;
}

static_always_inline u8
cake_dscp_from_buffer (vlib_buffer_t *b, u8 is_ip4)
{
  const u8 *l3 = cake_l3_header (b);

  if (is_ip4)
    {
      const ip4_header_t *ip4 = (const ip4_header_t *) l3;
      return (ip4->tos >> 2) & 0x3f;
    }
  else
    {
      const ip6_header_t *ip6 = (const ip6_header_t *) l3;
      u32 vtcfl = clib_net_to_host_u32 (
        ip6->ip_version_traffic_class_and_flow_label);
      return (vtcfl >> 22) & 0x3f;
    }
}
```

## Follow-On Fixes

The same bad assumption exists in other enqueue-path helpers in `src/osvbng_qos_sched.h`:

- `cake_dst_host_hash()` at `src/osvbng_qos_sched.h:257-268`
- `cake_hash_flow()` at `src/osvbng_qos_sched.h:445-485`

Those should be switched to the same `cake_l3_header()` helper as well. Even if flow hashing appears to “work” in testing, it is currently parsing from the same unsafe base pointer as DSCP classification.

## Bottom Line

The reviewed `diffserv4` table and `dscp_to_tin` setup are correct. The real bug is the unsafe use of `vlib_buffer_get_current()` in `cake_dscp_from_buffer()` on the egress feature arc. Fix the L3 header lookup, and DSCP 0 will index the real IPv4 TOS byte and map through `cake_dscp_diffserv4[0]` as intended.
