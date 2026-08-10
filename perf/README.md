# Clocks/Packet rig

`make vpp-perf`: release VPP under packet-generator load, per-node
cycle and memory readout. Plugin PRs run it before and after a change
and paste the table.

## What a containerized run legitimately claims

`show runtime` clocks are cycles the node's own code consumed per
packet. They measure algorithmic cost (branches, working-set cache
behavior, copies) at both ends of the load curve:

- **Paced** (vectors near 1): an idle dataplane taking occasional
  control frames; worst-case per-packet cost, batching contributes
  nothing.
- **Saturated** (vectors at 256): where dual loops, prefetch and
  interrupt coalescing either show up or do not. Judged numbers come
  from HERE; a vector-1-only rig misprices a batched node by an order
  of magnitude.

Valid use: same box, relative, before/after. Memory is read at the
end; punt paths allocate nothing per packet, so heap growth between
two runs is itself a finding.

## What it cannot claim

Absolute throughput, NIC/RSS/multi-worker behavior (dpdk is disabled,
main thread only), or cache-miss attribution (no PMU in the
container). Platform numbers come from real hardware with real NICs
under bngblaster load; this rig exists so a PR cannot make a node
quietly more expensive between hardware sessions.
