# QoS Plugin Testing

## Current Setup (Temporary)

Phase benchmarks use containerlab test 18 (`ipoe-linux-client`) with af-packet interfaces. This is adequate for validating correctness and tracking **relative** overhead between phases, but is NOT representative of production performance.

### Limitations

- **af-packet**: kernel-mediated I/O, not zero-copy — adds latency and jitter
- **No CPU pinning**: VPP workers share cores with OS, containerlab, iperf3
- **veth pairs**: containerlab links are veth, not PCIe/DPDK
- **No hugepages isolation**: shared with host

Results are useful for: phase-over-phase clocks/vector comparison, functional validation, pipeline correctness.

Results are NOT useful for: absolute PPS numbers, production capacity planning, tail latency benchmarks.

### Production Benchmark Environment (TODO)

- Bare metal or QEMU with isolated cores (`isolcpus`, `nohz_full`)
- DPDK interfaces (10G/25G NICs, SR-IOV or full passthrough)
- Dedicated traffic generator (TRex or bng-blaster with hardware timestamping)
- CPU pinning: VPP main + workers on dedicated cores, traffic gen on separate NUMA node
- Hugepages: 1G pages, pre-allocated at boot
- Repeat with multiple subscriber counts (1, 10, 100, 1000) to measure scaling

## Running Benchmarks

### Prerequisites

1. Deploy test 18 topology:
   ```bash
   sudo containerlab deploy -t tests/18-ipoe-linux-client/18-ipoe-linux-client.clab.yml
   ```

2. Wait for IPoE session to establish:
   ```bash
   docker exec clab-osvbng-ipoe-linux-client-bng1 \
     vppctl -s /var/run/osvbng/cli.sock show interface | grep ipoe_session
   ```

3. Install iperf3 on subscriber and core router:
   ```bash
   docker exec clab-osvbng-ipoe-linux-client-subscriber sh -c "apk add --no-cache iperf3"
   docker exec clab-osvbng-ipoe-linux-client-corerouter1 sh -c "apk add --no-cache iperf3"
   ```

4. Start iperf3 server on subscriber:
   ```bash
   docker exec clab-osvbng-ipoe-linux-client-subscriber iperf3 -s -D
   ```

5. Verify connectivity:
   ```bash
   docker exec clab-osvbng-ipoe-linux-client-subscriber ping -c 2 10.0.0.2
   ```

### Run Benchmark

```bash
pipx run --spec ttp python3 tests/benchmark.py --phase "phase1-fifo-shaper"

# All options:
pipx run --spec ttp python3 tests/benchmark.py \
  --interface ipoe_session0 \
  --rate 100000 \
  --runs 5 \
  --duration 10 \
  --phase "phase1-fifo-shaper"
```

### What It Measures

**Baseline (no scheduler):** 5 downstream iperf3 runs, captures:
- `ip4-lookup`, `ip4-midchain`, `tunnel-output` clocks/vector

**Shaped (scheduler enabled):** 5 downstream iperf3 runs, captures:
- `ip4-cake-enqueue` clocks/vector — enqueue overhead per packet
- `cake-dequeue` clocks/vector — dequeue + shaping overhead per packet
- Enqueued/dropped packet counts
- Vectors/call — batch efficiency

### Key Metrics

| Metric | What It Means | Target |
|--------|--------------|--------|
| `ip4-cake-enqueue` clocks/vector | CPU cycles to classify + queue one packet | Track growth per phase |
| `cake-dequeue` clocks/vector | CPU cycles to shape + dequeue + re-inject one packet | Track growth per phase |
| Vectors/call | Packets processed per node invocation (batching) | Higher is better (>4) |
| Dropped | Tail-drop from buffer overflow | Should stabilise after initial burst |

### Phase-over-Phase Summary

The key regression metric is `ip4-cake-enqueue` c/v — this is the per-packet CPU overhead added to the forwarding path. Baseline forwarding (no scheduler) costs ~271 c/v (`ip4-lookup` 113 + `ip4-midchain` 96 + `tunnel-output` 62).

| Phase | enqueue c/v | Delta vs Phase 1 | Description |
|-------|------------|-------------------|-------------|
| 1 | **282** | — | FIFO + token-bucket shaper |
| 2 | | | Per-flow queuing + DRR |
| 3 | | | COBALT AQM (CoDel + BLUE) |
| 4 | | | DiffServ tins |
| 5 | | | Overhead compensation (ATM/PTM/GPON) |
| 6 | | | Triple isolation (per-host fairness) |

### Phase History

Record full results here after each phase benchmark.

#### Phase 1: FIFO + Token-Bucket Shaper (2026-03-20)

Environment: containerlab af-packet, 100 Mbps shaper, 10s iperf3, 5 runs

**Baseline (no scheduler):**

| Run | Bitrate | ip4-lookup c/v | ip4-midchain c/v | tunnel-output c/v | Vectors |
|-----|---------|---------------|-----------------|-------------------|---------|
| 1 | 4.43 Gbits/sec | 105 | 94 | 60 | 620665 |
| 2 | 4.29 Gbits/sec | 105 | 97 | 61 | 600307 |
| 3 | 4.27 Gbits/sec | 132 | 97 | 64 | 597934 |
| 4 | 4.36 Gbits/sec | 103 | 98 | 63 | 609668 |
| 5 | 4.36 Gbits/sec | 122 | 94 | 60 | 610315 |
| **Mean** | **4.34 Gbits/sec** | **113** | **96** | **62** | **607778** |

**Shaped (100 Mbps):**

| Run | Bitrate | enqueue c/v | dequeue c/v | Enqueued | Dropped | Vec/Call |
|-----|---------|------------|------------|----------|---------|----------|
| 1 | 121 Mbits/sec | 287 | 241000 | 24659 | 22 | 5.34 |
| 2 | 123 Mbits/sec | 281 | 240000 | 42254 | 38 | 5.34 |
| 3 | 123 Mbits/sec | 281 | 249000 | 59855 | 54 | 5.35 |
| 4 | 123 Mbits/sec | 277 | 229000 | 77494 | 65 | 5.34 |
| 5 | 123 Mbits/sec | 283 | 237000 | 95110 | 76 | 5.29 |
| **Mean** | **123 Mbits/sec** | **282** | **239200** | — | — | **5.33** |

**Notes:**
- enqueue c/v (282) is the per-packet overhead added to the forwarding path
- dequeue c/v is high (~239K) because the INPUT polling node spends most cycles polling with nothing eligible (shaper pacing) — this is expected and not a per-packet cost
- Enqueued/Dropped are cumulative (scheduler kept enabled across runs)
