# How the osvbng CAKE Scheduler Works

## The Problem: Bufferbloat

When a subscriber downloads a large file while gaming or on a video call, their internet feels slow and laggy — even though they have plenty of bandwidth. This is **bufferbloat**.

Here's what happens:

1. Netflix sends data as fast as it can
2. The BNG shapes the subscriber to their plan speed (e.g. 100 Mbps)
3. Excess packets queue up in buffers — inside the BNG, inside the DSLAM/OLT, inside the CPE
4. These buffers can hold hundreds of milliseconds of data
5. The gaming packets and VoIP packets sit behind all that Netflix data, waiting
6. Latency goes from 5ms to 500ms
7. The subscriber's game stutters and their video call breaks up

Traditional BNG QoS uses **policers** — they drop excess packets at a rate boundary. This enforces the speed limit but does nothing about the queuing. The buffers still fill up and latency still spikes.

## The Solution: CAKE

CAKE (Common Applications Kept Enhanced) is an algorithm originally created for Linux by Dave Taht and Jonathan Morton. It solves bufferbloat by replacing dumb packet queuing with intelligent traffic scheduling.

Instead of: "drop packets that exceed the rate" (policer)
CAKE does: "queue packets, pace them out at the exact rate, and actively manage the queue to keep latency low"

This plugin implements CAKE inside VPP's packet processing pipeline, making it available for per-subscriber scheduling on a BNG at line rate.

## How It Works — The Six Components

### 1. Token-Bucket Shaper

The shaper paces packets out at exactly the configured rate. Instead of bursting and dropping, it smoothly releases packets at even intervals.

At 100 Mbps, a 1500-byte packet is released every ~120 microseconds. No bursts, no downstream buffer buildup.

### 2. Per-Flow Queuing (Fair Queuing)

Every TCP/UDP flow gets its own queue. A flow is identified by its 5-tuple (source IP, destination IP, source port, destination port, protocol).

This means one greedy download can't starve other flows. If a subscriber is downloading a large file AND gaming AND on a video call, each activity gets its fair share of bandwidth automatically.

The flow lookup uses **set-associative hashing** — a 1024-entry table with 8-way sets, giving O(1) lookup with very low collision probability.

### 3. Deficit Round Robin (DRR)

DRR is the scheduling algorithm that decides which flow's packet to send next. Each flow gets a "deficit" (byte budget). When a flow's deficit runs out, it goes to the back of the line and the next flow gets a turn.

Flows are categorised as:
- **Sparse** — only one packet queued (interactive traffic like gaming, SSH, DNS). These get immediate service with no DRR overhead.
- **Bulk** — multiple packets queued (downloads, streaming). These share bandwidth fairly via DRR.
- **Decaying** — recently drained, kept briefly in case more packets arrive.

### 4. COBALT AQM (Active Queue Management)

COBALT is the core of what makes CAKE eliminate bufferbloat. It combines two algorithms:

**CoDel** (Controlled Delay): Monitors how long each packet sits in the queue (sojourn time). If packets are consistently queued for longer than 5ms, CoDel starts dropping packets at an increasing rate. This signals TCP senders to slow down, which reduces the queue, which reduces latency. The key insight: CoDel targets the **queue delay**, not the queue size.

**BLUE**: Catches unresponsive flows (like UDP floods) that ignore CoDel's signals. BLUE uses probabilistic drops — the more the queue overflows, the higher the drop probability. Unlike CoDel, BLUE always drops (never ECN-marks), because unresponsive senders won't react to ECN anyway.

**ECN** (Explicit Congestion Notification): When a TCP sender supports ECN, CoDel marks the packet with a CE (Congestion Experienced) flag instead of dropping it. The sender gets the congestion signal without losing data — faster reaction, no retransmission needed.

### 5. DiffServ Tins (Traffic Classes)

Traffic is classified into priority tins based on the DSCP field in the IP header:

| Mode | Tins | Use Case |
|------|------|----------|
| besteffort | 1 | All traffic treated equally |
| diffserv3 | 3 | Bulk, Best Effort, Voice |
| diffserv4 | 4 | Bulk, Best Effort, Video, Voice |
| diffserv8 | 8 | Full precedence mapping |

Higher-priority tins are served first (strict priority). Voice packets (EF/CS5) always go before bulk downloads. This means VoIP stays at sub-millisecond latency even when the link is fully loaded.

Each tin has its own set of flow queues, DRR scheduler, and COBALT AQM — they're completely independent.

### 6. Triple Isolation (Per-Host Fairness)

Behind a subscriber's CPE (router), there may be multiple devices — phones, laptops, TVs, IoT. Without triple isolation, a device running 10 flows gets 10x the bandwidth of a device running 1 flow.

Triple isolation adjusts each flow's DRR quantum based on how many bulk flows its host (destination IP) has. A host with 10 flows gets `quantum/10` per flow. A host with 1 flow gets the full quantum. Both hosts get equal aggregate bandwidth.

## VPP Integration

### Where It Sits in the Packet Path

```
Downstream packet arrives at BNG core interface
  → ip4-lookup (route to subscriber)
  → ip4-output feature arc
      → ip4-cake-enqueue ← CAKE captures the packet here
          → flow hash → per-flow ring buffer → DRR list
  → [packet held in scheduler queue]

cake-dequeue INPUT node (polls continuously)
  → shaper: is it time to send?
  → DRR: which flow's turn?
  → COBALT: should we drop/mark this packet?
  → re-inject to ip4-output arc
  → ip4-rewrite → tunnel-output → subscriber TX
```

### Owner-Thread Model

Each subscriber's scheduler is owned by exactly one VPP worker thread. If a packet for that subscriber arrives on a different worker (due to RSS), it's handed off to the owner thread via a lock-free frame queue. This ensures all scheduler state is single-writer — no locks in the data path.

### Ring Buffer Per Flow

Each flow's packet queue is a fixed-size power-of-2 ring buffer (128 entries). Enqueue and dequeue are each a single store/load + AND + increment — no allocator calls, no branches, no cache misses on the hot path.

## Key Performance Numbers

Measured on containerlab (af-packet, not production-representative):

| Metric | Value |
|--------|-------|
| Enqueue overhead | **347 cycles/packet** |
| Budget target | <500 cycles/packet |
| Shaping accuracy | ±5% of configured rate |
| DRR fairness | 10 flows share equally |

## What It Does NOT Do

- **Ingress (upload) scheduling** — the subscriber's upload is constrained by their access link, not the BNG. Upload uses standard VPP policers.
- **Replace policers entirely** — coexists with policers. Each subscriber can use either CAKE or a policer for egress, configured per service group.
- **Guarantee absolute latency numbers** — the 5ms CoDel target is for queue delay within the scheduler. End-to-end latency depends on the full network path.

## Configuration

```
# VPP CLI:
set cake scheduler ipoe_session0 rate 100000 diffserv4

# With overhead compensation for VDSL2:
set cake scheduler ipoe_session0 rate 50000 diffserv4 dsl-pppoe-ptm

# Show state:
show cake scheduler
```

In osvbng, the scheduler is configured via QoS policies in the service group and activated automatically on subscriber session creation.
