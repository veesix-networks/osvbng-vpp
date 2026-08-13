#!/usr/bin/env python3
# Copyright 2026 Veesix Networks Ltd
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Phase benchmark script for osvbng QoS scheduler plugin.

Usage:
  pipx run --spec ttp python3 tests/benchmark.py --phase "phase1-fifo-shaper"

Prerequisites:
  - containerlab topology deployed (test 18: ipoe-linux-client)
  - iperf3 installed on subscriber and corerouter1
  - IPoE session established and connectivity verified

TEMPORARY manual testing process using af-packet (containerlab).
"""

import argparse
import logging
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

logging.getLogger("ttp").setLevel(logging.CRITICAL)

from ttp import ttp


BNG = "clab-osvbng-ipoe-linux-client-bng1"
CORE = "clab-osvbng-ipoe-linux-client-corerouter1"
SUB = "clab-osvbng-ipoe-linux-client-subscriber"
VPPCTL = "vppctl -s /var/run/osvbng/cli.sock"

VPP_RUNTIME_TEMPLATE = """
<group name="nodes*">
{{ name }} {{ state }} {{ calls | to_int }} {{ vectors | to_int }} {{ suspends | to_int }} {{ clocks | to_float }} {{ vec_call | to_float }}
</group>
"""

VPP_SCHED_TEMPLATE = """
<group name="schedulers*">
  {{ interface }}: rate {{ rate_bps | to_int }} B/s ({{ rate_kbps | to_int }} kbps), overhead {{ overhead | to_int }}, queue {{ queue_pkts | to_int }} pkts {{ queue_bytes | to_int }}/{{ buffer_limit | to_int }} bytes
    enqueued: {{ enqueued_pkts | to_int }} pkts {{ enqueued_bytes | to_int }} bytes, dequeued: {{ dequeued_pkts | to_int }} pkts {{ dequeued_bytes | to_int }} bytes, dropped: {{ dropped_pkts | to_int }} pkts
</group>
"""


def docker_exec(container, cmd):
    result = subprocess.run(
        ["docker", "exec", container] + cmd.split(),
        capture_output=True, text=True, timeout=120,
    )
    return result.stdout + result.stderr


def vpp(cmd):
    return docker_exec(BNG, f"{VPPCTL} {cmd}")


def restart_iperf_server():
    docker_exec(SUB, "sh -c killall iperf3")
    time.sleep(1)
    docker_exec(SUB, "iperf3 -s -D")
    time.sleep(1)


def run_iperf(duration):
    return docker_exec(CORE, f"iperf3 -c 10.255.0.2 -t {duration}")


def parse_bitrate(iperf_output):
    for line in iperf_output.splitlines():
        if "receiver" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p in ("Gbits/sec", "Mbits/sec", "Kbits/sec"):
                    return f"{parts[i-1]} {p}"
    return "n/a"


def parse_runtime(runtime_output):
    """Parse VPP show runtime output via TTP.

    Returns dict: node_name -> {calls, vectors, clocks, vec_call}
    For nodes on multiple threads, keeps the one with most vectors.
    """
    parser = ttp(data=runtime_output, template=VPP_RUNTIME_TEMPLATE)
    parser.parse()
    results = parser.result()

    nodes = {}
    for result_set in results:
        for group in result_set:
            for node in group.get("nodes", []):
                name = node.get("name", "")
                vectors = node.get("vectors", 0)
                if vectors <= 0:
                    continue
                if name not in nodes or vectors > nodes[name]["vectors"]:
                    nodes[name] = node

    return nodes


def parse_sched(sched_output):
    parser = ttp(data=sched_output, template=VPP_SCHED_TEMPLATE)
    parser.parse()
    results = parser.result()

    for result_set in results:
        for group in result_set:
            scheds = group.get("schedulers", [])
            if scheds:
                return scheds[0]

    return {"enqueued_pkts": 0, "dropped_pkts": 0}


def run_benchmark(iface, rate, runs, duration, phase):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print("=" * 60)
    print(f"  osvbng QoS Scheduler Benchmark")
    print(f"  Phase:     {phase}")
    print(f"  Interface: {iface}")
    print(f"  Rate:      {rate} kbps")
    print(f"  Runs:      {runs} (baseline) + {runs} (shaped)")
    print(f"  Duration:  {duration}s per run")
    print(f"  Date:      {now}")
    print("=" * 60)
    print()

    # --- Baseline ---
    print("--- Baseline (no scheduler) ---")
    print()
    print(f"{'Run':<4}  {'Bitrate':<20}  {'ip4-lookup c/v':<16}  {'ip4-midchain c/v':<18}  {'tunnel-out c/v':<16}  {'Vectors':<10}")

    for i in range(1, runs + 1):
        restart_iperf_server()
        vpp("clear runtime")
        iperf_out = run_iperf(duration)
        bitrate = parse_bitrate(iperf_out)
        nodes = parse_runtime(vpp("show runtime"))

        lookup = nodes.get("ip4-lookup", {}).get("clocks", 0)
        midchain = nodes.get("ip4-midchain", {}).get("clocks", 0)
        tunnel = nodes.get("tunnel-output", {}).get("clocks", 0)
        vectors = nodes.get("ip4-midchain", {}).get("vectors", 0)

        print(f"{i:<4}  {bitrate:<20}  {lookup:<16.0f}  {midchain:<18.0f}  {tunnel:<16.0f}  {vectors:<10.0f}")

    print()

    # --- Shaped ---
    print(f"--- Shaped (scheduler at {rate} kbps) ---")
    print()
    print(f"{'Run':<4}  {'Bitrate':<20}  {'enqueue c/v':<14}  {'dequeue c/v':<14}  {'Enqueued':<10}  {'Dropped':<10}  {'Vec/Call':<10}")

    vpp(f"set cake scheduler {iface} rate {rate}")
    # Warmup run to fill shaper credit and stabilise TCP
    print("  (warmup run...)")
    run_iperf(5)

    for i in range(1, runs + 1):
        restart_iperf_server()
        vpp("clear runtime")
        iperf_out = run_iperf(duration)
        bitrate = parse_bitrate(iperf_out)
        nodes = parse_runtime(vpp("show runtime"))
        sched = parse_sched(vpp("show cake scheduler"))

        enq_cv = nodes.get("ip4-cake-enqueue", {}).get("clocks", 0)
        deq_cv = nodes.get("cake-dequeue", {}).get("clocks", 0)
        vec_call = nodes.get("ip4-cake-enqueue", {}).get("vec_call", 0)
        enqueued = sched.get("enqueued_pkts", 0)
        dropped = sched.get("dropped_pkts", 0)

        print(f"{i:<4}  {bitrate:<20}  {enq_cv:<14.0f}  {deq_cv:<14.0f}  {enqueued:<10}  {dropped:<10}  {vec_call:<10.2f}")

    vpp(f"set cake scheduler {iface} disable")

    print()
    print("=" * 60)
    print("  Benchmark complete")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="osvbng QoS scheduler benchmark")
    parser.add_argument("--interface", default="ipoe_session0")
    parser.add_argument("--rate", type=int, default=100000, help="Rate in kbps")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--duration", type=int, default=10, help="iperf3 duration in seconds")
    parser.add_argument("--phase", default="unknown")
    args = parser.parse_args()

    run_benchmark(args.interface, args.rate, args.runs, args.duration, args.phase)
