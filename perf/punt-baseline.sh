#!/bin/bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Runs INSIDE the build container: osvbng_punt Clocks/Packet scenarios.
# Each scenario offers a continuous pg stream under two load profiles,
# clears the runtime counters, waits a window, reads per-node clocks:
#
#   paced      vectors near 1: an idle dataplane taking occasional
#              control frames; worst-case per-packet cost
#   saturated  pg flat out, vectors toward 256: where batching either
#              shows up or does not; regressions are judged HERE
#
# Scenarios: default policer against a storm (the policed path), and
# unlimited policer with no shm consumer (the ring-full shed path).
# The punted/dropped counters are printed so a blended number says it
# is blended. Release build only.

set -euo pipefail

B=/work/vpp/build-root/build-vpp-native/vpp
export LD_LIBRARY_PATH=$B/lib/x86_64-linux-gnu
mkdir -p /run/vpp

MEASURE_SECONDS=${MEASURE_SECONDS:-5}
NODES="osvbng-punt-dhcp ethernet-input ip4-input ip4-udp-lookup"

cat > /tmp/perf-startup.conf <<EOF
unix { nodaemon log /tmp/vpp.log cli-listen /run/vpp/cli.sock gid 0 }
cpu { main-core 0 }
memory { main-heap-size 512M }
buffers { buffers-per-numa 65536 }
plugins {
  path $B/lib/x86_64-linux-gnu/vpp_plugins
  plugin dpdk_plugin.so { disable }
  plugin osvbng_punt_plugin.so { enable }
}
EOF

$B/bin/vpp -c /tmp/perf-startup.conf &
until $B/bin/vppctl -s /run/vpp/cli.sock show version >/dev/null 2>&1; do sleep 1; done
cli() { $B/bin/vppctl -s /run/vpp/cli.sock "$@"; }

cli create packet-generator interface pg0
cli set interface state pg0 up
cli set interface ip address pg0 10.0.0.1/24
MAC=$(cli show hardware-interfaces pg0 | grep -oE "([0-9a-f]{2}:){5}[0-9a-f]{2}" | head -1)

stream() { # name [rate]; no rate = flat out
  local rate=""
  [ -n "${2:-}" ] && rate="rate $2"
  cli packet-generator new "name $1 limit 0 $rate node ethernet-input source pg0 size 300-300 data { IP4: 02:00:00:00:00:02 -> $MAC UDP: 10.0.0.2 -> 10.0.0.1 UDP: 68 -> 67 incrementing 200 }"
}

sample() {
  cli clear runtime
  cli clear errors
  sleep "$MEASURE_SECONDS"
  printf '%-20s %14s %14s %12s\n' node clocks/pkt vectors/call pkts
  for node in $NODES; do
    cli show runtime | awk -v n="$node" \
      '$1==n {printf "%-20s %14s %14s %12s\n", $1, $6, $7, $4}'
  done
  cli show errors | grep -E "osvbng-punt" | sed 's/^/    /' || true
}

measure() { # label stream-name paced-rate
  echo "--- $1, paced ${3}pps"
  stream "$2-paced" "$3"
  cli packet-generator enable
  sample
  cli packet-generator disable
  cli packet-generator delete "$2-paced"

  echo "--- $1, saturated (pg flat out)"
  stream "$2-flat"
  cli packet-generator enable
  sample
  cli packet-generator disable
  cli packet-generator delete "$2-flat"
}

echo "== osvbng_punt Clocks/Packet"
echo "== $(cli show version | head -1)"
echo "== window ${MEASURE_SECONDS}s, containerized main thread: compare"
echo "== runs on the same box only."

cli osvbng punt enable pg0 protocol dhcpv4

measure "policed storm, default policer" policed 5e4

cli osvbng punt policer protocol dhcpv4 rate 1000000 burst 100000
measure "ring-full shed, no shm consumer" shed 5e4

echo "--- memory"
cli show memory main-heap | head -3 | sed 's/^/    /'
cli show buffers | sed 's/^/    /'

echo "== done"
