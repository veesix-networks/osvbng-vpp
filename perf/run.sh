#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Clocks/Packet rig entry point (make vpp-perf): release VPP from the
# work volume, VPP's packet generator as the metronome, per-node cycle
# readout. Plugin PRs run this before and after and paste the table.
# Numbers are same-box relative, containerized, main thread only; see
# perf/README.md for the validity boundary.

set -euo pipefail
cd "$(dirname "$0")/.."
source build/builder.sh

ensure_builder

NAME=osvbng-vpp-perf
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
cleanup

docker run --rm --name "$NAME" --privileged \
  -v "$WORK_VOL":/work \
  -v "$PWD/perf":/perf \
  "$IMG" bash /perf/punt-baseline.sh
