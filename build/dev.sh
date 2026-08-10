#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Plugin iteration loop (make vpp-dev): same builder image, same work
# and ccache volumes as build.sh, incremental ninja instead of a clean
# release build. No /out mount by design, so a dev build can never
# masquerade as a release artifact.
#
#   make vpp-dev                                incremental, all targets
#   VPP_DEV_BUILD=debug make vpp-dev            ASSERT-enabled tree
#   VPP_DEV_TARGET=osvbng_punt_plugin make vpp-dev   one plugin

set -euo pipefail
cd "$(dirname "$0")/.."
source build/builder.sh

ensure_builder

NAME=osvbng-vpp-dev
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
cleanup

docker run --rm --name "$NAME" \
  -e VPP_TAG="$TAG" \
  -e VPP_DEV_BUILD="${VPP_DEV_BUILD:-release}" \
  -e VPP_DEV_TARGET="${VPP_DEV_TARGET:-}" \
  -v "$WORK_VOL":/work \
  -v "$CCACHE_VOL":/ccache \
  -v "$PWD/plugins":/plugins:ro \
  -v "$PWD/build/inner-dev.sh":/inner-dev.sh:ro \
  -v "$PWD/build/glue-plugins.sh":/glue-plugins.sh:ro \
  "$IMG" bash /inner-dev.sh
