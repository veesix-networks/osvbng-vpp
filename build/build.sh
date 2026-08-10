#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Release build entry point (make vpp-build): clean tree, patch queue
# applied, all plugins glued into the VPP source, debs into dist/.
# Host-agnostic: any docker host with ~50G free runs this identically.
# This is the ONLY path that produces release artifacts; the dev loop
# (dev.sh) never writes to dist/.

set -euo pipefail
cd "$(dirname "$0")/.."
source build/builder.sh

ensure_builder
mkdir -p dist

NAME=osvbng-vpp-build
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
cleanup

docker run --rm --name "$NAME" \
  -e VPP_TAG="$TAG" \
  -v "$WORK_VOL":/work \
  -v "$CCACHE_VOL":/ccache \
  -v "$PWD/patches":/patches:ro \
  -v "$PWD/plugins":/plugins:ro \
  -v "$PWD/dist":/out \
  -v "$PWD/build/inner-build.sh":/inner-build.sh:ro \
  -v "$PWD/build/glue-plugins.sh":/glue-plugins.sh:ro \
  "$IMG" bash /inner-build.sh
