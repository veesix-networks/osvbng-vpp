#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared plumbing for the build container. Sourced by build.sh (release
# artifacts) and dev.sh (incremental loop) so both always use the same
# image and the same volumes: a dev build against a different tree than
# the release build would be worthless as a check.

TAG="${VPP_TAG:-v26.06}"
IMG="osvbng-vpp-builder:${TAG}"
WORK_VOL=osvbng-vpp-work
CCACHE_VOL=osvbng-vpp-ccache

ensure_builder() {
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    docker build -t "$IMG" --build-arg VPP_TAG="$TAG" \
      -f build/Dockerfile.builder build
  fi
  docker volume create "$WORK_VOL" >/dev/null
  docker volume create "$CCACHE_VOL" >/dev/null
}
