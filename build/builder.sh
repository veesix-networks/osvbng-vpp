#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared plumbing for the build container. Sourced by build.sh (release
# artifacts) and dev.sh (incremental loop) so both always use the same
# image and the same volumes: a dev build against a different tree than
# the release build would be worthless as a check.

TAG="${VPP_TAG:-v26.06}"
# The distro is part of the build environment's identity: artifacts
# must install on the runtime image's distro, so a base change means a
# different builder image and different volumes, never an in-place
# mutation of the old ones.
DISTRO=debian12
IMG="osvbng-vpp-builder:${TAG}-${DISTRO}"
WORK_VOL=osvbng-vpp-work-${DISTRO}
CCACHE_VOL=osvbng-vpp-ccache-${DISTRO}

ensure_builder() {
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    docker build -t "$IMG" --build-arg VPP_TAG="$TAG" \
      -f build/Dockerfile.builder build
  fi
  docker volume create "$WORK_VOL" >/dev/null
  docker volume create "$CCACHE_VOL" >/dev/null
}
