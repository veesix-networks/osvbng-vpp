#!/bin/bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Runs INSIDE the build container: fetch the pinned VPP, apply the
# patch queue in order, glue the plugin suite into the tree, build debs
# into /out. Dataplane and plugins ship as one versioned artifact set,
# which removes the plugin-ABI-drift failure class entirely. The tree
# is cleaned before every release build: never trust incremental
# dataplane builds for artifacts; ccache keeps that honest without
# being slow.

set -euo pipefail

TAG="${VPP_TAG:-v26.06}"
cd /work

if [ ! -d vpp/.git ]; then
  git clone https://github.com/FDio/vpp.git vpp
fi
cd vpp
git fetch --tags --force origin
git checkout -f "$TAG"
git clean -fdx

shopt -s nullglob
patches=(/patches/*.patch)
if [ ${#patches[@]} -gt 0 ]; then
  for p in "${patches[@]}"; do
    echo "applying $(basename "$p")"
    git apply --verbose "$p"
  done
else
  echo "patch queue empty"
fi

bash /glue-plugins.sh

UNATTENDED=yes make install-dep
make pkg-deb

mkdir -p /out
rm -f /out/*.deb
cp build-root/*.deb /out/
echo "== artifacts:"
ls -la /out/
ccache -s | head -6 || true
