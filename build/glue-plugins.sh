#!/bin/bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Glues the plugin suite into the VPP source tree, INSIDE the build
# container. VPP's src/plugins/CMakeLists.txt globs every subdirectory
# holding a CMakeLists.txt, so a symlink per plugin is the whole
# mechanism: no vendoring, no out-of-tree build, and the plugins
# compile against the exact patched tree they will run on. Stale links
# are removed so a deleted plugin cannot linger in the persistent work
# volume.

set -euo pipefail

src=${1:-/plugins}
dst=${2:-/work/vpp/src/plugins}

for link in "$dst"/*; do
  [ -L "$link" ] || continue
  name=$(basename "$link")
  if [ ! -d "$src/$name" ]; then
    echo "unlinking stale plugin $name"
    rm -f "$link"
  fi
done

count=0
shopt -s nullglob
for dir in "$src"/*/; do
  name=$(basename "$dir")
  # A directory without CMakeLists.txt is silently ignored by VPP's
  # glob, which reads as "my plugin did not build" much later.
  if [ ! -f "$dir/CMakeLists.txt" ]; then
    echo "skipping $name: no CMakeLists.txt" >&2
    continue
  fi
  ln -sfn "$src/$name" "$dst/$name"
  count=$((count + 1))
done

echo "glued $count plugin(s) into $dst"
