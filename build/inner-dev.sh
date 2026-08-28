#!/bin/bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Runs INSIDE the build container: the plugin iteration loop. Same
# image, volumes and patched tree as inner-build.sh, minus everything
# that makes a release build slow: no clean, no re-fetch, no patch
# re-apply, no artifacts. cmake regenerates only when the plugin set
# changes; ninja rebuilds what changed, so an edit-compile cycle is
# seconds instead of an hour. Release debs come from build.sh only.

set -euo pipefail

BUILD="${VPP_DEV_BUILD:-release}"
case "$BUILD" in
  # Release is the default: it is what ships and the only build
  # performance numbers may come from. Debug adds VPP's ASSERTs, which
  # catch plugin bugs (bihash misuse, buffer accounting) long before a
  # lab does; the debug tree costs roughly another 8G in the work
  # volume, so build it when you want the asserts, not by habit.
  release) dir=build-root/build-vpp-native/vpp; bootstrap=build-release ;;
  debug)   dir=build-root/build-vpp_debug-native/vpp; bootstrap=build ;;
  *) echo "VPP_DEV_BUILD must be release or debug, got '$BUILD'" >&2; exit 2 ;;
esac

if [ ! -d /work/vpp/.git ]; then
  echo "no VPP source tree in the work volume: run make vpp-build first" >&2
  exit 1
fi
cd /work/vpp

# The builder image bakes the build dependencies at the pinned tag, so
# the stamp VPP's build targets expect is a statement of fact here.
mkdir -p build-root && touch build-root/.deps.ok

# Docker mode mounts these at fixed paths; the devcontainer runs this
# script straight from the workspace and points them at the checkout.
bash "${GLUE:-/glue-plugins.sh}" "${PLUGINS_DIR:-/plugins}"

# The stamp tracks what was actually glued, not what sits in /plugins:
# a directory the glue skipped must not force a cmake regeneration on
# every run. Empty is a valid answer.
plugins=$(cd src/plugins && for e in *; do if [ -L "$e" ]; then printf '%s ' "$e"; fi; done)
stamp="$dir/.osvbng-plugins"

if [ ! -f "$dir/build.ninja" ]; then
  echo "== configuring $BUILD tree (first dev build, this one is slow)"
  make "$bootstrap"
elif [ "$(cat "$stamp" 2>/dev/null || true)" != "$plugins" ]; then
  # VPP globs plugin directories without CONFIGURE_DEPENDS, so cmake
  # cannot see a plugin that appeared since the last configure.
  echo "== plugin set changed, regenerating cmake"
  cmake "$dir"
fi

ninja -C "$dir" ${VPP_DEV_TARGET:+"$VPP_DEV_TARGET"}

# ninja does not delete the .so of a target that no longer exists, so a
# removed plugin would keep loading from this tree and look alive in a
# lab. Drop what left the glued set.
for gone in $(cat "$stamp" 2>/dev/null || true); do
  case " $plugins " in
    *" $gone "*) continue ;;
  esac
  find "$dir" -name "${gone}_plugin.so" -delete -printf 'removed stale %f\n'
done
echo "$plugins" >"$stamp"

# A glued plugin that produces no .so while ninja reports success means
# add_vpp_plugin named a different target than the directory: the
# plugin is silently absent from the build, the worst failure mode to
# discover in a lab. Not a failure under VPP_DEV_TARGET, which builds
# one thing on purpose.
#
# Only ninja's output under lib/ counts. The deb staging tree under
# CMakeFiles/debian keeps copies from the last release build, and a
# search of the whole tree can list one of those as this build's
# binary, which is how a stale plugin reaches a lab.
echo "== plugin binaries:"
missing=0
for name in $plugins; do
  found=$(find "$dir/lib" -name "${name}_plugin.so" -printf '%p\n' -quit)
  if [ -z "$found" ]; then
    echo "   $name: no ${name}_plugin.so produced" >&2
    missing=1
  else
    echo "   $found"
  fi
done
if [ "$missing" = 1 ] && [ -z "${VPP_DEV_TARGET:-}" ]; then
  echo "plugin target name must match its directory name" >&2
  exit 1
fi
echo "== vpp: $dir/bin/vpp"
ccache -s | head -4 || true
