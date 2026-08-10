# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: vpp-build vpp-dev vpp-perf

# Release: clean tree, patch queue, all plugins, debs into dist/.
vpp-build:
	./build/build.sh

# Incremental plugin loop in the same container; never produces
# release artifacts (build/dev.sh for the knobs).
vpp-dev:
	./build/dev.sh

# Clocks/Packet regression rig; plugin PRs run this before and after.
vpp-perf:
	./perf/run.sh
