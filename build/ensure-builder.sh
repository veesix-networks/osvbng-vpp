#!/usr/bin/env bash
# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Builds the builder image and creates the work and ccache volumes if
# they are missing, then exits. The make targets do this inline via
# builder.sh; the devcontainer runs it as initializeCommand so the
# image and volumes exist before the container it opens into mounts
# them. One place decides what "the build environment" is.

set -euo pipefail
cd "$(dirname "$0")/.."
source build/builder.sh
ensure_builder
