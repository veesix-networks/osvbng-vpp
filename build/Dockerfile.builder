# Copyright 2026 The osvbng Authors
# Licensed under the GNU General Public License v3.0 or later.
# SPDX-License-Identifier: GPL-3.0-or-later

# Build image with VPP's build dependencies baked at the pinned tag, so
# runtime builds never apt-install. Rebuild this image only on a VPP
# version bump: dependency layers changing between builds is how ABI
# surprises happen.

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git make sudo curl ca-certificates ccache python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*

ARG VPP_TAG=v26.06
RUN git clone --depth 1 --branch ${VPP_TAG} https://github.com/FDio/vpp.git /tmp/vpp \
    && cd /tmp/vpp \
    && UNATTENDED=yes make install-dep \
    && rm -rf /tmp/vpp /var/lib/apt/lists/*

ENV CCACHE_DIR=/ccache
WORKDIR /work
