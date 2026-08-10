# osvbng-vpp

VPP dataplane for [osvbng](https://github.com/veesix-networks/osvbng):
all osvbng VPP plugins and the containerized build that produces VPP
and the plugins as one versioned artifact set.

VPP is built from a pinned upstream tag with a reviewed patch queue
applied (`patches/`), then every plugin under `plugins/` builds inside
that exact tree. One pipeline, one artifact set: the plugin ABI in a
release can never drift from the VPP underneath it.

## Building

Requires docker and roughly 50G free disk. The build runs in a
container with VPP's build dependencies baked at the pinned tag; no
host toolchain is used.

```
make vpp-build   # release: clean tree, patches, all plugins, debs in dist/
make vpp-dev     # incremental plugin loop (seconds per edit)
make vpp-perf    # per-node cycle regression rig
```

`build/dev.sh` documents the dev-loop knobs (debug tree, single
target).

## Layout

```
build/     containerized build pipeline
patches/   VPP patch queue (format and policy in patches/README.md)
plugins/   one directory per plugin, glued into the VPP tree at build
perf/      Clocks/Packet regression rig
dist/      release debs (untracked)
```

## Status

Consolidation of the previously separate osvbng-vpp-plugin-*
repositories, imported with history. Plugins target VPP v26.06.
