# osvbng-vpp - working notes for Claude

All osvbng VPP plugins and the containerized VPP build, one repo, one
versioned artifact set. Consumed by the main osvbng repo as a
submodule. Architecture decisions live in the osvbng-context submodule
sibling; read its CLAUDE.md before your first change anywhere in the
osvbng tree, and cite ADRs by number when a decision governs the code
you touch.

## Repo rules

- License is GPL-3.0-or-later. Every new file gets the three-line
  osvbng header (copy from any file here). Never any other header.
- Plugin names, .api files, message prefixes, C symbols and vppctl
  commands all carry the `osvbng_` prefix, and a plugin's directory
  name equals its add_vpp_plugin target name (the dev loop fails the
  build when they differ).
- Conventional Commits, title only, imperative, no attribution
  trailers of any kind.
- Comments are for what code cannot say: the invariant, the why, the
  constraint, the ADR or RFC section that governs. Plain engineering
  language. Never narrate what a line does, never pad ("simply",
  "note that", "in order to", "robust", "elegant"), no em dashes, no
  emoji. Test before keeping a comment: delete it, and if the reader
  lost no fact, leave it deleted.
- Protocol behavior is written with the spec text open, never from
  memory, and each behavioral branch cites its section. The RFC corpus
  lives in osvbng-context.

## Build

- `make vpp-build`: release path. Clean pinned tree (VPP v26.06),
  patch queue from patches/ (see patches/README.md), every plugin
  glued in by symlink, debs into dist/. The only artifact producer.
- `make vpp-dev`: iteration loop, seconds per edit. Same container and
  volumes, no clean, no artifacts. `VPP_DEV_BUILD=debug` for VPP
  ASSERTs, `VPP_DEV_TARGET=<target>` for one plugin.
- `make vpp-perf`: Clocks/Packet rig. Same box relative numbers only;
  plugin PRs paste before/after (see perf/README.md for what a
  containerized number can and cannot claim).
- Rig scripts own their containers: named, cleaned on any exit. Never
  `exec docker run` from a script and never leave a privileged VPP
  container to a killed client.
- The loop is edit on the host, build in the container: change a
  plugin, `make vpp-dev`, load the .so in a VPP smoke to check. The
  build never uses a host toolchain. `.devcontainer/` opens the same
  builder image for humans who want clangd navigation against the VPP
  tree; there `make vpp-dev` builds in place (OSVBNG_IN_BUILDER) rather
  than spawning a nested container. A plugin .so change needs a VPP
  restart; nothing hot-reloads.

## The two execution contexts

Every design and review decision starts with: which context does this
code run in?

### Context A - VPP main thread (control plane)

One core, cooperatively scheduled: every binapi handler, CLI command,
process node tick, FIB update and plugin init serialises here.

- No blocking I/O; binapi handlers return in microseconds.
- No polling loops: vlib_process_wait_for_event_or_clock, 1s+.
- No vlib_worker_thread_barrier_sync on any churning path: one-shot
  config changes only. Anything workers read per packet that this
  thread mutates (including udp_register_dst_port, which can realloc
  the port table) changes under the barrier, including on CLI paths.
- No unbounded walks in a handler; bucket or hand to workers.

### Context B - VPP workers (data plane)

Design for N workers, never a specific number.

- Per-worker state for anything mutated per packet
  (per_thread_data[vm->thread_index]); a writable cache line shared
  between workers is the single biggest measured throughput killer.
- Shared lookups via bihash; pack (thread_index << 32 | index) into
  values so a hit names the owning worker.
- Worker handoff when RSS lands a packet off its owning worker.
- Per-thread counters only; aggregate off the data path.
- NEVER pool_get/pool_put on a shared pool from a worker; periodic
  reaps use the centralised-process plus per-worker interrupt-walk
  pattern.
- NEVER ASSERT(thread_index == 0) to force single-worker.

### Intersections

- VLIB_INIT_FUNCTION runs before workers exist; size per-thread state
  and resolve worker counts in VLIB_MAIN_LOOP_ENTER_FUNCTION.
- Cross-plugin calls go through graph next-arcs resolved by node name,
  never direct symbols between .so files.

## Performance review bar (every plugin PR answers these)

1. Any writable cache line reachable by two workers?
2. Hot branches annotated with PREDICT_TRUE/FALSE, trace and error
   paths out of line?
3. Prefetch aimed at lookup data; dual-loop shape where bursts exist?
4. One parse pass; hot struct fields in the first cache line?
5. Counters per-worker, aggregation off-path?
6. Classification O(shapes), not O(rules)?
7. Clocks/Packet before and after (make vpp-perf, release build),
   pasted in the PR. Judge regressions on the saturated profile;
   vector-1 numbers misprice batching by an order of magnitude.

## Punt dispatch buffer positions (hard-won; misuse corrupts silently)

- ethernet-input dispatch (ethertype registration): buffer past
  Ethernet and VLANs; rewind to l2_hdr_offset, never a plain reset
  (tunnel paths put the inner frame deep in the buffer).
- udp_register_dst_port dispatch: buffer at the UDP payload; rewind
  Ethernet + VLANs + IP + UDP.
- icmp6_register_type dispatch: buffer at the IPv6 header, not ICMPv6.
- Plugin .so changes need a VPP restart; nothing hot-reloads.

## Plugins serve any control plane, not just osvbng

A plugin is a general VPP dataplane building block. Its .api, its node
graph and any shared-memory protocol are the entire contract; nothing
inside a plugin may assume osvbng specifically sits above it. Policy
(which subscriber, which pool, which service) belongs to the control
plane; the plugin exposes mechanism. This is not politeness, it is
what keeps the plugins reusable and forces the clean seam that makes
them correct.

## Per-plugin requirements

- An affinity statement in the main header: RSS-pinned, handoff, or
  main-thread, and why.
- A capability/version query message in every .api so ANY control
  plane discovers what it is talking to instead of assuming.
- No hardcoded paths; every runtime parameter via .api or
  startup.conf, defaults stated in one place.
- Node-internal shared-memory protocols carry a magic and a version;
  a consumer refuses a version it was not built for.

## Patches: upstream first

A patch about VPP itself, not about osvbng, goes to fd.io before it
enters patches/, and stays in the queue only until it merges upstream.
The patch header records the gerrit link and Upstream-Status;
local-only needs a stated reason. VPP is a commons we build on and
give back to, and a short queue is what survives a version bump. See
patches/README.md and context ADR 0002.

## Anti-patterns (each cost real debugging time once)

- Single shared session pool written from any worker.
- A shared SPSC ring published by multiple workers (a correctness
  race, not just a slowdown): one ring per worker.
- Datapath gating that checks nothing (a global UDP port registration
  is not per-interface enablement; the node checks).
- Egress/input nodes without TRACE_SUPPORTED, or vlib_add_trace from
  an input node without vlib_trace_buffer: trace silently records
  nothing exactly where an operator needs it.
- Interrupt coalescing that clears the pending flag after a capped
  batch without re-arming: frames strand until unrelated traffic.
- Punt enablement without receivability: enabling a punt implies the
  frames can reach it (broadcast receive routes and friends), or they
  die in ip4-lookup before the punt node ever sees them.
- Spinlocks or barrier_sync on hot paths; fmt-style formatting in
  binapi handlers; DPOs holding pointers into vecs (store indices).
