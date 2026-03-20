# osvbng-vpp-plugin-qos AI Workflow

This project uses a structured workflow for spec writing, design review, and code review. All participating agents read this file as their entry point.

**This is a lightweight, public workflow.** Anyone can contribute — human or AI — as long as work follows the process below.

## Requirements

All work starts from a **GitHub issue created by a human**. No spec, no branch, no PR happens without a tracked issue.

### Scope Rules

**One feature per PR. One PR per issue. No exceptions.**

- A PR implements exactly one issue. If an issue requires multiple features, split it into multiple issues first.
- Do not bundle unrelated changes, "while I'm here" improvements, or opportunistic refactors into a feature PR.
- If implementation reveals a needed change outside the issue's scope, file a new issue for it.

## Agent Participation

The workflow supports flexible agent participation:

- **Claude only** — Claude drafts, reviews, and implements. Phases 2 and 3 are skipped.
- **Claude + Gemini** — Gemini reviews the spec (Phase 2). Codex critique (Phase 3) is skipped.
- **Claude + Codex** — Codex critiques the spec (Phase 3). Gemini review (Phase 2) is skipped.
- **All three** — Full pipeline: Claude drafts, Gemini reviews, Codex critiques, Claude finalizes and implements.

Claude handles Phase 1 (draft) and Phase 5 (implementation) since it has direct codebase access. Phases 2, 3, and 6 are opt-in.

## Project Summary

`context/SUMMARY.md` is the project-level state tracker. Every agent session should read it before starting new work.

## Spec Directory Convention

Every issue that goes through the spec workflow gets a directory at:

```
context/specs/<slug>/
```

Where `<slug>` is a short lowercase-hyphenated description. Examples:

- `context/specs/full-qos/`
- `context/specs/cake-scheduler/`
- `context/specs/triple-isolation/`

## Workflow Phases

### Phase 0: Issue (Human)

- **Actor:** Human
- **Output:** GitHub issue using the appropriate template
- **Gate:** No work begins until the issue exists. Add the `approved` label to signal the issue is ready.

### Phase 1: Spec Draft (Claude)

- **Invocation:** Human gives Claude the issue reference:
  > Read context/PROCESS.md and execute Phase 1 for issue #N.
- **Input:** Claude reads the issue + `context/SUMMARY.md` + existing codebase + VPP upstream source
- **Branch:** Create a feature branch from `main` before any file edits.
- **Output:**
  - `context/specs/<slug>/IMPLEMENTATION_SPEC.md`
  - `context/specs/<slug>/README.md` (status tracker)
- Claude MUST generate ready-to-paste prompts for subsequent agents.
- **Why Claude:** Direct codebase access means the spec is grounded in real VPP code — real file paths, existing patterns, concrete data structures.

### Phase 2: Spec Refinement (Gemini) — optional

- **Input:** `IMPLEMENTATION_SPEC.md`
- **Output:** `context/specs/<slug>/spec-reviews/GEMINI.md`
- **Focus:** RFC compliance, protocol correctness, algorithm verification
- **Commit and push** review artifacts before completing the session.
- **Gemini does NOT edit the spec directly.**

### Phase 3: Spec Critique (Codex) — optional

- **Input:** `IMPLEMENTATION_SPEC.md` + VPP upstream source + plugin source in `src/`
- **Output:** `context/specs/<slug>/spec-reviews/CODEX.md`
- **Focus:** Architectural gaps, missing edge cases, failure modes, VPP-specific issues (buffer lifecycle, thread safety, feature arc correctness)
- **Commit and push** review artifacts before completing the session.

### Phase 4: Spec Finalization (Claude)

- **Input:** Review artifacts + human accept/reject decisions
- **Output:** Final `IMPLEMENTATION_SPEC.md` + `DECISIONS.md` + updated `README.md`
- **Skip when:** Phases 2 and 3 were both skipped.

### Phase 5: Implementation (Claude)

- **Output:** Code committed to the repo + PR created
- **Implementation Rules:**
  1. Use the existing branch from Phase 1.
  2. One commit per logical unit.
  3. Commit message provided immediately.

### Phase 6: Post-Implementation Review — optional

- **Claude — Bug Hunter:** Line-level bugs, race conditions, memory safety, buffer leaks. Output: `code-reviews/CLAUDE.md`
- **Codex — Spec Compliance:** Did we build what the spec says? VPP API correctness. Output: `code-reviews/CODEX.md`
- **Gemini — Protocol Conformance:** RFC compliance, algorithm correctness, AQM parameter validation. Output: `code-reviews/GEMINI.md`

## VPP Plugin Context

This repo is a VPP plugin that builds against [fd.io VPP](https://fd.io/vpp). Plugin source code lives in `src/`.

Related projects:
- **[osvbng](https://github.com/veesix-networks/osvbng)** — Go control plane (calls this plugin's binary API)

When writing or reviewing VPP C code, the following areas of the upstream VPP source are relevant:
- `vnet/policer/` — existing policer architecture (pattern reference)
- `vnet/interface_output.c` — interface-output feature arc (where enqueue hooks in)
- `vnet/buffer.h` — buffer metadata (opaque/opaque2 space)
- `vlib/node.h` — node registration and types
- `vppinfra/pool.h` — pool allocator

## Spec Format

### IMPLEMENTATION_SPEC.md

Must contain these sections:

1. **Overview** — what and why, 2-3 sentences max
2. **References** — RFCs, vendor docs, existing specs
3. **Current State** — what exists today
4. **Design** — architecture, data flow, key decisions
5. **Configuration** — config schema with examples
6. **File Plan** — every file to create or modify, with purpose
7. **Implementation Order** — numbered phases, each independently testable
8. **Attribute Mappings** — parameter translations (config → API → VPP)
9. **Testing** — what to test, how to test it
10. **Not In Scope** — what this spec explicitly does not cover

### DECISIONS.md

```markdown
# Decisions: <slug>

## Accepted

### <finding title>
- **Source:** CODEX | GEMINI
- **Severity:** CRITICAL | HIGH | MEDIUM | LOW
- **Resolution:** <what was changed in the spec>

## Rejected

### <finding title>
- **Source:** CODEX | GEMINI
- **Severity:** CRITICAL | HIGH | MEDIUM | LOW
- **Rationale:** <why this was rejected>
```

### README.md — Status Tracker

Required content:
- **What** — one-line description
- **Status** — table showing each phase's status
- **Key Files** — links to the spec, decisions, reviews
- **Prompt to Resume** — ready-to-paste prompt for continuing in a new session

## Severity Scale

| Severity | Definition |
|----------|------------|
| **CRITICAL** | Will cause crashes, data corruption, security vulnerabilities, or protocol violations |
| **HIGH** | Significant bugs that affect correctness but have workarounds |
| **MEDIUM** | Edge cases, performance issues, non-ideal error handling |
| **LOW** | Cosmetic issues, future-proofing concerns |

## Anti-Patterns (All Agents)

1. **Capability summaries** — State what is broken, missing, or wrong. Not what works.
2. **Style reviews** — Do not comment on naming, formatting, or code style.
3. **Speculative issues** — Show the concrete execution path or don't report it.
4. **Generic recommendations** — "Consider adding more tests" is not a finding.
