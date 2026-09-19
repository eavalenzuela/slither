# ADR-0043: YARA scanning — out-of-process extension, on-demand only

**Status:** accepted (scope); implementation not started

**Date:** 2026-09-19

## Context

PROJECT.md §3.2 lists "YARA scanning for on-disk and in-memory
artifacts (triggered by rule actions, not continuous)" as a v1
detection capability. It never got a Phase, and the 2026-09-19
completeness review found it was the one §3.2 item with zero code.
ADR-0027 anticipated it in passing ("a future YARA file-scanning
module") as an extension, without deciding anything.

Two constraints decide the shape:

1. **The agent is a static `CGO_ENABLED=0` binary by design** (Makefile
   §Build; Phase 5 #89 reproducible builds; cosign-signed release
   artefacts in ADR-0039). Every usable YARA implementation is a C or
   Rust library behind cgo — libyara via `hillu/go-yara`, YARA-X via
   its C API. Linking either into the agent ends static linking, ends
   the reproducible-build guarantee, complicates cross-compilation
   for arm64, and puts a large, historically CVE-prone parser inside
   the process that holds the BPF file descriptors and the mTLS key.
2. **ADR-0029 exists for exactly this.** Out-of-process, supervised,
   separate user and capability set, cgroup resource limits, signed
   binary verified on every spawn (Phase 6 #107). A YARA scanner is a
   CPU-heavy, crash-prone, third-party-library-shaped workload — the
   profile the extension model was built to hold at arm's length.

The "not continuous" clause in §3.2 matters too: a continuous
on-access scanner is the AV product PROJECT.md §1 says slither is not.
Scanning is a *response action* — something a rule or an operator
asks for about a specific artefact — not a collector.

## Decision

YARA scanning is a **first-party extension**, `slither-ext-yara`,
built under ADR-0027 / ADR-0029, invoked through the response path of
ADR-0034, and never linked into the agent. Scope, in order:

1. **Response action `SCAN_YARA`** (a new `ResponseAction` in
   `control.proto`, additive), targeting a file path or a pid (memory
   regions via `/proc/<pid>/mem` and `maps`, and the executable image).
   Gated exactly like every other action: per-rule `auto_respond` +
   per-host policy bit (`allow_scan`), operator path from the console,
   audit row for every invocation. Default-deny like the rest.
2. **The agent dispatches the action to the extension** over the
   existing `ExtensionService.Execute` RPC; the extension returns
   matches (rule name, tags, meta, matched strings with offsets). The
   agent turns matches into a `DetectionFinding` (2004) carrying the
   YARA rule identity and the target, so alerts, the flow graph and
   the JSON API need no new class.
3. **YARA rule distribution rides the signed rule-bundle path** of
   ADR-0039: a bundle may carry `.yar` files next to Sigma `.yml`; the
   agent hands the YARA set to the extension on start and on bundle
   reload. Unsigned YARA rules are refused for the same reason
   unsigned Sigma bundles are.
4. **Engine choice is the extension's business.** First cut on
   libyara (mature, widest rule compatibility); YARA-X can replace it
   inside the extension without the agent noticing.
5. **Explicitly not in scope:** on-access / continuous scanning,
   scheduled full-disk sweeps, scanning inside container images.
   Continuous scanning would be an ADR-0022 protection-first
   regression (latency for the whole host in exchange for artefact
   coverage) and is the AV line PROJECT.md §1 draws.

## Consequences

- The agent stays static and reproducible; libyara's attack surface
  lives in a separate, capability-restricted, cgroup-limited process
  that the supervisor can kill and restart.
- A YARA match is an alert like any other: no new OCSF class, table,
  or console view.
- Operators without the extension installed see `SCAN_YARA` actions
  fail with "extension not present" in the audit log — the same shape
  as any other unavailable capability.
- The work is a real Phase 7 chunk (proto, dispatcher, extension,
  bundle format, console action button, validation run) and is tracked
  in IMPLEMENTATION.md §9 as not started.

## Alternatives considered

- **Link libyara into the agent (cgo).** Rejected: ends static /
  reproducible builds, puts a large C parser in the privileged
  process. See Context.
- **Pure-Go YARA reimplementation.** None exists at usable coverage;
  writing one is a multi-year project with permanent rule-compat
  drift.
- **Ship scanning as a server-side job over collected artefacts.**
  The `collect_artifacts` action already brings files and `/proc`
  snapshots to the server; scanning them there is a legitimate later
  addition but does not cover in-memory scanning of a live process
  and doubles the artefact traffic. Kept as a follow-on, not the
  primary design.
- **Continuous on-access scanning.** Out of scope; see Decision 5.

## References

- PROJECT.md §1 (not an AV), §3.2 (the original clause), §3.7
- ADR-0022 (protection-first), ADR-0027 / ADR-0029 (extensions),
  ADR-0034 (response model), ADR-0039 (signing)
- IMPLEMENTATION.md §9 (Phase 7 tracking entry)
