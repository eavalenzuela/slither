# ADR-0041: macOS agent scope + sequencing

**Status:** accepted

**Date:** 2026-05-26

## Context

Phases 0–6 closed (Phase 6 closed 2026-05-05, #121). Phase 7 is the
demand-driven "platform expansion" bullet list in IMPLEMENTATION.md §9.
The macOS agent is the first Phase 7 platform to be planned in earnest.

PROJECT.md §1 and ADR-0001 fixed Linux-only for v1; PROJECT.md §7 lists
"macOS agent (if funding for Apple dev program materializes)" as Phase 7.
The deliberate `//go:build linux` / `_other.go`-stub pattern across
`respond`, `selfprotect`, and `keystore` was preserved through Phases 3–5
precisely so a second platform could slot in without re-architecting.

A code-level survey (2026-05-26) confirms the seam is clean:

- The `Collector` interface (`agent/internal/collector/collector.go`) and
  the raw event structs (`agent/internal/pipeline/types.go` —
  `RawProcessEvent` / `RawFileEvent` / `RawNetEvent`) are OS-agnostic. A
  macOS backend emits the **same** structs and reuses the entire
  enricher → ruleengine → OCSF → gRPC path unchanged.
- A `darwin/arm64` build already compiles for `respond`, `selfprotect`,
  and `keystore` (their `_other.go` no-op stubs). The **only** hard
  compile blocker is that every file in `agent/internal/collector` is
  `//go:build linux`, and `app` imports that package.
- The one real enricher coupling is the process-cache cache-miss reader,
  which reads `/proc/<pid>/{stat,exe,cmdline,cwd}`. macOS needs a
  `libproc`-backed replacement behind that seam.

Three constraints make macOS materially different from "another Linux
arch":

1. **Telemetry source.** eBPF has no macOS analog. Endpoint Security (ES)
   is the only credible kernel-quality EDR source. OpenBSM / `auditpipe`
   is deprecated and not a serious option. ES gives exec/fork/exit, file,
   and auth events natively — but has **no socket events** (network is a
   gap, see below).
2. **CGO.** The agent builds `CGO_ENABLED=0` (static ELF). ES is a C
   framework, so the darwin build needs `CGO_ENABLED=1` + the macOS SDK.
   That means **no cross-compile from Linux — macOS CI runners are
   required.** The Linux build is untouched.
3. **Apple gating.** An ES client requires an Apple-granted restricted
   entitlement (`com.apple.developer.endpoint-security.client`), runs as
   a System Extension, and must be notarized for distribution outside a
   developer machine. This is the "funding for Apple dev program" gate
   PROJECT.md §7 named.

This ADR locks the macOS agent's milestone shape and the sequencing of
the Apple dependency so the §9 task breakdown can proceed.

## Decision

### M1 is telemetry-only; response + hardening are deferred

The first macOS milestone (M1) ships a **detection-only** agent: native
collectors feeding the existing enricher, rule engine, OCSF emission, and
gRPC sink. This mirrors the project's own "collector is the lynchpin"
build order and gets real macOS detections shipping fastest.

| Milestone | Scope |
|-----------|-------|
| **M1 — telemetry** | ES-backed process + file collectors; `libproc` enricher seam; darwin build + macOS CI; detection-only. Net collector gated (see below). |
| **M2 — response** | `kill_darwin.go` (libproc ancestry walk), `isolate_darwin.go` (pf via the existing `applier` seam), `collect_darwin.go` (libproc / `lsof` / `log show`), Keychain keystore. Quarantine + `log.chain` are already POSIX-portable — they need only state-dir path selection. |
| **M3 — hardening + distribution** | `PT_DENY_ATTACH` selfprotect, System Extension bundle, notarization, signed `.pkg`, auto-update. |

The Phase 4 six-action response freeze (ADR-0034) holds. macOS adds no new
action classes — it implements the existing six on a new platform.

### De-risk the pipeline before the Apple entitlement

The ES collector spine (Go↔ES cgo bridge, process + file collectors,
enricher seam) is built and proven against a **local dev-signed build** —
ES works with a personal Developer ID cert on a SIP-disabled test Mac —
**before** the restricted entitlement is granted. The Apple entitlement
and notarization become a ship-time packaging concern (M3), not a blocker
to start engineering.

This sequencing means all of M1's engineering proceeds in parallel with,
or ahead of, the Apple Developer Program enrollment and entitlement
request. It gates only **public distribution**, not development or
internal validation.

### Packaging target: System Extension in a notarized .app

The ES client ships as a **System Extension embedded in a host `.app`,
distributed as a notarized `.pkg`**. This is the Apple-blessed modern path:
it survives future macOS hardening and is required for distribution
outside a developer machine. The standalone-entitled-root-daemon
alternative is rejected — ES-as-plain-executable is increasingly fragile
across macOS releases and harder to distribute. Packaging machinery lands
in M3; M1/M2 run the collector as a dev-signed sysext on the test Mac.

### Network telemetry is a gap; M1 may ship without it

ES has no socket events. The two paths are:

| Option | Trade |
|--------|-------|
| (a) Ship M1 with `net.enabled=false` on darwin | Zero new entitlement surface; mirrors the arm64 `net.enabled=false` precedent (§9 #2). Loses network detections on macOS in M1. |
| (b) NetworkExtension (`NEFilterDataProvider`) | Real network telemetry, but a second restricted entitlement, its own content-filter approval, and material added complexity. |

The decision is deferred to a scoped spike (#M-C1) that measures the
NetworkExtension cost against shipping M1 net-disabled. Default lean is
(a) for M1, (b) as an M2+ exercise — recorded here as the open sub-item.

### Default-detect-only carries forward

Per ADR-0034: macOS hosts enroll at all-false response policy, exactly
like Linux hosts. M1 is detection-only anyway; M2 response inherits the
same posture.

## Consequences

- **Same wire, same schema, new source.** macOS events ride the existing
  OCSF classes over the frozen `slither.v1` gRPC contract. No server,
  ClickHouse, or console changes are required for M1 — a macOS agent
  enrolls to today's Linux server and its events render in today's
  console. This is the extension-model precedent ADR-0037 anticipated.
- **The build matrix grows a CGO leg.** `darwin/{amd64,arm64}` builds
  need `CGO_ENABLED=1` + macOS CI runners; they cannot be produced from
  the Linux release host. The Linux `CGO_ENABLED=0` static build is
  unchanged. Release tooling gains a darwin path but does not lose the
  reproducible-ELF property on Linux.
- **Apple is a hard external dependency for distribution only.** Enrollment,
  entitlement approval, and notarization gate M3 public distribution.
  M1/M2 engineering and internal validation do not wait on Apple.
- **Network detection is weaker on macOS in M1.** Until the
  NetworkExtension decision lands, macOS hosts detect on process + file
  telemetry only. Sigma rules that key on network events will not fire on
  macOS — the same partial-coverage posture as arm64 today.
- **Phase 7 stays demand-driven.** This ADR scopes the work; it does not
  commit to a delivery date. M1 starts when macOS demand (or Apple-program
  funding) materializes per PROJECT.md §7.

## Alternatives considered

- **OpenBSM / `auditpipe` instead of ES** — rejected; deprecated by Apple,
  coarse, no future.
- **Telemetry + response parity in one milestone** — rejected; longer to
  first ship, higher risk, and the collector is the genuine unknown worth
  isolating first.
- **Gate all engineering on the Apple entitlement grant** — rejected;
  stalls weeks of provable work on an external approval. De-risk path lets
  the architecture be proven on a dev cert first.
- **Standalone entitled root daemon** — rejected as the distribution form;
  retained only as the dev-time run mode on the test Mac.

## References

- ADR-0001 (platform Linux-only for v1)
- ADR-0010 (Linux telemetry primitive: eBPF — the macOS analog gap)
- ADR-0034 (response model + six-action freeze + default-detect-only)
- ADR-0037 (Phase 6 scope — "different platform, same wire" precedent)
- PROJECT.md §7 (Phase 7 platform expansion — macOS bullet)
- IMPLEMENTATION.md §9 (Phase 7 demand-driven list — macOS breakdown)
