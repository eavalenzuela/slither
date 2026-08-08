# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. If you cannot use GitHub, email the maintainer listed in the repository metadata.

## What to include

- A clear description of the issue and its impact.
- Reproduction steps, ideally with a minimal PoC.
- Affected versions / commits, if known.
- Suggested remediation, if you have one.

## What to expect

- **Acknowledgement within 72 hours.** We'll confirm we've seen your report and begin triage.
- **Status updates** at least weekly while the issue is open.
- **Coordinated disclosure.** We'll agree on a disclosure timeline with you before publishing fixes and advisories. The default is 90 days from report to public disclosure; we may shorten or extend by mutual agreement.
- **Credit** in the advisory, unless you prefer to remain anonymous.

## Scope

In scope:

- Slither agent (`slither-agent`) and server (`slither-server`) binaries.
- Agent↔server wire protocol.
- Default deployment configurations in `deploy/`.
- Slither-authored rule evaluation logic (injection, bypass, authorization flaws).

Out of scope:

- Vulnerabilities in third-party dependencies that have not yet been disclosed upstream — report those to the upstream project first.
- Denial-of-service that requires already having root on the monitored host (the agent runs as root by design; see PROJECT.md §6 threat model).
- Issues in development or test scaffolding that do not run in production deployments.

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, service disruption, or data destruction.
- Give us reasonable time to address issues before public disclosure.

## Risk dispositioning

Static-analysis findings (gosec, govulncheck) that we accept without code change are recorded here with explicit rationale. The bar is real justification, not noise suppression: every entry is a deliberate decision the next reviewer can second-guess. New `//nolint:gosec` annotations in agent/server code must reference this section.

| ID | File:line | Class | Disposition |
|---|---|---|---|
| G404-1 | `agent/internal/backpressure/rng.go:12` | Weak PRNG | Sampling-decision RNG; uniform-enough is the only contract. Predictability is not exploitable — adversaries cannot influence backoff outcomes. |
| G404-2 | `agent/internal/extensions/process.go:142` | Weak PRNG | Restart-backoff jitter, same class as G404-1. `crypto/rand` would add a syscall to a connection-recovery hot path for no security gain. |
| G204-1 | `agent/internal/extensions/process.go:179` | Subprocess from variable | `BinaryPath` is operator-supplied via `agent.yaml`. The extension supervisor's job *is* to launch operator-declared paths. Trust controls: cosign-keyless signature verify (line 164) gates execution on every spawn, the path goes straight to `exec.CommandContext` (no shell interpretation), the operator allow list is config-frozen at startup. Removing the dynamic argument removes the feature. |
| G304-1 | `agent/internal/output/grpc/buffer/buffer.go:251` | File inclusion via variable | Spool segment path is constructed by the buffer itself from operator-supplied `Options.Dir` plus an internal counter. Not request-derived. |
| G304-2 | `agent/internal/selfprotect/chain.go:146` | File inclusion via variable | Tamper-evident chain file open, append mode. Path is the configured chain location, not request-derived. |
| G304-3 | `agent/internal/selfprotect/chain.go:448` | File inclusion via variable | Same chain file, read mode (verify path). Same disposition as G304-2. |

When a finding here becomes invalid (call site moves, control changes, threat model shifts), update the table — don't leave stale entries. New entries land alongside the `//nolint:gosec` annotation that references them.

### Dependabot alert count vs. shipped risk

GitHub's Dependabot banner reports a much larger number than
`govulncheck` does, and the gap is structural rather than a disagreement
about severity. Recorded here so it does not have to be re-derived every
time someone pushes.

- **`govulncheck` scans what we ship.** It covers the five workspace
  modules (`agent`, `server`, `pkg`, `proto`, `extensions/osquery`) —
  the 60 modules actually linked into `slither-agent`,
  `slither-server` and `slither-ext-osquery`. As of 2026-08-08 those
  report **zero** advisories, both with reachability analysis and with
  `-scan module` (no reachability), after the bumps in `f090e92`.
- **Dependabot also scans `tools/`.** That module exists only so IDEs
  and `go mod` can resolve the seven import paths in `tools/tools.go`;
  its `go.mod` carries 285 indirect requires — the full transitive
  closure of `buf` and `golangci-lint`. 367 of the 396 modules pinned in
  `tools/go.sum` never appear in any shipped binary.
- **`tools/go.mod` is not even authoritative for the build.** Tool
  versions are pinned in `scripts/install-tools.sh`, which installs via
  `go install <pkg>@<version>`; that path does not consult
  `tools/go.mod`. The graph Dependabot is flagging is therefore inert
  twice over: not shipped, and not what gets built.
- **`govulncheck` structurally cannot scan `tools/`** — `tools.go`
  imports *programs*, not importable packages, so package loading fails
  by design. Its absence from the govulncheck numbers is a tooling
  limitation, not a clean bill of health.

The residual risk that remains is real but different in kind: a
compromised build-time tool is a supply-chain risk to the *build*, not a
runtime vulnerability in a deployed slither. It is dispositioned as
accepted-and-monitored via `.github/dependabot.yml`, which groups
`tools/` updates separately from the shipped modules so the two are
never triaged as one pile.

## Pre-release status

Slither is pre-alpha and has **not** undergone third-party security review. Assume vulnerabilities exist. Do not deploy to production systems yet.
