# ADR 0029 — Extension execution: out-of-process, supervised

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Given the decision to support extensions (ADR-0027), the remaining question is *how* they run. The major options:

- **In-process via Go's `plugin` package.** Shared memory; any crash takes the agent down. The `plugin` API is notoriously fragile across Go versions and toolchains.
- **In-process via cgo / shared libraries.** Same crash-blast-radius problem plus ABI headaches and a cross-compilation nightmare.
- **Out-of-process subprocess with a small IPC protocol.** Extension is a separate binary; the agent supervises it.
- **WASM sandbox.** Attractive for third-party code; heavy for first-party work and not free of ABI concerns.

Protection-first (ADR-0022) means the agent must stay up. An extension crash must not take the agent with it.

## Decision

Extensions run **out-of-process** as subprocesses supervised by the agent:

- **Binary interface.** Each extension is a separate executable. The agent starts it as a child process, reads its gRPC listener path from stdout, and connects over a local Unix socket.
- **Protocol.** The small `ExtensionService` gRPC interface (`Hello`, `Events`, `Execute`) defined in `proto/slither/v1/extension.proto`.
- **Supervision.** Exponential backoff restart on crash; circuit-breaker after N failures in a window (extension is marked unhealthy and reported to the server).
- **Isolation.** Extensions run under a distinct Linux user and with a tightened set of capabilities where feasible; the agent does not share its kernel-interaction privileges.
- **Resource limits.** CPU/memory limits enforced via cgroups where the init system supports it.

## Consequences

- An extension crash is contained — the agent keeps running, the failure is reported, the supervisor restarts on backoff.
- Extensions can be written in any language that speaks gRPC. First-party ones will be Go for consistency, but the interface does not mandate it.
- There is a subprocess per extension plus an IPC hop; this is cheap in absolute terms and a non-issue at target scale.
- Update cadence is decoupled — extensions ship as separate artifacts.
- The supervisor itself is one more thing to test and harden. Acceptable; supervision is a well-understood pattern.

## Alternatives considered

- **In-process `plugin`.** Crash-in-extension kills the agent. Rejected.
- **cgo shared libs.** Same blast radius, worse ABI story. Rejected.
- **WASM.** Promising for untrusted third-party code, which this ADR explicitly isn't solving for in v1. May revisit when/if a marketplace is considered.

## References

- PROJECT.md §3.7, §9.1 row 30; ADR-0027.
