# ADR 0001 — Platform: Linux-only for v1

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

A full EDR covers Linux, macOS, and Windows endpoints. Each platform has its own kernel-telemetry primitive with different cost profiles: eBPF on Linux, Endpoint Security framework on macOS (requires Apple Developer ID + entitlement), and ETW + minifilter driver on Windows (requires EV code-signing, potentially WHQL).

Slither is pre-alpha with a single developer. Committing to three kernel stacks at once would stall v1 indefinitely.

## Decision

v1 supports Linux only. macOS and Windows are post-v1 (Phase 7), gated on demonstrated demand and the funding needed for Apple Developer enrollment and Windows driver signing.

## Consequences

- Ships faster. One kernel-telemetry path means one set of CO-RE concerns, one loader, one test matrix.
- Narrower initial market — homelab and Linux-heavy SMB stacks only. Matches the target user profile (PROJECT.md §2).
- Cross-platform assumptions must not leak into shared types. Anything that would require abstraction over platforms is deferred until a second platform actually lands.

## Alternatives considered

- **Cross-platform from day one.** Rejected — time and signing cost would prevent any v1 from shipping.
- **Linux + macOS.** Rejected — Apple developer entitlement friction for a FOSS project is non-trivial.

## References

- PROJECT.md §1 non-goals, §9.1 row 1.
