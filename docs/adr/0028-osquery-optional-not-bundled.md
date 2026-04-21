# ADR 0028 — osquery: optional, bridge extension, operator-installed

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

osquery (Apache 2.0) is a mature host-inventory and state-introspection tool. It complements eBPF telemetry by answering "what is the state of this host right now?" — installed packages, users, scheduled tasks, listening sockets — questions eBPF is not designed to answer.

Integration is desirable. Bundling is not:

- osquery is a large binary with its own release cadence, signing, and kernel-extension concerns on some platforms.
- Redistributing a Facebook-originated binary invites licensing and supply-chain questions better left to osquery's own distribution.
- Operators already running osquery for other reasons should not get a second copy via Slither.

## Decision

osquery integration is delivered as an **optional first-party extension** within the extension framework (ADR-0027, ADR-0029):

- **Not bundled.** The Slither agent does not ship osquery binaries. The operator installs osquery via their normal channel (distro package, osquery's own deb/rpm, their config-management tool).
- **Bridge extension.** A small Slither-maintained extension binary connects to a local osquery socket, runs queries on a schedule (or on-demand from the server), and forwards results to the agent as OCSF events.
- **Opt-in per host.** The extension is enabled in the agent's config; there is no implicit dependency.
- **Phase 6 deliverable.** Not in the v1 agent MVP.

## Consequences

- Operators who don't want osquery pay zero cost (no binary, no process, no config).
- Operators already running osquery for other reasons get an integration path without duplicate processes.
- The project takes no responsibility for osquery's release or signing — that's upstream's problem.
- The bridge is small, well-scoped, and testable against a locally-installed osquery.
- When a new osquery version breaks something, the bridge extension can be updated independently of the core agent.

## Alternatives considered

- **Bundle osquery.** Rejected — redistribution, update cadence, and binary size all push the wrong direction.
- **No osquery integration at all.** Loses a genuinely useful capability for hosts where it's already installed.
- **Replicate osquery's tables in eBPF.** Massive scope creep; osquery exists for a reason.

## References

- PROJECT.md §3.7, §9.1 row 29; ADR-0027.
