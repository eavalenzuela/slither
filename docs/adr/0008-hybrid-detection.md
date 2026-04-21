# ADR 0008 — Detection topology: hybrid (edge + server)

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Detection can run on the server (full cross-host context, simpler agent) or on the agent (lower latency, enables immediate response). The trade-off: server-only detections pay round-trip latency before any response can fire, which is a real problem for protection-first deployments without 24/7 SOC coverage (ADR-0022).

## Decision

Hybrid. The Sigma compiler classifies each rule using the four-predicate gate (ADR-0018). Edge-eligible rules run on the agent; everything else runs server-side. A small number of rules may run on both sides (hybrid), but v1 defers that optimization.

## Consequences

- Agent ships with an edge rule engine (Phase 1 stateless; Phase 3 bounded-stateful).
- Server runs its own detection engine on the ingested stream for correlation and baseline-dependent rules.
- Compilation + classification is the single source of truth; operators do not hand-tag rules as edge or server.
- Both detection paths emit `detection_finding` events with the same OCSF shape.

## Alternatives considered

- **Server-only.** Simpler, but loses the low-latency response path essential to protection-first.
- **Edge-only.** Impossible for cross-host correlations.

## References

- PROJECT.md §3.2, §3.6, §9.1 row 8.
