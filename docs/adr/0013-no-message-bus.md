# ADR 0013 — Message bus: none in v1

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Distributed EDR architectures often place NATS / Kafka between ingest and detection. At the v1 scale target (50–500 hosts, single-node server; ADR-0004), this adds an operational burden without a matching correctness or scaling benefit.

## Decision

No external message bus in v1. Ingest and detection communicate through in-process Go channels with bounded buffers and backpressure.

## Consequences

- Simpler operational story — one binary, fewer moving parts.
- Ingest and detection share process lifetime; a detection-engine crash ends ingest.
- If scale-out becomes necessary, NATS is the first candidate to add (JetStream for persistence). That introduction gets its own ADR.

## Alternatives considered

- **NATS from day one.** Overhead without payoff at target scale.
- **Kafka from day one.** Much higher operational burden.

## References

- PROJECT.md §4.2, §9.1 row 14.
