# ADR 0004 — Scale target: 50–500 hosts per server

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The storage engine, message bus, and deployment topology all depend on how many endpoints a single server must handle. The target audience (small security teams, homelabs, researchers) does not need hyperscale, and designing for 10k+ would lock in operational complexity that users cannot justify.

## Decision

v1 is designed for **50–500 hosts per server**. Architecture must not preclude later scale-out, but we do not pre-optimize for it.

## Consequences

- Single-node server is the only supported topology in v1.
- ClickHouse handles ingest on one node comfortably at this scale (see ADR-0017).
- No message bus is needed in v1 (ADR-0013) — in-process channels suffice.
- If real operators push the upper bound, we revisit with a Phase 5+ horizontal-scale ADR.

## Alternatives considered

- **10-host homelab floor.** Would permit DuckDB+Parquet; dismissed as too small a target.
- **10k+ hosts.** Would require Kafka/NATS + distributed ClickHouse from day one; too much upfront cost.

## References

- PROJECT.md §2, §9.1 row 4.
