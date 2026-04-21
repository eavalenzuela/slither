# ADR 0017 — Event store: ClickHouse

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The event store must absorb a telemetry firehose at 50–500 hosts and support ad-hoc analytical queries over billions of rows. Options considered:

- **ClickHouse** — Apache 2.0, columnar OLAP, purpose-built for this workload.
- **EventStoreDB** — licence changed to ESL v2 in 2024 (source-available, not OSS). Disqualified on licensing alone, and it's an event-sourcing DB (wrong workload shape).
- **OpenSearch** — familiar to SOC analysts, much heavier RAM/ops burden, debatable at single-node target scale.
- **DuckDB + Parquet** — MIT, simplest to operate, but single-writer limits and awkward live-tail UX.

## Decision

ClickHouse (Apache 2.0, version 24.x on Alpine images). Single-node deployment in v1.

## Consequences

- Handles target ingest rate comfortably.
- Real-time queryable — rows are searchable immediately on insert, so live tail is natural.
- Requires operating ClickHouse (backups, upgrades). Acceptable — the operational burden is well-understood.
- Schema versioning is our responsibility; migrations harness arrives in Phase 5.

## Alternatives considered

See context.

## References

- PROJECT.md §4.2, §9.1 row 18.
