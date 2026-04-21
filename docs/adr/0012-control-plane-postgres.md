# ADR 0012 — Control-plane store: Postgres

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The server needs durable storage for relational data: users, roles, hosts, enrollment tokens, rules, alerts, audit log. This data is low-volume, transactional, and needs migrations.

## Decision

Postgres 16 is the control-plane store. Separate from the event store (ClickHouse, ADR-0017).

## Consequences

- Two datastores to operate. Acceptable — they serve orthogonal workloads.
- Standard migration tooling available (`golang-migrate` or similar).
- No ORM: `database/sql` + `sqlc` for type-safe queries (decision deferred to Phase 2 entry).
- Tests can use the docker-compose Postgres; integration tests spin up a fresh database.

## Alternatives considered

- **SQLite.** Plausible for single-node but loses operational familiarity and complicates concurrent access.
- **Consolidate into ClickHouse.** Wrong shape — ClickHouse is not built for transactional control-plane work.

## References

- PROJECT.md §4.2, §9.1 row 13.
