# ADR 0003 — Server language: Go

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The server handles gRPC ingest, ClickHouse/Postgres access, Sigma compilation, and HTMX console rendering. The main choice is whether to match the agent's language or specialize.

## Decision

Server is Go. Matches the agent, sharing protobuf and OCSF types without a translation boundary.

## Consequences

- Single toolchain; contributors learn one language to contribute anywhere in the codebase.
- Go's HTTP/gRPC/Prometheus ecosystems are mature and battle-tested for a server of this shape.
- `templ` for HTML templates + Tailwind standalone CLI give a fully Node-free frontend build.
- If a component (detection engine, specifically) ever outgrows Go in terms of expressiveness or ecosystem, reassess with an ADR.

## Alternatives considered

- **Python for the detection engine.** Tempting for Sigma/Jupyter integration, but splits the build and runtime.
- **Rust.** Shares agent strengths but would fragment the team/toolchain.

## References

- PROJECT.md §4.2, §9.1 row 3.
