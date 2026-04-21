# ADR 0011 — Transport: gRPC bidirectional streams over mTLS

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Agent↔server communication must carry a continuous event stream upward and push control messages (rule updates, response requests) downward on the same connection. Options: gRPC bidi streaming, HTTPS+SSE+POST, WebSockets, custom framing.

## Decision

gRPC bidirectional streaming over HTTP/2 with mutual TLS. Each host holds a per-host client certificate signed by the Slither CA; connections without a valid cert are refused.

## Consequences

- Schema-driven wire protocol via `proto/slither/v1/`; buf enforces wire compatibility.
- Strong authentication and encryption by default; rotation is a routine cert-management task.
- gRPC adds tooling complexity (protoc, buf) but those are already part of the toolchain.
- Operators needing raw HTTP ingestion for third-party integrations will receive a separate read-only query API on the server, not the ingest surface.

## Alternatives considered

- **HTTPS + SSE + POST.** Simpler but forces duplicating framing + backpressure.
- **WebSockets.** Equally capable but less Go-idiomatic and without schema tooling.

## References

- PROJECT.md §4.2, §9.1 row 12; IMPLEMENTATION.md §2.4.
