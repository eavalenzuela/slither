# ADR 0007 — Canonical event schema: OCSF

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Every event has to live somewhere in a schema. Options: invent our own, adopt ECS (Elastic), or adopt OCSF (Open Cybersecurity Schema Framework). Downstream consumers (SIEMs, data lakes) increasingly expect OCSF. Maintaining a native schema plus published OCSF mappings means two schemas to keep in sync, which is a well-known drift surface.

## Decision

OCSF 1.3 is the canonical on-the-wire and at-rest schema. Internal Go types in `pkg/ocsf` map directly to OCSF class names and field names. Slither does not maintain a parallel "native" schema.

## Consequences

- Downstream SIEM / data-lake consumers can ingest Slither events with zero translation.
- OCSF classes are sometimes more verbose than a bespoke schema would be — accepted cost.
- OCSF version bumps force deliberate, ADR-backed migration work. We pin `1.3.0` and don't chase minor bumps automatically.
- A drift-check test (`pkg/ocsf/schema_test.go`) verifies our field expectations against upstream JSON schema files to prevent silent divergence.

## Alternatives considered

- **ECS.** Strong Elastic ecosystem fit, weaker outside it.
- **Native schema + OCSF mapping.** Maintenance burden that produces bugs.

## References

- PROJECT.md §5, §9.1 row 7.
