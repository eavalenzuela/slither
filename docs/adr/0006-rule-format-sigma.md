# ADR 0006 — Rule format: Sigma

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

A detection engine needs a rule language. Options: a Slither-native DSL, a borrowed industry format, or free-form code. Operators already maintain Sigma rule libraries; rebuilding our own DSL would demand they either rewrite rules or maintain two formats.

## Decision

Sigma is the primary rule format. Slither compiles Sigma YAML to an internal AST that supports both server-side and edge-side execution (see ADR-0018).

## Consequences

- Existing Sigma rule libraries are usable with translation/mapping work only, not rewrites.
- Sigma's evolution is external; we pin a specification version and migrate deliberately.
- Not every Sigma feature maps to every evaluation site; we classify rules edge vs. server per the four-predicate gate (ADR-0018).
- Custom Slither-specific detection logic that doesn't fit Sigma is still possible but must be documented as an escape hatch, not a parallel rule format.

## Alternatives considered

- **Native DSL.** Would let us optimize for our AST, but the interoperability cost for users is too high.
- **KQL / EQL.** Compelling but couples us to one vendor's rule ecosystem.

## References

- PROJECT.md §3.2, §9.1 row 6.
