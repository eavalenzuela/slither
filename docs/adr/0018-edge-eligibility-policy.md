# ADR 0018 — Edge-eligibility policy: four-predicate gate

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Hybrid detection (ADR-0008) requires a rule for deciding whether a given Sigma rule runs on the agent, on the server, or both. The rule must be mechanical — the Sigma compiler is the single source of truth — and it must prevent expensive or cross-host rules from ever landing on endpoints.

## Decision

A rule is **edge-eligible** if **all four** predicates hold:

1. **Inputs are locally observable.** No server-side enrichment, no cross-host joins.
2. **If stateful, bounded per host:** window ≤ 300 seconds, state ≤ 1024 entries per (host, rule).
3. **IOC lists ≤ 100k entries** (configurable).
4. **No baselines older than agent uptime.**

Everything else is server-only.

## Consequences

- The compiler classifies every rule automatically; no hand-tagging.
- Thresholds are policy and can be tuned without schema changes.
- Edge rule engine complexity is bounded — it never needs to handle unbounded state or cross-host joins.
- Authors get compile-time errors when a rule violates an edge-eligibility constraint but is forced-edge, with the failed predicate cited.

## Alternatives considered

- **Hand-tag rules.** Error-prone; different operators will classify identical rules differently.
- **Always server-side.** Loses low-latency response for protection-first deployments (ADR-0022).

## References

- PROJECT.md §3.6, §9.1 row 19.
