# ADR 0020 — Operator overrides: force-server-only, never force-edge

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

ADR-0018 defines a mechanical four-predicate gate for edge-eligibility. Operators occasionally need to override the default placement for a specific rule — e.g., to keep a noisy rule off endpoints during a tuning window, or to pin a privacy-sensitive rule to the server.

Two override directions are possible:

- **Force server-only** on an otherwise edge-eligible rule.
- **Force edge** on a rule that fails the eligibility gate.

The first is safe; the second is not. An edge-ineligible rule is ineligible for a reason: it requires unbounded state, a cross-host join, server-side enrichment, or a feed too large for an endpoint. Letting an operator bypass that check would re-introduce exactly the failure modes the gate exists to prevent.

## Decision

- **Force server-only is allowed.** Any edge-eligible rule can be pinned to the server via a rule-level tag (`slither.placement: server`).
- **Force-edge on an ineligible rule is a compile error.** The Sigma compiler refuses to produce an edge build for the rule and cites the failed predicate.

Overrides live in the rule itself (as a tag), not in a separate configuration file. The compiler is the single source of truth for placement.

## Consequences

- Operators keep a useful escape hatch for noise and privacy concerns without needing a separate mechanism.
- The edge engine's complexity budget (bounded state, bounded feeds, local-only inputs) is protected unconditionally.
- "Why is this rule running on the server?" has exactly two answers: it failed the gate, or it was tagged server-only. Both are visible in the rule file.

## Alternatives considered

- **Allow force-edge with a warning.** Rejected — warnings are ignored and the failure mode is subtle (memory growth, stalled rules) rather than loud.
- **Put overrides in a separate config file.** Rejected — splits placement knowledge across two files and makes rule review harder.

## References

- PROJECT.md §3.6, §9.1 row 21; ADR-0018.
