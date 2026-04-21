# ADR 0019 — Edge engine: phased rollout by rule complexity

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The edge rule engine is a non-trivial piece of the agent. Shipping it all at once risks stability; shipping nothing until the full design is ready delays the protection-first benefit.

## Decision

Phase the edge engine capability by rule complexity:

- **Phase 1 (agent MVP):** stateless single-event rules only. No counters, no windows, no IOC feeds.
- **Phase 3 (detection phase):** bounded-stateful rules on edge (counters within per-host bounded windows per ADR-0018); small IOC feed push to agents.
- **Phase 4+:** hybrid rules (same rule both sides); edge baselines via bloom filter or count-min sketch.

## Consequences

- Phase 1 agent is the simplest possible edge engine: a list of compiled predicates, a dispatch loop. Fast to ship, easy to test.
- Operators get immediate protection-first value in Phase 1 for the stateless rule class, which covers many common reverse-shell and suid-abuse patterns.
- Stateful classification in Phase 3 extends coverage to brute-force and rapid-enumeration patterns without changing the compiler/AST architecture.

## Alternatives considered

- **Full engine Phase 1.** Too ambitious for a first ship; bounded-stateful evaluation needs testing infrastructure that doesn't exist yet.

## References

- PROJECT.md §3.6, §9.1 row 20; IMPLEMENTATION.md §3.5.
