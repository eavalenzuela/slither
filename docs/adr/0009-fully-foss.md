# ADR 0009 — Commercial model: fully FOSS

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Open-source security tools span the spectrum from pure volunteer FOSS to open-core commercial products with paid tiers. The model affects license choice, contributor agreements, and which features are prioritized.

## Decision

Slither is fully FOSS. No paid tier, no hosted SaaS offering, no enterprise-only features. License is MIT (unchanged from repo inception).

## Consequences

- No CLA; DCO is sufficient (ADR-0014).
- All features ship in the core repository; no dual-license or enterprise fork.
- Dependency licenses must remain MIT-compatible. Source-available or BSL-style dependencies are rejected (see ADR-0017 on EventStoreDB rejection).
- Revenue model is not a design consideration; decisions are made on operator-value, not monetization.

## Alternatives considered

- **Open-core.** Would create a tension between community features and paid features; incompatible with the goal of serving small teams without budget.
- **Business-Source License (BSL).** Common in modern infra OSS; incompatible with the FOSS framing.

## References

- PROJECT.md §8, §9.1 row 9.
