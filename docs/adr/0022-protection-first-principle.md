# ADR 0022 — Operating principle: protection-first

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Most EDR products are built around a SOC workflow: detect, triage, investigate, then respond. That model assumes a staffed team watching a queue and calling in a response when something looks real. The target user for Slither (50–500 hosts, small ops team, no dedicated SOC) does not have that team — by the time a human reads an alert, the attacker may already have lateral-moved.

The project needs an explicit operating principle to disambiguate design tradeoffs where speed-of-blocking and investigative depth pull in opposite directions.

## Decision

**Protection-first** is the project's operating principle:

- Prefer blocking an intrusion early over preserving its artifacts for later forensic analysis.
- Push detection to the edge where it can act in milliseconds (ADR-0008, ADR-0018).
- Make immediate response a supported path, gated by explicit opt-in (ADR-0021), not an afterthought.
- When a design choice trades latency for richness, choose latency.

This is a posture, not a mandate — detect-only is still a first-class mode and is the default for every rule and every host. The principle governs what the product makes *easy* and *fast*, not what it forbids.

## Consequences

- UI, defaults, documentation, and rule packs emphasize the protection path. "Detect, then decide whether to protect" is framed as a promotion workflow, not a separate product mode.
- Edge engine investment is justified by this principle — otherwise a server-only architecture would be simpler.
- Investigative depth (hunt queries, full process trees, long-horizon baselines) remains valuable but is explicitly the *second* capability added, after protection-first is solid.
- The operator's first hour with the product should answer "am I being actively protected?" before it answers "what happened yesterday?"

## Alternatives considered

- **SOC-first (detect-and-triage primary).** Wrong for the target user — assumes staffing that does not exist.
- **No stated principle.** Decisions drift; every tradeoff re-argued from scratch.

## References

- PROJECT.md §1 Vision, §3.6, §9.1 row 23.
