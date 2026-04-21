# ADR 0021 — Immediate response: opt-in per rule and per host

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The edge rule engine can take response actions (kill process, isolate host, quarantine file) the moment a rule matches, without waiting for a server round-trip. This is the protection-first payoff (ADR-0022) — but it is also the scariest behavior in the product. A false-positive that auto-kills an essential process on a production host is worse than a missed detection.

The decision is how to gate this capability so that operators get the speed when they want it and cannot be surprised by it when they don't.

## Decision

Immediate response is **opt-in at two layers**, both of which must be true for any action to fire:

1. **Per rule.** The rule must declare a response action in its `slither.response` block. Rules without the block are detection-only.
2. **Per host (or host group).** The host must be in a policy that enables immediate response. Default policy is detect-only.

A rule that declares a response action running on a detect-only host records the finding as normal; the action is simply not executed. Operators see a clear "would have killed PID 12345" marker in the alert.

## Consequences

- The dangerous path requires two explicit deliberate choices. Neither a rule author nor a host operator can unilaterally enable auto-kill.
- Progressive rollout is natural: write the rule, ship it detect-only to all hosts, promote specific hosts to response-enabled once the rule has proven clean.
- The "would have" marker gives operators real data to decide whether to promote a host.
- The server still receives the finding either way, so global visibility is unaffected by host-level policy.

## Alternatives considered

- **Per-rule only.** Simpler, but removes operator-side control — a noisy rule would auto-fire everywhere until rule authors caught up.
- **Per-host only.** Makes every rule on a response-enabled host dangerous by default. Too coarse.
- **Always-on with allowlist.** Inverted default; surprising and unsafe.

## References

- PROJECT.md §3.6, §9.1 row 22; ADR-0022.
