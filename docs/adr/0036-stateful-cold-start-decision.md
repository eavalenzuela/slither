# ADR-0036: Stateful cold-start hybrid — declined

**Status:** accepted

**Date:** 2026-05-01

## Context

Phase 3 #59 shipped per-rule opt-in warm-start for the bounded-stateful
detection runtime: rules carry an optional `lookback: true` YAML flag
(default `false`); rules that opt in have their per-key sliding windows
pre-populated from ClickHouse on every Refresh, so a rule like
`count(*) > 5 within 60s` can fire immediately after agent or server
restart if the past 60 s already contained the threshold-crossing burst.

The decision deferred at Phase 3 close was whether to replace the
opt-in default with an **always-on hybrid**: every stateful rule does
lookback on Refresh, capped at a global
`max_cold_start_lookback` (default ~1 h) so unbounded windows don't
trigger unbounded CH reads. ADR-0035 §"§59 stateful cold-start hybrid"
parked the call for Phase 5 #101 once production-shape CH telemetry
was available.

This ADR records the resolution.

## Decision

**Decline the always-on hybrid. Keep `lookback` opt-in per rule.**

The current shape stays:

- Default: stateful rules cold-start with empty windows. Only events
  arriving after Refresh count toward threshold crossings.
- Operator escape hatch: a rule sets `lookback: true` in its YAML, the
  compiler emits a `ServerPlan.Lookback` flag, and the detection
  engine consumes it on every Refresh by reading the rule's `timeframe`
  window from CH.
- The per-rule cap is bounded by `Options.MaxLookback` (default 1 h)
  so a misconfigured `timeframe: 30d` doesn't blow up CH read budget.

## Rationale

The hybrid was attractive on operator-UX grounds — "operators don't
have to remember to set `lookback: true`" — but cost-benefit doesn't
favour it:

- **Read amplification scales the wrong way.** Always-on lookback runs
  one CH range scan per stateful rule per Refresh per host. A
  representative production fleet (say 50 stateful rules × 100 hosts
  × Refresh-on-rule-edit) is 5,000 CH reads per rule edit, every edit.
  With opt-in, the same fleet pays for whichever subset of those 50
  rules actually need warm-start — typically a single-digit count.

- **The hybrid's tuning knob is global, the rules' is per-rule.**
  `max_cold_start_lookback` is one number; a fleet with mixed
  workloads (some rules want 1 h lookback, some want 5 m, some none)
  can't express that. Per-rule `lookback` already does. Replacing a
  fine-grained knob with a coarser one is the opposite of a UX win
  for operators who've already learned the tool.

- **Operators in Phase 3/4 didn't hit the missing-default pain point.**
  The Phase 4 #86 cloud run included one explicit auto-respond rule
  (`8b7c4d00-…0086`) that intentionally fired on a fresh exec — it
  didn't need lookback at all. Phase 3 #70's mixed 14-rule pack used
  lookback on zero rules and validation passed. The "people forget
  the flag" failure mode is hypothetical.

- **The decision is structural, not telemetry-driven.** ADR-0035
  proposed a telemetry threshold (lookback queries < 5 % of CH read
  budget, p95 < 500 ms) as the gate. We don't actually need that data
  to make this call: even if lookback queries were free, the global
  knob is still strictly less expressive than the per-rule knob the
  hybrid would replace. Telemetry would only matter if we'd discovered
  that the per-rule shape was hitting some operational ceiling the
  hybrid would relieve — and we haven't.

- **Reopening is cheap.** If a future fleet hits the missing-default
  pain point, flipping the compiler's default from `lookback: false`
  to `lookback: true` is a one-line change. The hybrid's
  `max_cold_start_lookback` cap already exists in
  `Options.MaxLookback`; it's just unused at the engine layer until
  someone wants it.

## Consequences

- **Coverage gap is operator-controlled, not phase-wide.** Stateful
  rules that need to fire on first-event-after-restart get
  `lookback: true`. Rules that don't, stay cold. This is the same
  contract Phase 3 shipped; nothing regresses.

- **Documentation surface unchanged.** No new operator concept; the
  `lookback` flag was already documented in IMPLEMENTATION.md §5.1
  #59 and the rule-authoring guide. No deprecation notice needed.

- **Phase 5 task budget freed.** #101 closes; #102 (threat model
  doc) + #103 (exit-gate cloud run) absorb the freed time.

- **Open question parked for Phase 6+.** If real-fleet telemetry
  emerges showing operators routinely failing to set `lookback`
  where they need it, reopen this ADR. The reopen criterion is
  "operator UX failure pattern documented", not "lookback queries
  cost too much" (which the per-rule shape already controls).

## References

- IMPLEMENTATION.md §5.1 #59 (the per-rule lookback flag)
- ADR-0018 (rule classification — bounded-stateful runtime constraints)
- ADR-0035 §"§59 stateful cold-start hybrid: decision belongs in Phase 5"
- IMPLEMENTATION.md §7.1 #101 (this task)
