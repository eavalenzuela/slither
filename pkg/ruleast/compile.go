package ruleast

import "fmt"

// Compile is the §5.1 #54 entry point that returns the three-artefact
// trio defined in ADR-0032: an edge artefact for the agent, a server
// plan for the detection engine, and a classification routing the rule
// between them.
//
// #54a stubbed every rule as EdgeOnly. #54d lit up ADR-0018 predicate 2
// (window ≤ 300s, state cap ≤ 1024) for stateful rules. #54e adds
// predicate 1 (locally observable inputs) — `near` correlations and
// `cross_host: true` aggregations always classify ServerOnly. Stateless
// rules continue to round-trip as EdgeOnly v1.
//
// Rules that fail YAML/Sigma parse return (nil, nil, "", err) wrapping
// ErrCompile, matching the previous CompileSigma contract. Rules that
// trip an ADR-0018 predicate while declaring `force_edge: true` also
// return ErrCompile with the predicate cited in the message — the
// vocabulary mirrors the agent's runtime refusal reasons in ADR-0032.
func Compile(src []byte) (*EdgeArtefact, *ServerPlan, Classification, error) {
	rule, doc, err := compileSigma(src)
	if err != nil {
		return nil, nil, "", err
	}
	return classify(rule, doc.ForceEdge, doc.Lookback, doc.CrossHost)
}

// ParseRule is Compile minus the classification gate: it returns the
// boolean-tree + aggregation Rule the compiler built from src,
// regardless of whether the rule routes to the agent or the server.
// The server detection engine (#58) calls this to recover the *Rule
// for server-only rules (where Compile returns a nil EdgeArtefact and
// the *Rule would otherwise be discarded). All compile-time errors
// still wrap ErrCompile.
func ParseRule(src []byte) (*Rule, error) {
	rule, _, err := compileSigma(src)
	return rule, err
}

// classify implements the subset of ADR-0018 predicates the compiler
// can decide today:
//
//   - Predicate 1 (locally observable inputs): a rule is server-only when
//     its condition contains `near` (cross-stream join) or its top-level
//     YAML declares `cross_host: true`. Predicate 3 (IOC ≤ 100k) lights
//     up with #66; predicate 4 (no baselines older than agent uptime)
//     needs a baseline subsystem that doesn't exist yet.
//   - Predicate 2 (bounded-stateful caps): window ≤ 300s, state cap ≤
//     1024. Stateful rules within the caps run on the edge; over-cap
//     rules go server-only.
//
// force_edge against a violating predicate fails compile with the
// predicate name cited.
func classify(rule *Rule, forceEdge, lookback, crossHost bool) (*EdgeArtefact, *ServerPlan, Classification, error) {
	// Predicate 1: cross-stream / cross-host inputs aren't locally
	// observable, so the rule cannot run on the agent.
	join := temporalJoinFrom(rule)
	if join != nil || crossHost {
		if forceEdge {
			return nil, nil, "", compileErr(rule.ID, "ruleast",
				fmt.Errorf("force_edge violates ADR-0018 predicate \"inputs_not_locally_observable\": %s", predicate1Reason(join != nil, crossHost)))
		}
		plan := &ServerPlan{
			RuleID:    rule.ID,
			Lookback:  lookback,
			CrossHost: crossHost,
		}
		if rule.Aggregation != nil {
			plan.Aggregation = rule.Aggregation
			plan.TimeframeSecs = rule.Aggregation.TimeframeSecs
		}
		if join != nil {
			plan.TemporalJoin = join
			plan.TimeframeSecs = join.WithinSecs
		}
		return nil, plan, ClassificationServerOnly, nil
	}

	if rule.Aggregation == nil {
		// force_edge on a stateless rule is harmless — the rule is
		// already edge-only — so accept it without comment. Authors can
		// flip the flag prophylactically without churning a rule whose
		// current shape doesn't need it.
		if lookback {
			// Caught earlier in compileSigma, but defend against future
			// callers that build Rule structs by hand.
			return nil, nil, "", compileErr(rule.ID, "ruleast",
				fmt.Errorf("lookback only applies to stateful rules"))
		}
		return &EdgeArtefact{
			Rule:       rule,
			ASTVersion: ASTVersionV1,
		}, nil, ClassificationEdgeOnly, nil
	}

	const maxWindowSecs uint32 = 300
	const maxStateCap uint32 = 1024

	window := rule.Aggregation.TimeframeSecs
	stateCap := maxStateCap // default to ADR-0018 ceiling; YAML has no tighter knob

	switch {
	case window > maxWindowSecs:
		if forceEdge {
			return nil, nil, "", compileErr(rule.ID, "ruleast",
				fmt.Errorf("force_edge violates ADR-0018 predicate \"state_window_too_large\": timeframe %ds exceeds %ds", window, maxWindowSecs))
		}
		return nil, &ServerPlan{
			RuleID:        rule.ID,
			Aggregation:   rule.Aggregation,
			TimeframeSecs: window,
			Lookback:      lookback,
		}, ClassificationServerOnly, nil
	case stateCap > maxStateCap:
		// Defensive — stateCap is set to maxStateCap above. Kept so
		// future tighter knobs (e.g. per-rule cap_override YAML) trip
		// the same vocabulary the agent will use at runtime refusal.
		if forceEdge {
			return nil, nil, "", compileErr(rule.ID, "ruleast",
				fmt.Errorf("force_edge violates ADR-0018 predicate \"state_cap_too_large\": cap %d exceeds %d", stateCap, maxStateCap))
		}
		return nil, &ServerPlan{
			RuleID:        rule.ID,
			Aggregation:   rule.Aggregation,
			TimeframeSecs: window,
			Lookback:      lookback,
		}, ClassificationServerOnly, nil
	}

	return &EdgeArtefact{
		Rule:            rule,
		ASTVersion:      ASTVersionV2,
		StateWindowSecs: window,
		StateCap:        stateCap,
		Lookback:        lookback,
	}, nil, ClassificationEdgeOnly, nil
}

// temporalJoinFrom returns the wire-form join spec when the rule's
// condition is a binary `near` expression. Returns nil for any other
// shape — including nested compositions which are rejected at parse
// time, so this branch only triggers for the parser's NodeNear output.
func temporalJoinFrom(rule *Rule) *TemporalJoin {
	near, ok := rule.Condition.(*NodeNear)
	if !ok {
		return nil
	}
	return &TemporalJoin{
		Left:       near.L.Name,
		Right:      near.R.Name,
		WithinSecs: near.WithinSecs,
	}
}

func predicate1Reason(hasNear, crossHost bool) string {
	switch {
	case hasNear && crossHost:
		return "rule contains both `near` and `cross_host: true`; both forms require server-side correlation"
	case hasNear:
		return "`near` correlates two event streams which the agent cannot observe in isolation"
	case crossHost:
		return "`cross_host: true` requires visibility across hosts which the agent cannot supply"
	}
	return ""
}
