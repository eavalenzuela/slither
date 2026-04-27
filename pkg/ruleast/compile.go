package ruleast

import "fmt"

// Compile is the §5.1 #54 entry point that returns the three-artefact
// trio defined in ADR-0032: an edge artefact for the agent, a server
// plan for the detection engine, and a classification routing the rule
// between them.
//
// #54a stubbed every rule as EdgeOnly. #54d (this commit) lights up the
// classification gate against ADR-0018 predicate 2 (window ≤ 300s,
// state cap ≤ 1024) for stateful rules carrying `| count() …`. Stateless
// rules continue to round-trip as EdgeOnly v1 — the Phase 1/2 corpus
// stays byte-stable.
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
	return classify(rule, doc.ForceEdge, doc.Lookback)
}

// classify implements ADR-0018 predicate 2 — bounded-stateful caps. The
// other three predicates land with later sub-tasks: predicate 1 (locally
// observable inputs) is enforced by #54e once `near` arrives, predicate
// 3 (IOC ≤ 100k) lights up with #66, predicate 4 (no baselines older
// than agent uptime) needs a baseline subsystem that doesn't exist yet.
//
// Stateless rules: EdgeOnly, ASTVersionV1, no state bounds.
// Stateful + within caps: EdgeOnly, ASTVersionV2, state bounds populated.
// Stateful + over caps + !force_edge: ServerOnly, ServerPlan populated.
// Stateful + over caps + force_edge: ErrCompile citing the predicate.
func classify(rule *Rule, forceEdge, lookback bool) (*EdgeArtefact, *ServerPlan, Classification, error) {
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
