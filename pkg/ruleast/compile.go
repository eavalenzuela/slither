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
func Compile(src []byte, opts ...CompileOption) (*EdgeArtefact, *ServerPlan, Classification, error) {
	rule, doc, err := compileSigma(src)
	if err != nil {
		return nil, nil, "", err
	}
	cfg := applyOptions(opts)
	iocVerdict, err := classifyIOC(rule, doc.ForceEdge, cfg.IOCRegistry)
	if err != nil {
		return nil, nil, "", err
	}
	// compileSigma already validated the response block; rebuild the
	// canonical form here so we can stamp it on the artefact/plan
	// without a second compileSigma round-trip.
	var intent *ResponseIntent
	if doc.Slither != nil && doc.Slither.Response != nil {
		intent, err = compileResponseIntent(rule, doc.Slither.Response)
		if err != nil {
			return nil, nil, "", compileErr(rule.ID, "ruleast", err)
		}
	}
	art, plan, class, err := classify(rule, doc.ForceEdge, doc.Lookback, doc.CrossHost, iocVerdict)
	if err != nil {
		return nil, nil, "", err
	}
	if intent != nil {
		if art != nil {
			art.Response = intent
		}
		if plan != nil {
			plan.Response = intent
		}
	}
	return art, plan, class, nil
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

// iocVerdict is the per-rule output of the IOC classification gate.
// Empty FeedIDs means the rule has no IOC predicates and the gate is a
// no-op. ServerOnly is set when any referenced feed exceeds
// MaxIOCFeedEntries (ADR-0018 predicate 3) — `force_edge: true`
// against an oversize feed fails compile rather than silently downgrading.
type iocVerdict struct {
	FeedIDs    []string
	ServerOnly bool
	Reason     string // populated when ServerOnly is true
}

// classifyIOC walks the rule's predicates, validates every IOC feed
// reference against the registry, and decides whether feed sizes
// force ServerOnly classification. Returns ErrCompile when a referenced
// feed is unknown or when force_edge contradicts predicate 3.
func classifyIOC(rule *Rule, forceEdge bool, reg IOCRegistry) (iocVerdict, error) {
	feeds := collectIOCFeeds(rule)
	if len(feeds) == 0 {
		return iocVerdict{}, nil
	}
	if reg == nil {
		return iocVerdict{}, compileErr(rule.ID, "ruleast",
			fmt.Errorf("rule references ioc feeds %v but compiler was given no registry", feeds))
	}
	verdict := iocVerdict{FeedIDs: feeds}
	for _, feedID := range feeds {
		count, _, ok := reg.Lookup(feedID)
		if !ok {
			return iocVerdict{}, compileErr(rule.ID, "ruleast",
				fmt.Errorf("ioc feed %q not found in registry", feedID))
		}
		if count > MaxIOCFeedEntries {
			if forceEdge {
				return iocVerdict{}, compileErr(rule.ID, "ruleast",
					fmt.Errorf("force_edge violates ADR-0018 predicate \"ioc_feed_too_large\": feed %q has %d entries (cap %d)",
						feedID, count, MaxIOCFeedEntries))
			}
			verdict.ServerOnly = true
			verdict.Reason = fmt.Sprintf("ioc feed %q has %d entries (cap %d)",
				feedID, count, MaxIOCFeedEntries)
		}
	}
	return verdict, nil
}

// collectIOCFeeds walks every selection branch and returns the
// deduplicated set of feed_ids referenced by OpIOC predicates.
func collectIOCFeeds(rule *Rule) []string {
	if rule == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, sel := range rule.Selections {
		for _, branch := range sel.Branches {
			for i := range branch {
				if branch[i].Op != OpIOC {
					continue
				}
				for _, f := range branch[i].FeedIDs {
					if _, ok := seen[f]; !ok {
						seen[f] = struct{}{}
					}
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	// Stable order so golden tests + ServerPlan output are deterministic.
	sortStrings(out)
	return out
}

func sortStrings(in []string) {
	// Tiny insertion sort to avoid an unconditional `sort` import in
	// the hot compile path; len(in) is bounded by the rule's IOC
	// reference count which is single-digit in practice.
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j-1] > in[j]; j-- {
			in[j-1], in[j] = in[j], in[j-1]
		}
	}
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
func classify(rule *Rule, forceEdge, lookback, crossHost bool, ioc iocVerdict) (*EdgeArtefact, *ServerPlan, Classification, error) {
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
			IOCFeeds:  ioc.FeedIDs,
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

	// Predicate 3: oversize IOC feeds force ServerOnly even on
	// otherwise-edge-eligible rules. force_edge against an oversize
	// feed already failed in classifyIOC; reaching here means feeds
	// are within cap or no feeds at all.
	if ioc.ServerOnly {
		return nil, &ServerPlan{
			RuleID:        rule.ID,
			Aggregation:   rule.Aggregation,
			TimeframeSecs: aggTimeframe(rule),
			Lookback:      lookback,
			IOCFeeds:      ioc.FeedIDs,
		}, ClassificationServerOnly, nil
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
			IOCFeeds:   ioc.FeedIDs,
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
			IOCFeeds:      ioc.FeedIDs,
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
			IOCFeeds:      ioc.FeedIDs,
		}, ClassificationServerOnly, nil
	}

	return &EdgeArtefact{
		Rule:            rule,
		ASTVersion:      ASTVersionV2,
		StateWindowSecs: window,
		StateCap:        stateCap,
		Lookback:        lookback,
		IOCFeeds:        ioc.FeedIDs,
	}, nil, ClassificationEdgeOnly, nil
}

// aggTimeframe returns the rule's aggregation timeframe in seconds, or
// 0 when the rule is stateless. Pulled out of inline conditionals so
// the IOC-only ServerOnly path can populate ServerPlan.TimeframeSecs
// without re-checking nil aggregation.
func aggTimeframe(rule *Rule) uint32 {
	if rule == nil || rule.Aggregation == nil {
		return 0
	}
	return rule.Aggregation.TimeframeSecs
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
