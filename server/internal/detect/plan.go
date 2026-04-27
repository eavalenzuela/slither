package detect

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/ruleeval"
)

// plan is the runnable form of a server-only Sigma rule. The boolean
// predicate (Rule.Condition) decides whether an event matches; what
// happens next depends on whether the rule carries an aggregation or
// a temporal join. Both shapes share the same windowing primitive —
// only the firing condition differs.
type plan struct {
	rule     *ruleast.Rule
	class    ocsf.ClassID
	access   ruleeval.Accessor
	window   *ruleWindow
	severity uint32

	// kind selects the firing shape. Server-only Sigma rules carry
	// either an Aggregation or a NodeNear in the boolean tree, never
	// both — the compiler enforces that.
	kind planKind

	// aggregation-only fields
	agg *ruleast.Aggregation

	// near-only fields
	join *ruleast.TemporalJoin
}

type planKind uint8

const (
	planAggregation planKind = iota + 1
	planNear
)

// compilePlans rebuilds every server-only rule as an executable plan.
// Rules that no longer compile, or whose ServerPlan is missing/
// malformed, are skipped with a count for telemetry — the engine never
// rejects the whole ruleset because of one bad row.
func compilePlans(rows []rulePlanRow, defaultMaxKeys int, onEvict func(ruleID string)) (out []*plan, skipped int) {
	for _, row := range rows {
		p, err := compileOne(row, defaultMaxKeys, onEvict)
		if err != nil {
			skipped++
			continue
		}
		if p != nil {
			out = append(out, p)
		}
	}
	return out, skipped
}

// rulePlanRow is the projection from pg.Rule the engine actually
// needs. Defining it here keeps the detect package decoupled from
// store/pg's internal struct shape.
type rulePlanRow struct {
	UID            string
	SourceYAML     string
	Classification string
	ServerPlanJSON []byte
}

func compileOne(row rulePlanRow, defaultMaxKeys int, onEvict func(ruleID string)) (*plan, error) {
	if row.Classification != "server_only" && row.Classification != "both" {
		return nil, nil
	}
	// We need both halves: the *Rule for the boolean predicate +
	// (when present) Rule.Aggregation, and the ServerPlan for the
	// temporal-join spec / cross-host metadata. ParseRule recovers
	// the rule even when Compile classified it server-only and would
	// otherwise discard the EdgeArtefact.
	rule, err := ruleast.ParseRule([]byte(row.SourceYAML))
	if err != nil {
		return nil, fmt.Errorf("recompile: %w", err)
	}
	_, srvPlan, _, err := ruleast.Compile([]byte(row.SourceYAML))
	if err != nil {
		return nil, fmt.Errorf("recompile classify: %w", err)
	}
	// Persisted ServerPlan from rules.server_plan jsonb cross-checks
	// the recompile; when fresh compile didn't emit a plan but the
	// row carries one (e.g. manually-edited row), prefer the row's.
	if srvPlan == nil && len(row.ServerPlanJSON) > 0 {
		var stored ruleast.ServerPlan
		if jerr := json.Unmarshal(row.ServerPlanJSON, &stored); jerr == nil {
			srvPlan = &stored
		}
	}
	if srvPlan == nil {
		return nil, fmt.Errorf("rule %q has no server plan", row.UID)
	}

	cls, ok := ruleeval.CategoryToClass(rule.Category)
	if !ok {
		return nil, fmt.Errorf("rule %q: unsupported category %q", rule.ID, rule.Category)
	}
	access := ruleeval.AccessorFor(rule.Category)
	severity := levelToSeverity(rule.Level)

	timeframe := time.Duration(srvPlan.TimeframeSecs) * time.Second
	if timeframe <= 0 {
		// Server-only without timeframe is a server-side join with no
		// bound — disallow. Compiler should have rejected, but defend.
		return nil, fmt.Errorf("rule %q: server plan missing timeframe", rule.ID)
	}
	maxKeys := defaultMaxKeys
	uid := rule.ID
	w := newRuleWindow(timeframe, maxKeys, func() {
		if onEvict != nil {
			onEvict(uid)
		}
	})

	switch {
	case rule.Aggregation != nil:
		return &plan{
			rule:     rule,
			class:    cls,
			access:   access,
			window:   w,
			severity: severity,
			kind:     planAggregation,
			agg:      rule.Aggregation,
		}, nil
	case srvPlan.TemporalJoin != nil:
		return &plan{
			rule:     rule,
			class:    cls,
			access:   access,
			window:   w,
			severity: severity,
			kind:     planNear,
			join:     srvPlan.TemporalJoin,
		}, nil
	}
	// Server-only rules that aren't aggregations and aren't joins shouldn't
	// reach here today (e.g. cross_host without aggregation: the compiler
	// emits ServerPlan but no specific shape). Skip with a clear error.
	return nil, fmt.Errorf("rule %q: server plan has no executable shape", rule.ID)
}

// levelToSeverity matches the agent's mapping (severity uses OCSF
// severity_id 1..5). Duplicated here to avoid a control→detect import
// cycle once both packages mature.
func levelToSeverity(l ruleast.Level) uint32 {
	switch l {
	case ruleast.LevelCritical:
		return 5
	case ruleast.LevelHigh:
		return 4
	case ruleast.LevelMedium:
		return 3
	case ruleast.LevelLow:
		return 2
	case ruleast.LevelInformational:
		return 1
	}
	return 1
}
