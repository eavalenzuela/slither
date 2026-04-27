package ruleengine

import (
	"fmt"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/ruleeval"
)

// stateCapDefault mirrors ADR-0018's per-rule key-cardinality cap. The
// compiler emits this value on EdgeArtefact.StateCap for every stateful
// rule today; #57's runtime refusal will reject anything larger if a
// misconfigured server pushes it. Hard-coding it here keeps the engine
// usable for tests that build *ruleast.Rule directly without going
// through ruleast.Compile.
const stateCapDefault uint32 = 1024

// CompileRules wraps a set of already-parsed ruleast rules in CompiledRule
// adapters indexed by OCSF class. A rule whose category has no OCSF mapping
// fails compilation loudly — we don't want silent rule-drop at startup.
//
// Stateful rules (Rule.Aggregation != nil) get a per-rule bounded-state
// allocator wired in alongside the boolean tree. Match runs the predicate
// first; on a positive match the state ticks under the by-tuple's key
// and the aggregation's comparison decides whether the engine emits a
// finding. Stateless rules take the original fast path unchanged.
//
// telem may be nil — in that case state evictions go uncounted but the
// hot path still works (used by tests that don't exercise telemetry).
func CompileRules(rules []*ruleast.Rule, telem *telemetry.Counters) ([]CompiledRule, error) {
	out := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		cls, ok := ruleeval.CategoryToClass(r.Category)
		if !ok {
			return nil, fmt.Errorf("ruleengine: rule %q: unsupported category %q", r.ID, r.Category)
		}
		acc := ruleeval.AccessorFor(r.Category)
		if acc == nil {
			return nil, fmt.Errorf("ruleengine: rule %q: no field taxonomy for %q", r.ID, r.Category)
		}
		scr := &sigmaCompiledRule{r: r, class: cls, access: acc, now: time.Now}
		if r.Aggregation != nil {
			if r.Aggregation.TimeframeSecs == 0 {
				return nil, fmt.Errorf("ruleengine: rule %q: stateful rule missing timeframe", r.ID)
			}
			scr.state = newRuleState(r.Aggregation, r.Aggregation.TimeframeSecs, stateCapDefault, telem)
		}
		out = append(out, scr)
	}
	return out, nil
}

// sigmaCompiledRule is the engine-side view of a ruleast.Rule.
type sigmaCompiledRule struct {
	r      *ruleast.Rule
	class  ocsf.ClassID
	access ruleeval.Accessor
	state  *ruleState // nil for stateless rules
	now    func() time.Time
}

func (s *sigmaCompiledRule) ID() string                { return s.r.ID }
func (s *sigmaCompiledRule) AppliesTo() []ocsf.ClassID { return []ocsf.ClassID{s.class} }
func (s *sigmaCompiledRule) Cost() int                 { return s.r.Cost() }

func (s *sigmaCompiledRule) Match(e ocsf.Event) bool {
	if e.ClassID() != s.class {
		return false
	}
	env := ruleeval.EnvFor(e, s.access)
	if !s.r.Match(env) {
		return false
	}
	if s.state == nil {
		return true
	}
	key := s.state.keyFromEvent(env)
	return s.state.tick(s.now(), key)
}

// sweep prunes expired keys from the rule's bounded state. Called by
// the engine's janitor tick on a coarse cadence so the hot Match path
// stays focused on the one key that just matched. No-op for stateless
// rules — the type-assertion in the engine skips them.
func (s *sigmaCompiledRule) sweep(now time.Time) {
	if s.state == nil {
		return
	}
	s.state.sweep(now)
}

// rule returns the underlying ruleast.Rule — used by the finding builder to
// project rule metadata (title, description, level) into DetectionFinding.
func (s *sigmaCompiledRule) rule() *ruleast.Rule { return s.r }
