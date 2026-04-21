package ruleengine

import (
	"fmt"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// CompileRules wraps a set of already-parsed ruleast rules in CompiledRule
// adapters indexed by OCSF class. A rule whose category has no OCSF mapping
// fails compilation loudly — we don't want silent rule-drop at startup.
func CompileRules(rules []*ruleast.Rule) ([]CompiledRule, error) {
	out := make([]CompiledRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		cls, ok := categoryToClass(r.Category)
		if !ok {
			return nil, fmt.Errorf("ruleengine: rule %q: unsupported category %q", r.ID, r.Category)
		}
		acc := accessorFor(r.Category)
		if acc == nil {
			return nil, fmt.Errorf("ruleengine: rule %q: no field taxonomy for %q", r.ID, r.Category)
		}
		out = append(out, &sigmaCompiledRule{r: r, class: cls, access: acc})
	}
	return out, nil
}

// sigmaCompiledRule is the engine-side view of a ruleast.Rule.
type sigmaCompiledRule struct {
	r      *ruleast.Rule
	class  ocsf.ClassID
	access fieldAccessor
}

func (s *sigmaCompiledRule) ID() string                { return s.r.ID }
func (s *sigmaCompiledRule) AppliesTo() []ocsf.ClassID { return []ocsf.ClassID{s.class} }
func (s *sigmaCompiledRule) Cost() int                 { return s.r.Cost() }

func (s *sigmaCompiledRule) Match(e ocsf.Event) bool {
	if e.ClassID() != s.class {
		return false
	}
	return s.r.Match(&ocsfEnv{event: e, access: s.access})
}

// rule returns the underlying ruleast.Rule — used by the finding builder to
// project rule metadata (title, description, level) into DetectionFinding.
func (s *sigmaCompiledRule) rule() *ruleast.Rule { return s.r }
