// Package ruleeval is the OCSF-backed evaluator for compiled Sigma
// rules. The agent's edge engine and the server's detection engine
// (Phase 3 #58) both feed events through this package so the field
// taxonomy stays single-sourced — no two-place rot when an OCSF
// schema bump renames a path.
//
// The evaluator implements pkg/ruleast.Env so any *ruleast.Rule can
// run against an Event without knowing whether it's running on agent
// or server.
package ruleeval

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// Env adapts an OCSF event to the ruleast.Env contract. Construct one
// per event using EnvFor, which selects the right Accessor for the
// event's Sigma category.
type Env struct {
	event  ocsf.Event
	access Accessor
}

// EnvFor returns an Env that resolves Sigma field names against the
// given event using the supplied accessor. The accessor is chosen by
// the caller (typically AccessorFor(category)) so the cost of category
// → table lookup is paid once per rule, not per event.
func EnvFor(event ocsf.Event, access Accessor) *Env {
	return &Env{event: event, access: access}
}

// Lookup returns the string values bound to a Sigma field on the
// current event. Unknown or unpopulated fields return (nil, false) so
// rules see a non-match instead of a panic — Sigma's
// missing-field-is-not-a-match contract.
func (e *Env) Lookup(field string) ([]string, bool) {
	if e == nil || e.access == nil {
		return nil, false
	}
	fn, ok := e.access[field]
	if !ok {
		return nil, false
	}
	vs := fn(e.event)
	if len(vs) == 0 {
		return nil, false
	}
	return vs, true
}

// Compile-time check: *Env satisfies ruleast.Env.
var _ ruleast.Env = (*Env)(nil)
