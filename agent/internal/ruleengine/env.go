package ruleengine

import "github.com/t3rmit3/slither/pkg/ocsf"

// ocsfEnv adapts an OCSF event to the ruleast.Env interface. One instance is
// built per event per rule — its zero allocation cost (just two pointer-sized
// fields) keeps hot-path evaluation cheap.
type ocsfEnv struct {
	event  ocsf.Event
	access fieldAccessor
}

// Lookup returns the string values bound to a Sigma field on the current
// event. Unknown or unpopulated fields return (nil, false) so Sigma rules
// see a non-match instead of a panic.
func (e *ocsfEnv) Lookup(field string) ([]string, bool) {
	if e.access == nil {
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
