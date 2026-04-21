// Package ruleengine evaluates OCSF events against the stateless Sigma subset.
//
// Phase 1 scope (IMPLEMENTATION.md §3.5):
//   - Compiled rules indexed by OCSF class id.
//   - Rules sorted by predicate count; cheaper rules run first to short-circuit.
//   - Match emits an OCSF DetectionFinding alongside the triggering event.
//   - No stateful / windowed rules; those land in Phase 3 per ADR-0019.
package ruleengine

import (
	"context"
	"errors"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ErrNotImplemented is returned by evaluation paths that aren't wired yet.
var ErrNotImplemented = errors.New("ruleengine: not yet implemented")

// Engine is the interface exposed to the pipeline orchestrator.
type Engine interface {
	// Run consumes events from in and emits enriched items (the original
	// event plus any DetectionFinding it produced) on Output().
	Run(ctx context.Context, in <-chan ocsf.Event) error
	// Output returns the channel of events + findings destined for the sink.
	Output() <-chan ocsf.Event
}

// CompiledRule is a rule that has been compiled by pkg/ruleast and classified
// as edge-eligible for this agent.
type CompiledRule interface {
	// ID returns the stable rule identifier (Sigma `id:`).
	ID() string
	// AppliesTo returns the OCSF class ids this rule can match.
	AppliesTo() []ocsf.ClassID
	// Match evaluates the rule against an event.
	Match(e ocsf.Event) bool
	// Cost is a predicate-count heuristic used for ordering.
	Cost() int
}

// New returns an Engine loaded with the given compiled rules.
func New(rules []CompiledRule, telem *telemetry.Counters) Engine {
	return &engine{rules: rules, telem: telem, out: make(chan ocsf.Event, 2048)}
}

type engine struct {
	rules []CompiledRule
	telem *telemetry.Counters
	out   chan ocsf.Event
}

func (e *engine) Output() <-chan ocsf.Event { return e.out }

// Run: Phase 1 task #20 fills this in.
func (e *engine) Run(ctx context.Context, in <-chan ocsf.Event) error {
	<-ctx.Done()
	return ctx.Err()
}
