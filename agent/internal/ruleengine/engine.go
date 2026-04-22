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
	"fmt"
	"sort"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ErrDetectionQueueFull is returned by Run when the output channel refuses a
// DetectionFinding within the bounded wait. Per IMPLEMENTATION.md §3.5,
// detections are never dropped — we surface a diagnostic instead.
var ErrDetectionQueueFull = errors.New("ruleengine: detection queue full — sink not draining")

// Engine is the interface exposed to the pipeline orchestrator.
type Engine interface {
	// Run consumes events from in and emits enriched items (the original
	// event plus any DetectionFinding it produced) on Output().
	Run(ctx context.Context, in <-chan ocsf.Event) error
	// Output returns the channel of events + findings destined for the sink.
	Output() <-chan ocsf.Event
	// ReplaceRules atomically swaps the compiled rule set.
	ReplaceRules(rules []CompiledRule)
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

// detectionBlockWait bounds how long Run waits for a DetectionFinding send
// before declaring the sink broken. 200 ms is long enough to absorb a jittery
// downstream flush, short enough that the diagnostic fires before operators
// mistake a stalled agent for a quiet one.
const detectionBlockWait = 200 * time.Millisecond

// New returns an Engine loaded with the given compiled rules.
func New(rules []CompiledRule, telem *telemetry.Counters) Engine {
	return &engine{
		index:   indexByClass(rules),
		telem:   telem,
		out:     make(chan ocsf.Event, 2048),
		now:     time.Now,
		replace: make(chan map[ocsf.ClassID][]CompiledRule, 1),
	}
}

type engine struct {
	index   map[ocsf.ClassID][]CompiledRule
	telem   *telemetry.Counters
	out     chan ocsf.Event
	now     func() time.Time
	replace chan map[ocsf.ClassID][]CompiledRule
}

// ReplaceRules swaps in a freshly-compiled rule set. The Run loop applies
// the swap before evaluating the next event; calls made concurrently or
// before Run starts are coalesced to the latest.
func (e *engine) ReplaceRules(rules []CompiledRule) {
	idx := indexByClass(rules)
	select {
	case e.replace <- idx:
	default:
		select {
		case <-e.replace:
		default:
		}
		select {
		case e.replace <- idx:
		default:
		}
	}
}

func (e *engine) Output() <-chan ocsf.Event { return e.out }

// Run pumps events through the rule index. Every event is forwarded to the
// sink; each match also produces a DetectionFinding on the same channel.
func (e *engine) Run(ctx context.Context, in <-chan ocsf.Event) error {
	defer close(e.out)

	for {
		// Pending replace always wins over the next event so reloads apply
		// deterministically even when the input channel is backed up.
		select {
		case idx := <-e.replace:
			e.index = idx
		default:
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case idx := <-e.replace:
			e.index = idx
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if err := e.processEvent(ctx, ev); err != nil {
				return err
			}
		}
	}
}

// processEvent emits ev, then any findings it triggers. Event-priority sends
// are non-blocking; detection sends block up to detectionBlockWait and return
// ErrDetectionQueueFull if the sink is still full.
func (e *engine) processEvent(ctx context.Context, ev ocsf.Event) error {
	e.telem.IncEvents()

	select {
	case e.out <- ev:
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Event priority: drop and move on. Detection priority gets its own
		// path below.
		e.telem.IncDrops()
	}

	// Followup events are deferred enrichments of prior events the engine has
	// already evaluated. Running rules against them would double-count
	// detections for a single logical action, so we pass them through to the
	// sink without re-matching.
	if isFollowup(ev) {
		return nil
	}

	rules := e.index[ev.ClassID()]
	for _, r := range rules {
		if !r.Match(ev) {
			continue
		}
		finding := e.findingFor(r, ev)
		if finding == nil {
			continue
		}
		if err := e.emitDetection(ctx, finding); err != nil {
			return err
		}
		e.telem.IncDetections()
	}
	return nil
}

// isFollowup reports whether ev carries the "followup" metadata label. The
// enricher tags its hash-followup emissions this way so the engine can skip
// rule matching without needing a dedicated event type.
func isFollowup(ev ocsf.Event) bool {
	var labels []string
	switch v := ev.(type) {
	case *ocsf.ProcessActivity:
		labels = v.Metadata.Labels
	case *ocsf.FileSystemActivity:
		labels = v.Metadata.Labels
	case *ocsf.NetworkActivity:
		labels = v.Metadata.Labels
	default:
		return false
	}
	for _, l := range labels {
		if l == "followup" {
			return true
		}
	}
	return false
}

// findingFor builds a DetectionFinding from a match. sigmaCompiledRule exposes
// its underlying ruleast rule; external CompiledRule implementations would
// need their own path, but Phase 1 ships only the sigma adapter.
func (e *engine) findingFor(r CompiledRule, ev ocsf.Event) *ocsf.DetectionFinding {
	scr, ok := r.(*sigmaCompiledRule)
	if !ok {
		// Non-sigma rule type shipped from elsewhere — skip rather than
		// invent metadata. Not expected in Phase 1.
		return nil
	}
	return buildFinding(scr.rule(), ev, e.now())
}

func (e *engine) emitDetection(ctx context.Context, f *ocsf.DetectionFinding) error {
	select {
	case e.out <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	t := time.NewTimer(detectionBlockWait)
	defer t.Stop()
	select {
	case e.out <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("%w (capacity %d)", ErrDetectionQueueFull, cap(e.out))
	}
}

// indexByClass groups rules per OCSF class and pre-sorts each bucket
// cheap-first. Sorting once at construction keeps the hot loop branch-free.
func indexByClass(rules []CompiledRule) map[ocsf.ClassID][]CompiledRule {
	out := make(map[ocsf.ClassID][]CompiledRule)
	for _, r := range rules {
		if r == nil {
			continue
		}
		for _, c := range r.AppliesTo() {
			out[c] = append(out[c], r)
		}
	}
	for c := range out {
		bucket := out[c]
		sort.SliceStable(bucket, func(i, j int) bool {
			return bucket[i].Cost() < bucket[j].Cost()
		})
		out[c] = bucket
	}
	return out
}
