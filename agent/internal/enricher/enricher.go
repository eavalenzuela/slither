// Package enricher converts raw kernel events into OCSF events.
//
// Responsibilities (IMPLEMENTATION.md §3.4):
//   - Maintain a pid-keyed process cache populated on exec/fork, evicted on
//     exit (with a grace period for late-arriving events).
//   - Resolve ppid chains to depth 8 for process.parent_process in OCSF.
//   - Kick off async SHA-256 hashing on exec; attach inline if ready or emit
//     a followup event referencing event_id otherwise (Phase 1 task #23).
//   - Resolve uid → username via a /etc/passwd snapshot refreshed on SIGHUP.
package enricher

import (
	"context"
	"errors"

	"github.com/t3rmit3/slither/agent/internal/collector"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ErrNotImplemented is returned by enrichment paths that have not been wired.
var ErrNotImplemented = errors.New("enricher: not yet implemented")

// Enricher is the interface exposed to the pipeline orchestrator.
type Enricher interface {
	// Run blocks until ctx is cancelled, draining raw events from the
	// collector group and emitting OCSF events on Events().
	Run(ctx context.Context) error
	// Events returns the channel of enriched OCSF events.
	Events() <-chan ocsf.Event
}

// Options parameterises the enricher's caches and workers.
type Options struct {
	// ParentChainDepth caps ppid-walk depth (default 8).
	ParentChainDepth int
	// HashWorkers bounds the async hashing pool (default 4).
	HashWorkers int
	// HashInlineTimeoutMs is the budget for inline hash attachment.
	HashInlineTimeoutMs int
}

// New constructs an Enricher that reads from the given collector group.
func New(cg *collector.Group, telem *telemetry.Counters, opts Options) Enricher {
	return &enricher{cg: cg, telem: telem, opts: opts, out: make(chan ocsf.Event, 2048)}
}

type enricher struct {
	cg    *collector.Group
	telem *telemetry.Counters
	opts  Options
	out   chan ocsf.Event
}

func (e *enricher) Events() <-chan ocsf.Event { return e.out }

// Run: Phase 1 task #18 fills this in.
func (e *enricher) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
