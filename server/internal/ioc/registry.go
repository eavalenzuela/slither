// Package ioc owns the server's IOC-feed registry — the compile-time
// surface that resolves `ioc:<feed_id>` references in Sigma rules
// (Phase 3 #66 / ADR-0018 predicate 3).
//
// Architecture: a thin atomic.Pointer-swapped snapshot of the iocs
// table, refreshed before every hub rule recompile so a freshly
// inserted oversize feed flips a rule's classification on the next
// refresh tick. Lookups are O(1) map reads on the snapshot — the hot
// path runs inside the Sigma compiler at every rule push.
package ioc

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// FeedSource is the narrow Postgres surface the registry uses;
// pg.Store satisfies it. Factored as an interface so tests stub the
// store without spinning up a database.
type FeedSource interface {
	ListIOCFeeds(ctx context.Context) ([]pg.IOCFeed, error)
	GetIOCFeedEntries(ctx context.Context, feedID string) (pg.IOCFeedWithEntries, error)
}

// Registry caches feed metadata for the compile-time gate. Concurrent
// Refresh + Lookup are safe — Lookup reads the atomic snapshot;
// Refresh swaps a new map in atomically.
type Registry struct {
	src      FeedSource
	snapshot atomic.Pointer[snapshot]
}

type snapshot struct {
	feeds map[string]feedEntry
}

type feedEntry struct {
	count   int
	kind    string
	entries []string
}

// New constructs an empty registry. Call Refresh once before serving
// the first rule recompile, otherwise every IOC reference will fail
// the compile gate.
func New(src FeedSource) *Registry {
	if src == nil {
		panic("ioc.New: nil source")
	}
	r := &Registry{src: src}
	empty := &snapshot{feeds: map[string]feedEntry{}}
	r.snapshot.Store(empty)
	return r
}

// Refresh re-queries the source and atomically swaps in a fresh
// snapshot. Returns the entry count loaded so callers can log
// observability around the swap.
func (r *Registry) Refresh(ctx context.Context) (int, error) {
	feeds, err := r.src.ListIOCFeeds(ctx)
	if err != nil {
		return 0, fmt.Errorf("ioc.Registry.Refresh: %w", err)
	}
	next := &snapshot{feeds: make(map[string]feedEntry, len(feeds))}
	for _, f := range feeds {
		// Loading entries upfront keeps the wire-build path read-only
		// against the snapshot (no per-push pg query). Memory cost is
		// bounded by the per-feed cap × feed count; production tuning
		// notes live in ADR-0018.
		full, ferr := r.src.GetIOCFeedEntries(ctx, f.FeedID)
		if ferr != nil {
			return 0, fmt.Errorf("ioc.Registry.Refresh: load %q: %w", f.FeedID, ferr)
		}
		next.feeds[f.FeedID] = feedEntry{
			count:   full.EntryCount,
			kind:    string(full.Kind),
			entries: full.Entries,
		}
	}
	r.snapshot.Store(next)
	return len(feeds), nil
}

// Lookup satisfies ruleast.IOCRegistry. Returns (0, "", false) for
// unknown feeds — the compiler treats those as a hard error so a
// typo'd feed_id never silently skips the rule.
func (r *Registry) Lookup(feedID string) (entryCount int, kind string, ok bool) {
	snap := r.snapshot.Load()
	if snap == nil {
		return 0, "", false
	}
	entry, present := snap.feeds[feedID]
	if !present {
		return 0, "", false
	}
	return entry.count, entry.kind, true
}

// Entries returns the cached feed entries + kind for feedID. Used by
// the control hub (Phase 3 #67) to populate RuleSet.IocFeeds before
// each push so the agent has the feed contents in hand alongside the
// rule that references them. Returns (nil, "", false) for unknown
// feeds.
func (r *Registry) Entries(feedID string) (entries []string, kind string, ok bool) {
	snap := r.snapshot.Load()
	if snap == nil {
		return nil, "", false
	}
	entry, present := snap.feeds[feedID]
	if !present {
		return nil, "", false
	}
	return entry.entries, entry.kind, true
}

// Compile-time guard that Registry implements ruleast.IOCRegistry.
var _ ruleast.IOCRegistry = (*Registry)(nil)
