// Package control owns the server's outbound rule distribution
// (Phase 2 §4.1 task #39). It compiles enabled `rules` rows into a
// pb.RuleSet and broadcasts the latest version to every connected
// agent Session via per-subscriber channels.
//
// Ordering invariants:
//
//   - The hub stores exactly one canonical *pb.RuleSet at a time. New
//     subscribers receive that snapshot immediately on Subscribe.
//   - When the rules table changes, Refresh() rebuilds the snapshot
//     and fans it out to every active subscriber. Slow subscribers
//     drop intermediate versions but always converge to the latest:
//     each subscriber channel holds capacity 1, and Publish replaces
//     a stale value rather than blocking.
//
// Wire-format note: EdgeRule.compiled_ast carries the raw Sigma YAML
// for ast_version=1. Phase 2 ships YAML pass-through so the agent can
// reuse pkg/ruleast.CompileSigma without a parallel deserialiser; a
// future ast_version may switch to a stable serialised AST.
package control

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// astVersion is the wire format identifier for EdgeRule.compiled_ast.
// 1 == raw Sigma YAML bytes; the agent runs CompileSigma on them.
const astVersion = 1

// RuleSource lists enabled rules; pg.Store satisfies it. Factored as
// an interface so tests can pass a stub without spinning up Postgres.
type RuleSource interface {
	ListEnabledRules(ctx context.Context) ([]pg.Rule, error)
}

// Hub is the broadcast point for RuleSet pushes.
type Hub struct {
	src   RuleSource
	telem *telemetry.Counters

	mu      sync.Mutex
	current *pb.RuleSet
	subs    map[string]chan *pb.RuleSet
	version atomic.Uint64
}

// NewHub constructs a Hub. src is required; telem may be nil and is
// substituted with a fresh counters value.
func NewHub(src RuleSource, telem *telemetry.Counters) *Hub {
	if src == nil {
		panic("control.NewHub: nil rule source")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &Hub{
		src:   src,
		telem: telem,
		subs:  make(map[string]chan *pb.RuleSet),
	}
}

// Refresh rebuilds the canonical RuleSet from the source and fans it
// out. Compilation errors on individual rules are skipped (a malformed
// rule must not block distribution of the rest); the count of skipped
// rules is returned alongside any fatal error.
func (h *Hub) Refresh(ctx context.Context) (skipped int, err error) {
	rows, err := h.src.ListEnabledRules(ctx)
	if err != nil {
		return 0, fmt.Errorf("control.Refresh: list: %w", err)
	}
	rs, skipped := buildRuleSet(rows, h.version.Add(1))

	h.mu.Lock()
	h.current = rs
	subs := make([]chan *pb.RuleSet, 0, len(h.subs))
	for _, ch := range h.subs {
		subs = append(subs, ch)
	}
	h.mu.Unlock()

	for _, ch := range subs {
		h.publishOne(ch, rs)
	}
	h.telem.IncRulesetsPushed()
	return skipped, nil
}

// Subscribe registers a per-session subscriber. The returned channel
// has capacity 1 — Publish overwrites a stale value rather than
// blocking. The current RuleSet (if any) is delivered synchronously
// before the channel is returned, so newly-connected agents converge
// without a separate priming round-trip.
func (h *Hub) Subscribe(name string) <-chan *pb.RuleSet {
	ch := make(chan *pb.RuleSet, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.subs[name]; ok {
		close(old) // forces stale receiver out
	}
	h.subs[name] = ch
	if h.current != nil {
		ch <- h.current
	}
	return ch
}

// Unsubscribe removes name and closes its channel.
func (h *Hub) Unsubscribe(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.subs[name]; ok {
		close(ch)
		delete(h.subs, name)
	}
}

// Current returns a pointer to the latest RuleSet snapshot or nil if
// Refresh hasn't run yet. Callers must not mutate the returned value.
func (h *Hub) Current() *pb.RuleSet {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current
}

// publishOne sends rs into ch, draining any stale value first so the
// subscriber always sees the latest snapshot rather than a queued
// older one.
func (h *Hub) publishOne(ch chan *pb.RuleSet, rs *pb.RuleSet) {
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- rs:
	default:
		// Receiver gone or channel closed; nothing to do.
	}
}

// buildRuleSet compiles each row's YAML to extract metadata (name,
// severity, mitre tags) and bundles the result into a pb.RuleSet whose
// EdgeRule.compiled_ast carries the YAML bytes for the agent to
// recompile. version is the monotonic ruleset version assigned by the
// caller. Returns the count of rows that failed compilation.
func buildRuleSet(rows []pg.Rule, version uint64) (rs *pb.RuleSet, skipped int) {
	rules := make([]*pb.EdgeRule, 0, len(rows))
	for _, r := range rows {
		compiled, err := ruleast.CompileSigma([]byte(r.SourceYAML))
		if err != nil {
			// A row that no longer compiles is dropped from the wire
			// payload but kept in the table — operators see the row
			// in audit, agents see one fewer rule. Phase 4 console
			// surfaces compile errors back to the editor (#42/#43).
			skipped++
			continue
		}
		rules = append(rules, &pb.EdgeRule{
			RuleId:      r.UID,
			Name:        ruleDisplayName(r, compiled),
			Severity:    levelToSeverity(compiled.Level),
			MitreIds:    compiled.Tags,
			CompiledAst: []byte(r.SourceYAML),
			AstVersion:  astVersion,
		})
	}
	return &pb.RuleSet{
		ControlId:  fmt.Sprintf("ruleset-%d", version),
		Version:    fmt.Sprintf("%d", version),
		CompiledAt: timestamppb.New(time.Now()),
		Rules:      rules,
	}, skipped
}

func ruleDisplayName(r pg.Rule, compiled *ruleast.Rule) string {
	if r.Name != "" {
		return r.Name
	}
	if compiled.Title != "" {
		return compiled.Title
	}
	return r.UID
}

// levelToSeverity maps Sigma's level strings to the OCSF severity_id
// enum. Unknown levels fall back to Informational (1).
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

// ensure errors is exported so future error-wrapping changes don't
// silently drop the import.
var _ = errors.Is
