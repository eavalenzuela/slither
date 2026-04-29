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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ruleast"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// astVersionStateless is the wire-format tag for EdgeRule.compiled_ast
// on stateless rules — raw Sigma YAML bytes the agent decodes via
// ruleast.Compile (Phase 1 / Phase 2 wire shape, ADR-0032 V1).
//
// Stateful rules (Phase 3 #54d) ride V2 — same YAML pass-through, but
// the agent allocates a state ring on rule load and the compiler-emitted
// state_window_secs / state_cap fields communicate ADR-0018 bounds.
const (
	astVersionStateless = uint32(1)
	astVersionStateful  = uint32(2)
)

// RuleSource lists enabled rules; pg.Store satisfies it. Factored as
// an interface so tests can pass a stub without spinning up Postgres.
type RuleSource interface {
	ListEnabledRules(ctx context.Context) ([]pg.Rule, error)
}

// IOCRegistrar refreshes + looks up IOC feed sizes for the compiler's
// predicate-3 gate. *ioc.Registry satisfies it. Optional — when nil,
// rules referencing `|ioc:<feed_id>` predicates fail compile and are
// dropped from the wire payload (rather than silently slipping past
// ADR-0018).
type IOCRegistrar interface {
	Refresh(ctx context.Context) (int, error)
	ruleast.IOCRegistry
}

// Hub is the broadcast point for RuleSet pushes.
type Hub struct {
	src   RuleSource
	iocs  IOCRegistrar
	telem *telemetry.Counters

	mu      sync.Mutex
	current *pb.RuleSet
	subs    map[string]chan *pb.RuleSet
	version atomic.Uint64
}

// NewHub constructs a Hub. src is required; telem may be nil and is
// substituted with a fresh counters value. iocs is optional — passing
// it enables the IOC compile-time gate.
func NewHub(src RuleSource, telem *telemetry.Counters, iocs IOCRegistrar) *Hub {
	if src == nil {
		panic("control.NewHub: nil rule source")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &Hub{
		src:   src,
		iocs:  iocs,
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
	if h.iocs != nil {
		feedCount, refreshErr := h.iocs.Refresh(ctx)
		if refreshErr != nil {
			// Don't tear down the rule push because IOC refresh
			// flapped; the previous snapshot is still atomically
			// readable. Log loudly so an oncall sees the drift.
			slog.Warn("hub: ioc registry refresh failed (using stale snapshot)",
				"err", refreshErr)
		} else {
			slog.Debug("hub: ioc registry refreshed", "feed_count", feedCount)
		}
	}
	rs, skipped := buildRuleSet(rows, h.version.Add(1), h.iocs)

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
	h.telem.IncRulesetRefreshes()
	slog.Info("hub: refreshed",
		"rule_count", len(rs.GetRules()),
		"skipped", skipped,
		"version", rs.GetVersion(),
		"subscribers", len(subs))
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

// buildRuleSet compiles each row's YAML, drops server-only rules from
// the wire payload (per ADR-0032 server plans never reach agents), and
// bundles the rest into a pb.RuleSet whose EdgeRule.compiled_ast still
// carries the YAML bytes for v1/v2 agents. Stateful rules ride
// ast_version=2 with state_window_secs / state_cap populated from the
// compiler's verdict so the agent can enforce ADR-0018 hard caps at
// load time. Returns the count of rows that failed compilation or were
// classified server-only — both are skipped from the agent push.
//
// Per-rule classification is logged at INFO via the slog facade (#49)
// so operators can audit what landed where without scraping pg.
func buildRuleSet(rows []pg.Rule, version uint64, iocs ruleast.IOCRegistry) (rs *pb.RuleSet, skipped int) {
	rules := make([]*pb.EdgeRule, 0, len(rows))
	var compileOpts []ruleast.CompileOption
	if iocs != nil {
		compileOpts = append(compileOpts, ruleast.WithIOCRegistry(iocs))
	}
	for _, r := range rows {
		artefact, _, class, err := ruleast.Compile([]byte(r.SourceYAML), compileOpts...)
		if err != nil {
			// A row that no longer compiles is dropped from the wire
			// payload but kept in the table — operators see the row
			// in audit, agents see one fewer rule. Phase 4 console
			// surfaces compile errors back to the editor (#42/#43).
			slog.Warn("hub: skip rule (compile failed)",
				"rule_uid", r.UID, "err", err)
			skipped++
			continue
		}
		if class == ruleast.ClassificationServerOnly {
			slog.Info("hub: skip rule (server-only)",
				"rule_uid", r.UID, "classification", string(class))
			skipped++
			continue
		}
		er := &pb.EdgeRule{
			RuleId:      r.UID,
			Name:        ruleDisplayName(r, artefact.Rule),
			Severity:    levelToSeverity(artefact.Rule.Level),
			MitreIds:    artefact.Rule.Tags,
			CompiledAst: []byte(r.SourceYAML),
			AstVersion:  uint32(artefact.ASTVersion),
		}
		if artefact.ASTVersion == ruleast.ASTVersionV2 {
			er.StateWindowSecs = artefact.StateWindowSecs
			er.StateCap = artefact.StateCap
		}
		slog.Info("hub: include rule",
			"rule_uid", r.UID,
			"classification", string(class),
			"ast_version", er.AstVersion,
			"state_window_secs", er.StateWindowSecs,
			"state_cap", er.StateCap)
		rules = append(rules, er)
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
