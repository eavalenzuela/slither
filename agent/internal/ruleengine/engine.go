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
	"github.com/t3rmit3/slither/pkg/ruleast"
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
	// SetAutoRespondHook installs the optional Phase 4 #83 hook.
	// Engine calls hook.OnFinding when a rule with a response intent
	// fires; the hook decides (based on cached HostPolicy) whether
	// to actually run the local executor.
	SetAutoRespondHook(h AutoRespondHook)
	// SetAuditChain installs the Phase 5 #95 tamper-evident chain.
	// Nil disables the chain.
	SetAuditChain(c ChainAppender)
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

// AutoRespondHook is the engine→executor bridge for Phase 4 #83.
// Implementations decide based on the firing rule's intent + the
// agent's cached HostPolicy whether to actually invoke the local
// Executor. The hook may mutate finding.AutoResponse* fields before
// the finding ships to the sink.
//
// Phase 6 #111 added the `snapshot` flag. Engine calls the hook
// whenever a rule fires AND any of (intent != nil, snapshot == true)
// holds; the hook decides whether to dispatch a response action, a
// snapshot fanout, both, or neither (e.g. policy-denied + no
// providers).
type AutoRespondHook interface {
	OnFinding(ctx context.Context, intent *ruleast.ResponseIntent, snapshot bool, trigger ocsf.Event, finding *ocsf.DetectionFinding, category ruleast.Category)
}

// ChainAppender is the engine's view of selfprotect.ChainWriter.
// Engine appends one record per emitted detection finding for Phase
// 5 #95 tamper-evident audit. Mirrors the respond.ChainAppender
// shape so a single ChainWriter satisfies both consumers.
type ChainAppender interface {
	Append(kind string, summary any) error
}

// detectionBlockWait bounds how long Run waits for a DetectionFinding send
// before declaring the sink broken. 200 ms is long enough to absorb a jittery
// downstream flush, short enough that the diagnostic fires before operators
// mistake a stalled agent for a quiet one.
const detectionBlockWait = 200 * time.Millisecond

// janitorInterval is the cadence at which Run sweeps every stateful
// rule's expired keys. Coarse on purpose: the hot Match path already
// trims the one key it just touched, so the janitor only needs to
// reclaim memory from keys that have stopped being referenced. Per
// ADR-0018 the per-rule cap is 1024 keys, so even a missed sweep
// caps the worst-case footprint trivially. 30 s matches the agent's
// heartbeat cadence so operators see one rhythm.
const janitorInterval = 30 * time.Second

type engine struct {
	index    map[ocsf.ClassID][]CompiledRule
	telem    *telemetry.Counters
	out      chan ocsf.Event
	now      func() time.Time
	replace  chan map[ocsf.ClassID][]CompiledRule
	autoHook AutoRespondHook
	chain    ChainAppender
}

// SetAuditChain installs the optional Phase 5 #95 audit chain.
// Calling with nil disables the chain. Safe to call before Run.
func (e *engine) SetAuditChain(c ChainAppender) {
	e.chain = c
}

// New returns an Engine loaded with the given compiled rules.
func New(rules []CompiledRule, telem *telemetry.Counters) Engine {
	return &engine{
		index:   indexByClass(rules),
		telem:   telem,
		out:     make(chan ocsf.Event, 16384),
		now:     time.Now,
		replace: make(chan map[ocsf.ClassID][]CompiledRule, 1),
	}
}

// SetAutoRespondHook installs the optional Phase 4 #83 hook. Calling
// with nil disables auto-respond. Concurrent with rule evaluation: a
// rule firing during the swap reads whichever pointer was current at
// finding time.
func (e *engine) SetAutoRespondHook(h AutoRespondHook) {
	e.autoHook = h
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
//
// A janitor ticker sweeps stateful rules every janitorInterval so expired
// by-keys get reaped without any per-rule goroutines — this keeps rule
// lifecycle simple (ReplaceRules just swaps the index, no goroutine
// teardown) while still satisfying ADR-0018's "lock-light hot path"
// requirement: Match's tick only trims the key it just touched.
func (e *engine) Run(ctx context.Context, in <-chan ocsf.Event) error {
	defer close(e.out)

	jt := time.NewTicker(janitorInterval)
	defer jt.Stop()

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
		case <-jt.C:
			e.sweepStateful()
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

// sweepStateful walks every rule in the index and asks any stateful
// adapter to prune its expired keys. Rules without state (the common
// case in Phase 2) skip the type assertion's allocation by definition.
// Iteration over the index map is fine here — the engine's index is
// only mutated on ReplaceRules which goes through the same select
// arm, never concurrently with the ticker.
func (e *engine) sweepStateful() {
	now := e.now()
	seen := make(map[CompiledRule]struct{}, len(e.index))
	for _, bucket := range e.index {
		for _, r := range bucket {
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			if sr, ok := r.(statefulRule); ok {
				sr.sweep(now)
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
		e.telem.IncDropEngine()
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
		// Phase 4 #83: invoke the auto-respond hook before shipping
		// the finding so x_auto_response_executed /
		// x_auto_response_would_have_executed land on the same
		// payload the server logs as the alert.
		if e.autoHook != nil {
			if intent, snapshot, cat, ok := ruleHookInfo(r); ok {
				e.autoHook.OnFinding(ctx, intent, snapshot, ev, finding, cat)
			}
		}
		if err := e.emitDetection(ctx, finding); err != nil {
			return err
		}
		e.telem.IncDetections()

		// Phase 5 #95 — append a tamper-evident audit row. Best-
		// effort: chain errors don't tear down the engine. Summary
		// captures rule + host + finding identity (severity_id +
		// finding_uid via OCSF spec) so verify-logs's output ties
		// back to specific findings without dragging the whole
		// payload into the chain.
		if e.chain != nil {
			_ = e.chain.Append("detection_finding", map[string]any{
				"rule_uid":        finding.RuleInfo.UID,
				"finding_uid":     finding.Finding.UID,
				"severity":        finding.Severity,
				"auto_response":   finding.AutoResponseAction,
				"executed":        finding.AutoResponseExecuted,
				"would_have_exec": finding.AutoResponseWouldHaveExecuted,
			})
		}
	}
	return nil
}

// ruleHookInfo extracts the rule's response intent, snapshot flag, and
// category if the underlying type exposes them (sigmaCompiledRule
// does). Returns ok=true when the rule warrants a hook call —
// i.e., any of intent != nil OR snapshot == true. External CompiledRule
// implementations without these accessors skip the hook.
//
// Phase 4 #83 lit up the response side; Phase 6 #111 added the
// snapshot side. The hook receives both regardless so a rule with
// snapshot=true and no response still dispatches.
func ruleHookInfo(r CompiledRule) (*ruleast.ResponseIntent, bool, ruleast.Category, bool) {
	type withResponse interface {
		Response() *ruleast.ResponseIntent
		Category() ruleast.Category
	}
	type withSnapshot interface {
		Snapshot() bool
	}
	wr, ok := r.(withResponse)
	if !ok {
		return nil, false, "", false
	}
	intent := wr.Response()
	var snapshot bool
	if ws, ok := r.(withSnapshot); ok {
		snapshot = ws.Snapshot()
	}
	if intent == nil && !snapshot {
		return nil, false, "", false
	}
	return intent, snapshot, wr.Category(), true
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
