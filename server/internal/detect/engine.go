package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/ruleeval"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// ruleEvalEnv builds a ruleeval.Env tied to ev using the plan's
// pre-resolved Accessor.
func ruleEvalEnv(p *plan, ev ocsf.Event) *ruleeval.Env {
	return ruleeval.EnvFor(ev, p.access)
}

// aggCompare matches the agent's bounded-stateful comparison shape.
// Kept separate so Phase 4 work can vary server-side semantics (e.g.
// percentiles, distinct counts) without touching the agent.
func aggCompare(op ruleast.AggOp, count, threshold int64) bool {
	switch op {
	case ruleast.AggGT:
		return count > threshold
	case ruleast.AggGTE:
		return count >= threshold
	case ruleast.AggLT:
		return count < threshold
	case ruleast.AggLTE:
		return count <= threshold
	case ruleast.AggEQ:
		return count == threshold
	case ruleast.AggNE:
		return count != threshold
	}
	return false
}

// defaults that operators can override via Options. Values mirror the
// IMPLEMENTATION.md §5.1 #58 spec — 1h windows, 10 000 keys per rule,
// 4096-event subscription buffer.
const (
	defaultMaxKeysPerRule = 10_000
	defaultBusBuffer      = 4096
	defaultJanitorTick    = 30 * time.Second
	defaultFindingsBuffer = 256
	defaultSubscriberName = "detect"
)

// Options tunes Engine behaviour. All zero-values fall back to
// documented defaults so callers can pass an empty struct.
type Options struct {
	MaxKeysPerRule int
	BusBuffer      int
	JanitorTick    time.Duration
	FindingsBuffer int
	SubscriberName string
}

func (o Options) withDefaults() Options {
	if o.MaxKeysPerRule <= 0 {
		o.MaxKeysPerRule = defaultMaxKeysPerRule
	}
	if o.BusBuffer <= 0 {
		o.BusBuffer = defaultBusBuffer
	}
	if o.JanitorTick <= 0 {
		o.JanitorTick = defaultJanitorTick
	}
	if o.FindingsBuffer <= 0 {
		o.FindingsBuffer = defaultFindingsBuffer
	}
	if o.SubscriberName == "" {
		o.SubscriberName = defaultSubscriberName
	}
	return o
}

// RuleSource lists rules in the same shape the control hub uses, so
// the detect engine can feed off pg.Store without an extra interface
// adapter. The engine filters to classification ∈ {server_only, both}.
type RuleSource interface {
	ListEnabledRules(ctx context.Context) ([]pg.Rule, error)
}

// Engine subscribes to ingest.Bus, decodes envelope payloads to
// ocsf.Event, and runs every server-only Sigma plan against each
// event. Aggregation rules fire when their per-key count crosses the
// threshold; near rules fire when both selections have a hit inside
// the join window.
type Engine struct {
	bus     *ingest.Bus
	src     RuleSource
	telem   *telemetry.Counters
	opts    Options
	now     func() time.Time
	plans   atomicPlans
	subName string

	findings chan Finding
}

// New constructs an Engine. src and bus are required; telem may be nil
// (no counters). Opts may be the zero value.
func New(bus *ingest.Bus, src RuleSource, telem *telemetry.Counters, opts Options) *Engine {
	if bus == nil {
		panic("detect.New: nil bus")
	}
	if src == nil {
		panic("detect.New: nil rule source")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	opts = opts.withDefaults()
	return &Engine{
		bus:      bus,
		src:      src,
		telem:    telem,
		opts:     opts,
		now:      time.Now,
		subName:  opts.SubscriberName,
		findings: make(chan Finding, opts.FindingsBuffer),
	}
}

// Findings returns the channel of fired findings. The alert sink (#60)
// drains it; tests use it for assertions. The channel is closed when
// Run exits.
func (e *Engine) Findings() <-chan Finding { return e.findings }

// Refresh rebuilds the plan slice from src, replacing the active set
// atomically. Plans whose source_yaml no longer compiles or whose
// server_plan is malformed are skipped with a count returned.
func (e *Engine) Refresh(ctx context.Context) (skipped int, err error) {
	rows, err := e.src.ListEnabledRules(ctx)
	if err != nil {
		return 0, fmt.Errorf("detect.Refresh: list: %w", err)
	}
	planRows := make([]rulePlanRow, 0, len(rows))
	for _, r := range rows {
		planRows = append(planRows, rulePlanRow{
			UID:            r.UID,
			SourceYAML:     r.SourceYAML,
			Classification: r.Classification,
			ServerPlanJSON: r.ServerPlanJSON,
		})
	}
	plans, skipped := compilePlans(planRows, e.opts.MaxKeysPerRule, func(ruleID string) {
		if e.telem != nil {
			e.telem.IncDetectStateEvicted()
		}
		slog.Debug("detect: window key evicted", "rule_uid", ruleID)
	})
	e.plans.store(plans)
	slog.Info("detect: refreshed",
		"plan_count", len(plans),
		"skipped", skipped,
		"max_keys_per_rule", e.opts.MaxKeysPerRule)
	return skipped, nil
}

// Run subscribes to the bus and processes events until ctx is
// cancelled. A coarse janitor sweeps every plan's window on a fixed
// tick to reclaim memory from group keys that stopped being touched.
// Findings exceeding the channel buffer are dropped (the alert sink
// is the consumer; backpressure on findings cannot be allowed to
// stall the bus).
func (e *Engine) Run(ctx context.Context) error {
	defer close(e.findings)

	// Initial refresh — failure is fatal here because an empty
	// plan-set means no detection is happening; operators expect
	// the engine to start with whatever was in pg.
	if _, err := e.Refresh(ctx); err != nil {
		return fmt.Errorf("detect: initial refresh: %w", err)
	}

	events := e.bus.Subscribe(e.subName, e.opts.BusBuffer)
	defer e.bus.Unsubscribe(e.subName)

	jt := time.NewTicker(e.opts.JanitorTick)
	defer jt.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-jt.C:
			e.sweep()
		case env, ok := <-events:
			if !ok {
				return nil
			}
			e.process(env)
		}
	}
}

func (e *Engine) sweep() {
	now := e.now()
	for _, p := range e.plans.load() {
		p.window.sweep(now)
	}
}

// process runs every loaded plan against env. Decode happens once per
// event, not per plan, so a 50-rule pack pays one JSON unmarshal.
// Plans whose category doesn't match the envelope's class id are
// short-circuited without decoding their predicate.
func (e *Engine) process(env *pb.Envelope) {
	if env == nil {
		return
	}
	plans := e.plans.load()
	if len(plans) == 0 {
		return
	}
	cls := ocsf.ClassID(env.GetClassId())
	if cls == 0 {
		return
	}
	if e.telem != nil {
		e.telem.IncDetectEvents()
	}
	now := e.now()

	// Decode once per matching class — multiple plans on the same class
	// share the decoded event. We cache the decode lazily.
	var (
		decoded     ocsf.Event
		decodeErr   error
		decodeClass ocsf.ClassID
	)
	getEvent := func(want ocsf.ClassID) ocsf.Event {
		if decoded != nil && decodeClass == want {
			return decoded
		}
		if decodeErr != nil {
			return nil
		}
		decoded, decodeErr = decodeEnvelope(env, want)
		decodeClass = want
		return decoded
	}

	for _, p := range plans {
		if p.class != cls {
			continue
		}
		ev := getEvent(p.class)
		if ev == nil {
			continue
		}
		e.runPlan(now, p, ev, env)
	}
}

func (e *Engine) runPlan(now time.Time, p *plan, ev ocsf.Event, env *pb.Envelope) {
	// Phase 3 #58 server-only rules currently emit either an
	// aggregation or a near join — never both — and the predicate
	// is always the rule's boolean tree. Predicate match is the gate
	// for both kinds.
	switch p.kind {
	case planAggregation:
		e.runAggregation(now, p, ev, env)
	case planNear:
		e.runNear(now, p, ev, env)
	}
}

func (e *Engine) runAggregation(now time.Time, p *plan, ev ocsf.Event, env *pb.Envelope) {
	if !matchPredicate(p, ev) {
		return
	}
	key := composeKey(byTupleValues(p, ev))
	hits, count := p.window.record(now, key, env.GetEventId(), env.GetHostId())
	if !aggCompare(p.agg.Op, int64(count), p.agg.Threshold) {
		return
	}
	e.fire(Finding{
		RuleID:      p.rule.ID,
		RuleTitle:   p.rule.Title,
		Severity:    p.severity,
		HostID:      hostIDForFinding(p, env),
		GroupKey:    key,
		FiredAt:     now,
		WindowStart: hits[0].at,
		WindowEnd:   now,
		EventIDs:    eventIDsFromHits(hits),
		Reason:      fmt.Sprintf("count(*) %s %d over %s", p.agg.Op, p.agg.Threshold, p.window.window),
	})
}

func (e *Engine) runNear(now time.Time, p *plan, ev ocsf.Event, env *pb.Envelope) {
	// near needs to know which side of the join the current event
	// matches. Selections are name-keyed in the rule body; the join
	// spec carries the names. We re-evaluate per-side so an event
	// that matches both sides records into both rings (Sigma's
	// classic semantics where near is symmetric).
	left := selectionMatches(p, ev, p.join.Left)
	right := selectionMatches(p, ev, p.join.Right)
	if !left && !right {
		return
	}
	if left {
		_, _ = p.window.record(now, joinKeyLeft, env.GetEventId(), env.GetHostId())
	}
	if right {
		_, _ = p.window.record(now, joinKeyRight, env.GetEventId(), env.GetHostId())
	}
	// Fire when both sides have at least one live hit in the window.
	leftHits, lCount := p.window.peek(now, joinKeyLeft)
	rightHits, rCount := p.window.peek(now, joinKeyRight)
	if lCount == 0 || rCount == 0 {
		return
	}
	ids := make([]string, 0, lCount+rCount)
	for _, h := range leftHits {
		ids = append(ids, h.eventID)
	}
	for _, h := range rightHits {
		ids = append(ids, h.eventID)
	}
	e.fire(Finding{
		RuleID:      p.rule.ID,
		RuleTitle:   p.rule.Title,
		Severity:    p.severity,
		HostID:      hostIDForFinding(p, env),
		GroupKey:    fmt.Sprintf("%s→%s", p.join.Left, p.join.Right),
		FiredAt:     now,
		WindowStart: earliestHit(leftHits, rightHits),
		WindowEnd:   now,
		EventIDs:    ids,
		Reason:      fmt.Sprintf("%s near %s within %s", p.join.Left, p.join.Right, p.window.window),
	})
}

func (e *Engine) fire(f Finding) {
	if e.telem != nil {
		e.telem.IncDetectFindings()
	}
	select {
	case e.findings <- f:
	default:
		// Findings backed up — drop newest. The alert sink is the
		// consumer; ingest must never stall.
		if e.telem != nil {
			e.telem.IncDetectFindingsDropped()
		}
	}
}

// matchPredicate evaluates the rule's boolean tree. For NodeNear
// rules the tree is the join itself, which we don't want to call here;
// the caller checks p.kind first.
func matchPredicate(p *plan, ev ocsf.Event) bool {
	if ev.ClassID() != p.class {
		return false
	}
	env := ruleEvalEnv(p, ev)
	return p.rule.Match(env)
}

// selectionMatches evaluates a single named selection against ev.
// near-side decisions need this rather than the full Condition.
func selectionMatches(p *plan, ev ocsf.Event, name string) bool {
	if ev.ClassID() != p.class {
		return false
	}
	sel, ok := p.rule.Selections[name]
	if !ok {
		return false
	}
	env := ruleEvalEnv(p, ev)
	return sel.Eval(env)
}

// byTupleValues looks up each `by Field` in p.agg using the rule's
// selection-evaluator env so the projection is identical to
// matchPredicate's. Missing fields render as "" — composeKey turns
// those into the literal "<nil>" so a missing user doesn't merge
// silently with a present-user-"<nil>" event.
func byTupleValues(p *plan, ev ocsf.Event) []string {
	if p.agg == nil || len(p.agg.By) == 0 {
		return nil
	}
	env := ruleEvalEnv(p, ev)
	out := make([]string, len(p.agg.By))
	for i, f := range p.agg.By {
		v, ok := env.Lookup(f)
		if !ok || len(v) == 0 {
			out[i] = ""
			continue
		}
		out[i] = v[0]
	}
	return out
}

// hostIDForFinding stamps the triggering envelope's host on the
// finding. Cross-host aggregations still pin a host_id from whichever
// envelope crossed the threshold — operators want to land in /events
// filtered by that host when they click through. Phase 4 may
// distinguish per-host vs fleet findings explicitly.
func hostIDForFinding(_ *plan, env *pb.Envelope) string {
	return env.GetHostId()
}

// eventIDsFromHits projects hits onto their event IDs so Findings can
// reference the contributing envelopes.
func eventIDsFromHits(hits []hit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.eventID
	}
	return out
}

// earliestHit returns the older of either ring's first timestamp.
// Used to stamp the WindowStart on a near-fired Finding.
func earliestHit(a, b []hit) time.Time {
	switch {
	case len(a) > 0 && len(b) > 0:
		if a[0].at.Before(b[0].at) {
			return a[0].at
		}
		return b[0].at
	case len(a) > 0:
		return a[0].at
	case len(b) > 0:
		return b[0].at
	}
	return time.Time{}
}

// decodeEnvelope unmarshals env.Payload into the right OCSF type for
// class. Any decode error returns nil so the engine drops the event
// for that plan; we never return errors out of the bus consumer.
func decodeEnvelope(env *pb.Envelope, class ocsf.ClassID) (ocsf.Event, error) {
	payload := env.GetPayload()
	if len(payload) == 0 {
		return nil, errors.New("empty payload")
	}
	switch class {
	case ocsf.ClassProcessActivity:
		var v ocsf.ProcessActivity
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return &v, nil
	case ocsf.ClassFileSystemActivity:
		var v ocsf.FileSystemActivity
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return &v, nil
	case ocsf.ClassNetworkActivity:
		var v ocsf.NetworkActivity
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return &v, nil
	}
	return nil, fmt.Errorf("unsupported class %d", class)
}

// atomicPlans is a simple swap-pointer holder so Refresh can replace
// the active plan slice without a lock on the hot path.
type atomicPlans struct {
	mu    sync.RWMutex
	plans []*plan
}

func (a *atomicPlans) store(plans []*plan) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.plans = plans
}

func (a *atomicPlans) load() []*plan {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.plans
}
