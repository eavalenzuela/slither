// Phase 4 #83: agent-side auto-respond bridge between the rule
// engine and the executor.
//
// The rule engine calls into AutoResponder when a stateless or
// stateful rule fires AND the rule carries a `slither.response`
// intent. The responder consults the cached HostPolicy:
//
//   - Permitted: build a ResponseRequest, submit it to the local
//     Executor with rule_uid set + operator_id empty (rule-driven),
//     and stamp the finding with x_auto_response_executed=true.
//   - Denied (detect-only host): leave the executor alone; stamp
//     x_auto_response_would_have_executed=true so analysts see
//     "this would have killed the shell if you'd flipped the
//     allow_kill_process bit on this host's policy".
//
// HostPolicy lives behind atomic.Pointer so #84's NOTIFY-driven push
// can swap it in under load without the engine pausing. A nil
// pointer means "no policy seen yet" — treated as detect-only so the
// agent never auto-responds before the server has a chance to set
// expectations.

package respond

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/ruleeval"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// dedupeWindow is the lookback the AutoResponder uses to suppress
// duplicate executor submissions for the same (rule_uid, target) pair.
// Phase 4 #86 surfaced the duplicate-fire pattern: a single exec event
// can match a rule via the immediate-fire path AND emerge again via a
// post-hashing followup, producing two response_actions rows for the
// same kill. The finding still emits twice (it's an honest observation
// of two pipeline stages); only the executor submission is deduped.
//
// 2 s is a comfortable upper bound on the gap between the exec event
// and any hash/enrich-followup arriving at the engine — the captures
// from V5 showed both findings within the same millisecond, so 2 s is
// 1000× margin.
const dedupeWindow = 2 * time.Second

// PolicyProvider returns the latest cached HostPolicy. nil means "no
// policy seen yet" → detect-only. Implementations are expected to be
// atomic-load fast (no mutex on the engine hot path).
type PolicyProvider func() *pb.HostPolicy

// AutoResponder is the engine→executor bridge. Construct via
// NewAutoResponder and pass the resulting *AutoResponder to the
// engine's Options.AutoRespondHook.
type AutoResponder struct {
	executor *Executor
	policy   PolicyProvider

	// now is overridable for tests; defaults to time.Now.
	now func() time.Time

	// recent guards executor submissions for the same (rule_uid,
	// target) pair within dedupeWindow. Lazily swept on every call —
	// the cardinality is bounded by the number of distinct firing
	// rules × distinct targets seen in a 2 s window, which is small
	// in practice.
	mu     sync.Mutex
	recent map[string]time.Time
}

// NewAutoResponder wires the bridge. executor is required; policy may
// be nil (treated as a permanent detect-only baseline — useful for
// tests + the gap before #84 wires the real policy cache).
func NewAutoResponder(executor *Executor, policy PolicyProvider) *AutoResponder {
	return &AutoResponder{
		executor: executor,
		policy:   policy,
		now:      time.Now,
		recent:   make(map[string]time.Time),
	}
}

// shouldDedupe returns true when (ruleUID, target) was submitted to
// the executor within dedupeWindow. Side effect: records the current
// fire so subsequent duplicates are suppressed. Sweeps stale entries
// inline.
func (a *AutoResponder) shouldDedupe(ruleUID, target string) bool {
	if ruleUID == "" || target == "" {
		return false
	}
	key := ruleUID + "|" + target
	now := a.now()
	cutoff := now.Add(-dedupeWindow)

	a.mu.Lock()
	defer a.mu.Unlock()
	for k, t := range a.recent {
		if t.Before(cutoff) {
			delete(a.recent, k)
		}
	}
	if last, ok := a.recent[key]; ok && !last.Before(cutoff) {
		return true
	}
	a.recent[key] = now
	return false
}

// OnFinding is the engine hook. Called after the rule has fired and
// the finding has been built but before it ships to the sink, so this
// function is allowed to mutate finding's auto-response fields.
//
// trigger is the OCSF event that caused the rule to fire; the
// responder resolves intent.TargetField against it to produce the
// ResponseRequest's Target string.
//
// Returns nothing — failures (no policy, target unresolved, executor
// queue full) all surface either as a stamped would_have_executed=true
// or, for queue-full, a synthetic FAILED ResponseResult the executor
// itself emits. The engine doesn't need to know the difference.
func (a *AutoResponder) OnFinding(ctx context.Context, intent *ruleast.ResponseIntent, trigger ocsf.Event, finding *ocsf.DetectionFinding, category ruleast.Category) {
	if a == nil || intent == nil || finding == nil {
		return
	}
	finding.AutoResponseAction = string(intent.Action)

	target := resolveTargetField(trigger, intent.TargetField, category)
	if target == "" {
		// Field never resolved — the compiler already validated that the
		// field is referenced by some predicate, but the firing event
		// might still leave it empty (e.g. a quarantine rule that
		// matches on Image but the operator picked a target_field of
		// CommandLine which was empty for this row). Treat as detect-
		// only so the audit chain still records the rule's intent
		// without an unresolvable Target landing on the wire.
		finding.AutoResponseWouldHaveExecuted = true
		return
	}

	policy := a.policy
	var hp *pb.HostPolicy
	if policy != nil {
		hp = policy()
	}
	if !policyAllows(hp, intent.Action) {
		finding.AutoResponseWouldHaveExecuted = true
		return
	}

	// Phase 5 #88b: dedupe duplicate submissions for the same
	// (rule_uid, target) within a short window. The finding itself
	// still emits — it represents an honest observation of the rule
	// matching the event — but only the first observation drives an
	// executor submission. Subsequent observations leave the
	// executed/would_have_executed flags both false, which the
	// console surfaces as "rule fired again on the same target;
	// previous response is in flight or done".
	if a.shouldDedupe(finding.RuleInfo.UID, target) {
		return
	}

	req := &pb.ResponseRequest{
		ControlId: uuid.NewString(),
		// OperatorId is intentionally empty — rule-driven actions
		// carry rule_uid so the server's OnResult inserts a fresh
		// response_actions row keyed off rule_uid + action + target.
		Action:  actionToProto(intent.Action),
		Target:  target,
		RuleUid: finding.RuleInfo.UID,
	}
	if a.executor == nil || !a.executor.Submit(ctx, req) {
		// Queue-full path: executor.Submit already emitted a synthetic
		// FAILED with detail "agent executor queue full". Stamp the
		// finding so the console shows the rule wanted to fire but
		// couldn't — distinct from policy-denied.
		finding.AutoResponseWouldHaveExecuted = true
		return
	}
	finding.AutoResponseExecuted = true
}

// resolveTargetField returns the first bound value of field on
// trigger, or "" when the field isn't present on the event. Uses the
// same accessor table the rule engine uses for predicate evaluation
// so the resolution surface is identical (target_field == "Image"
// resolves to the same string the predicate matched on).
func resolveTargetField(trigger ocsf.Event, field string, category ruleast.Category) string {
	if trigger == nil || strings.TrimSpace(field) == "" {
		return ""
	}
	access := ruleeval.AccessorFor(category)
	if access == nil {
		return ""
	}
	env := ruleeval.EnvFor(trigger, access)
	values, ok := env.Lookup(field)
	if !ok || len(values) == 0 {
		return ""
	}
	return values[0]
}

// policyAllows mirrors server-side pg.HostPolicy.PermitsAction. A nil
// policy is the detect-only baseline (default-deny). UNISOLATE_HOST
// inherits ISOLATE_HOST per ADR-0034.
func policyAllows(p *pb.HostPolicy, action ruleast.ResponseAction) bool {
	if p == nil {
		return false
	}
	switch action {
	case ruleast.ResponseActionKillProcess:
		return p.GetAllowKillProcess()
	case ruleast.ResponseActionKillProcessTree:
		return p.GetAllowKillTree()
	case ruleast.ResponseActionQuarantineFile:
		return p.GetAllowQuarantine()
	case ruleast.ResponseActionIsolateHost, ruleast.ResponseActionUnisolateHost:
		return p.GetAllowIsolate()
	case ruleast.ResponseActionCollectArtifacts:
		return p.GetAllowCollect()
	}
	return false
}

// actionToProto converts the ruleast string enum to the proto enum.
// Unknown actions → UNSPECIFIED, which the executor's not-implemented
// default handler will surface as FAILED on the audit row.
func actionToProto(a ruleast.ResponseAction) pb.ResponseAction {
	switch a {
	case ruleast.ResponseActionKillProcess:
		return pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS
	case ruleast.ResponseActionKillProcessTree:
		return pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE
	case ruleast.ResponseActionQuarantineFile:
		return pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE
	case ruleast.ResponseActionIsolateHost:
		return pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST
	case ruleast.ResponseActionUnisolateHost:
		return pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST
	case ruleast.ResponseActionCollectArtifacts:
		return pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS
	}
	return pb.ResponseAction_RESPONSE_ACTION_UNSPECIFIED
}
