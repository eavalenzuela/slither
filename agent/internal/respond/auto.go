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

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
	"github.com/t3rmit3/slither/pkg/ruleeval"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

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
}

// NewAutoResponder wires the bridge. executor is required; policy may
// be nil (treated as a permanent detect-only baseline — useful for
// tests + the gap before #84 wires the real policy cache).
func NewAutoResponder(executor *Executor, policy PolicyProvider) *AutoResponder {
	return &AutoResponder{executor: executor, policy: policy}
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
