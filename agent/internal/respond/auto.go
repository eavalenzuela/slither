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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
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

// SnapshotDispatcher is the AutoResponder's view of the extension
// manager's snapshot fanout. Implementations return one
// extensions.SnapshotDispatch per provider, or
// extensions.ErrNoSnapshotProvider when no extension declares the
// capability. Phase 6 #111 wires *extensions.Manager as the production
// implementation; tests pass an in-memory stub.
//
// The interface mirrors the manager's signature without importing it,
// keeping the respond package free of an extensions dependency that
// would otherwise pull in cosign/sigverify on every test build.
type SnapshotDispatcher interface {
	DispatchSnapshot(ctx context.Context, req *pb.SnapshotRequest) ([]SnapshotProviderReplies, error)
}

// SnapshotProviderReplies is one provider's per-extension reassembly
// channel. Mirrors extensions.SnapshotDispatch shape.
type SnapshotProviderReplies struct {
	ExtensionName string
	Replies       <-chan *pb.ExtensionToAgent
}

// ErrNoSnapshotProvider mirrors extensions.ErrNoSnapshotProvider so
// the AutoResponder can distinguish "fanout had no providers" (a clean
// no-op the operator should see in the UX) from any other dispatch
// failure. The extensions package's sentinel value is wrapped on the
// dispatcher's adapter into this one.
var ErrNoSnapshotProvider = errors.New("respond: no extension declares snapshot_provide")

// snapshotPerProviderTimeout bounds how long the AutoResponder waits
// for one extension to deliver SnapshotComplete. 60 s is generous —
// real forensic snapshots (process memory, file dumps) take seconds
// not minutes — but caps a wedged extension cleanly.
const snapshotPerProviderTimeout = 60 * time.Second

// AutoResponder is the engine→executor bridge. Construct via
// NewAutoResponder and pass the resulting *AutoResponder to the
// engine's Options.AutoRespondHook.
type AutoResponder struct {
	executor  *Executor
	policy    PolicyProvider
	snapshots SnapshotDispatcher
	telem     *telemetry.Counters

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

// SetSnapshotDispatcher installs the optional Phase 6 #111 snapshot
// fanout. Calling with nil keeps the responder in detect-only mode for
// snapshot=true rules — findings are stamped with x_snapshot_no_providers
// so the alert detail page surfaces the no-op note.
//
// telem is plumbed alongside so the dispatcher's per-provider
// completed/failed accounting lands on the agent's standard counters.
// Both calls are race-free with hook firing because the engine
// installs the hook after wiring.
func (a *AutoResponder) SetSnapshotDispatcher(d SnapshotDispatcher, telem *telemetry.Counters) {
	if a == nil {
		return
	}
	a.snapshots = d
	a.telem = telem
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
// Phase 6 #111 added the `snapshot` flag. When true the responder
// fans a SnapshotRequest out to every CAPABILITY_SNAPSHOT_PROVIDE
// extension, reassembles the per-extension tarball, and submits a
// synthetic COLLECT_ARTIFACTS ResponseRequest carrying the result blob
// + alert/extension hints so the server's persistArtefact lands the
// blob under <artefactDir>/<alert_id>/<extension_name>.tgz. Snapshot
// dispatch is independent of the response intent — a rule may carry
// snapshot=true and no response, which is still a valid hook call.
//
// Returns nothing — failures (no policy, target unresolved, executor
// queue full) all surface either as a stamped would_have_executed=true
// or, for queue-full, a synthetic FAILED ResponseResult the executor
// itself emits. The engine doesn't need to know the difference.
func (a *AutoResponder) OnFinding(ctx context.Context, intent *ruleast.ResponseIntent, snapshot bool, trigger ocsf.Event, finding *ocsf.DetectionFinding, category ruleast.Category) {
	if a == nil || finding == nil {
		return
	}
	if snapshot {
		a.dispatchSnapshot(ctx, finding)
	}
	if intent == nil {
		return
	}
	finding.AutoResponseAction = string(intent.Action)

	// Host-scoped actions (isolate/unisolate) don't draw a target from
	// the triggering event: the isolate handler autoderives the mgmt
	// subnet from /proc/net/route and the unisolate handler ignores
	// Target entirely. Resolving target_field here would at best produce
	// a value the handler must discard and at worst a PID-shaped string
	// that fails the isolate handler's CIDR parse. So we skip resolution
	// and submit an empty Target; the dedupe key falls back to a stable
	// per-(rule,action) token below so repeat firings don't re-isolate.
	hostScoped := intent.Action.IsHostScoped()

	var target string
	if !hostScoped {
		target = resolveTargetField(trigger, intent.TargetField, category)
		if target == "" {
			// Field never resolved — target_field is no longer required to
			// appear in a predicate, and the firing event might still leave
			// it empty (e.g. a quarantine rule matching on Image but
			// target_field of CommandLine which was empty for this row).
			// Treat as detect-only so the audit chain still records the
			// rule's intent without an unresolvable Target on the wire.
			finding.AutoResponseWouldHaveExecuted = true
			return
		}
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
	// Host-scoped actions carry an empty Target, so dedupe on a stable
	// per-action token instead — otherwise shouldDedupe's empty-target
	// short-circuit would let every firing re-isolate the host, spamming
	// audit rows (the iptables hook itself is idempotent, but the rows
	// aren't). Entity-scoped actions keep deduping on the resolved target.
	dedupeTarget := target
	if hostScoped {
		dedupeTarget = "host:" + string(intent.Action)
	}
	if a.shouldDedupe(finding.RuleInfo.UID, dedupeTarget) {
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

// dispatchSnapshot fans a SnapshotRequest to every loaded extension
// declaring CAPABILITY_SNAPSHOT_PROVIDE, reassembles the per-extension
// tarball, and submits a synthetic COLLECT_ARTIFACTS ResponseRequest
// carrying the blob + alert/extension hints. The server's
// persistArtefact reads the hints to write the blob under
// <artefactDir>/<alert_id>/<extension_name>.tgz.
//
// Stamps the finding's snapshot markers regardless of dispatch
// outcome:
//
//   - x_snapshot_no_providers when the manager returns
//     ErrNoSnapshotProvider — alert-detail page renders "(no snapshot
//     extensions configured)".
//   - x_snapshot_requested when at least one provider was reached.
//
// Per-provider reassembly runs in a goroutine bounded by
// snapshotPerProviderTimeout. Best-effort: a single extension's wedge
// or SHA-mismatch fails its own audit row but doesn't block the others.
func (a *AutoResponder) dispatchSnapshot(ctx context.Context, finding *ocsf.DetectionFinding) {
	if a.snapshots == nil {
		// Detect-only baseline — no fanout target wired. Still mark
		// the finding so the operator sees the rule asked for a
		// snapshot but the agent had nowhere to ask.
		finding.SnapshotNoProviders = true
		return
	}
	alertID := finding.Finding.UID
	if alertID == "" {
		// Defensive — findings without a UID can't key on-disk layout.
		// The compiler enforces UID at engine emit time, but the
		// AutoResponder mustn't assume.
		slog.Warn("respond: snapshot dispatch skipped: finding has no uid",
			"rule_uid", finding.RuleInfo.UID)
		return
	}
	req := &pb.SnapshotRequest{
		SnapshotId: uuid.NewString(),
		AlertId:    alertID,
		// Target is left empty in Phase 6 — no extension consumes it.
		// Phase 7 extensions can read finding.x_triggering_event_ids /
		// rule.uid to infer a target if needed.
	}
	dispatches, err := a.snapshots.DispatchSnapshot(ctx, req)
	if errors.Is(err, ErrNoSnapshotProvider) {
		finding.SnapshotNoProviders = true
		return
	}
	if err != nil {
		slog.Warn("respond: snapshot dispatch failed",
			"rule_uid", finding.RuleInfo.UID, "alert_id", alertID, "err", err)
		finding.SnapshotNoProviders = true
		return
	}
	finding.SnapshotRequested = true
	// Per-extension reassembly runs concurrently. The hook returns as
	// soon as fanout has launched; the executor submission lands
	// asynchronously when reassembly completes.
	for _, d := range dispatches {
		d := d
		go a.reassembleAndSubmit(ctx, alertID, finding.RuleInfo.UID, d)
	}
}

// reassembleAndSubmit consumes one provider's reply channel until
// SnapshotComplete arrives (or the channel closes / timeout fires),
// verifies the rolling SHA-256 chain, and submits a
// RESPONSE_ACTION_COLLECT_ARTIFACTS ResponseRequest carrying the
// tarball + path hints. Best-effort throughout: chunk drops, SHA
// mismatch, and timeout each tick the failed counter and return.
func (a *AutoResponder) reassembleAndSubmit(ctx context.Context, alertID, ruleUID string, d SnapshotProviderReplies) {
	deadline := time.NewTimer(snapshotPerProviderTimeout)
	defer deadline.Stop()

	hasher := sha256.New()
	var buf []byte
	manifest := ""

	for {
		select {
		case <-ctx.Done():
			a.tickSnapshotFailed()
			return
		case <-deadline.C:
			slog.Warn("respond: snapshot reassembly timeout",
				"ext", d.ExtensionName, "alert_id", alertID, "rule_uid", ruleUID)
			a.tickSnapshotFailed()
			return
		case msg, ok := <-d.Replies:
			if !ok {
				// Channel closed without a Complete — extension
				// teardown counts as a failure. The success branch
				// below returns directly, so reaching this path means
				// the channel closed mid-stream.
				a.tickSnapshotFailed()
				return
			}
			switch payload := msg.Payload.(type) {
			case *pb.ExtensionToAgent_SnapshotChunk:
				chunk := payload.SnapshotChunk
				buf = append(buf, chunk.GetBytes()...)
				hasher.Write(chunk.GetBytes())
				got := hex.EncodeToString(hasher.Sum(nil))
				if want := chunk.GetSha256(); want != "" && want != got {
					slog.Warn("respond: snapshot sha mismatch",
						"ext", d.ExtensionName, "alert_id", alertID,
						"want", want, "got", got)
					a.tickSnapshotFailed()
					return
				}
			case *pb.ExtensionToAgent_SnapshotComplete:
				if e := payload.SnapshotComplete.GetError(); e != "" {
					slog.Warn("respond: snapshot terminal error",
						"ext", d.ExtensionName, "alert_id", alertID, "err", e)
					a.tickSnapshotFailed()
					return
				}
				manifest = payload.SnapshotComplete.GetManifest()
				a.submitSnapshotBlob(alertID, ruleUID, d.ExtensionName, buf, manifest)
				a.tickSnapshotCompleted()
				return
			}
		}
	}
}

// submitSnapshotBlob hands the reassembled tarball off to the executor
// as a synthetic COLLECT_ARTIFACTS request. The server's persistArtefact
// reads SnapshotAlertId + SnapshotExtensionName to land the blob
// under <artefactDir>/<alert_id>/<extension_name>.tgz; missing hints
// fall back to the v0 <action_id>.tgz layout.
//
// The blob round-trips on the executor because that's the wire path
// already audited (#75 OnResult inserts a response_actions row keyed
// by rule_uid for agent-initiated actions). Snapshot blobs land as
// rule-driven COLLECT_ARTIFACTS rows with a fresh control_id; the
// _ = manifest stays unused in v1 — operator-visible manifest UX is a
// Phase 7 concern.
func (a *AutoResponder) submitSnapshotBlob(alertID, ruleUID, extName string, blob []byte, manifest string) {
	if a.executor == nil {
		return
	}
	_ = manifest
	req := &pb.ResponseRequest{
		ControlId:             uuid.NewString(),
		Action:                pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS,
		Target:                "snapshot:" + extName,
		RuleUid:               ruleUID,
		SnapshotAlertId:       alertID,
		SnapshotExtensionName: extName,
	}
	// The executor's COLLECT_ARTIFACTS handler runs the standard
	// /var/lib/slither inventory tar — but for snapshot dispatches the
	// agent already has the blob in hand. We bypass the handler by
	// wiring a snapshot-specific direct emit: the executor's regular
	// flow doesn't accept a pre-built blob, so we synthesise the
	// ResponseResult here and feed it directly into the result channel.
	//
	// emitSnapshotResult sits behind the same outbound channel the
	// executor uses, preserving #75 OnResult's row-creation contract.
	a.executor.EmitSnapshotResult(req, blob)
}

func (a *AutoResponder) tickSnapshotCompleted() {
	if a.telem != nil {
		a.telem.IncExtSnapshotCompleted()
	}
}

func (a *AutoResponder) tickSnapshotFailed() {
	if a.telem != nil {
		a.telem.IncExtSnapshotFailed()
	}
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
