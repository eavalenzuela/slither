// Package respond owns the Phase 4 #75 response-action dispatcher.
//
// The dispatcher is the seam between operator intent (a console POST
// to /alerts/{id}/respond) or rule intent (an edge auto-respond
// finding) and the agent's executor on the wire. It sits in front of
// pg (response_actions / host_response_policies) and the agent
// SessionService send channel.
//
// Lifecycle of one action:
//
//  1. Dispatch() validates the requested action against the host's
//     policy (HostPolicy.PermitsAction). Detect-only hosts get a
//     "denied_by_policy" row written + an early return — the agent
//     never sees the request.
//  2. Permitted actions land as a `pending` row via
//     pg.InsertResponseAction.
//  3. The action is enqueued onto the per-host channel a session's
//     send goroutine consumes (see Subscribe below). Queue overflow
//     drops with a counter bump; the row stays in `pending` so an
//     operator can re-dispatch.
//  4. The agent runs the action and emits ResponseResult. The
//     SessionService.handle path calls OnResult, which transitions
//     the row to done/failed via pg.TransitionResponseAction (which
//     also writes the audit row, atomic with the state change).
//
// The Hub keeps a per-host capacity-N channel; new sessions Subscribe
// at session-open, queued actions stream onto the channel when the
// session is up. Disconnected agents see queued actions on reconnect
// (the Subscribe call drains any pending entries the hub had stashed).
package respond

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// queueDepth is the per-host pending channel capacity. Sized so a
// burst of operator-driven actions on a single host (e.g. an analyst
// killing every shell from a brute-force scenario) doesn't drop, but
// not so large that a wedged agent buffers unbounded.
const queueDepth = 32

// Hub fans response-action requests out to per-host channels for the
// SessionService send goroutines to consume. Safe for concurrent
// Dispatch + Subscribe + OnResult callers.
type Hub struct {
	store *pg.Store
	telem *telemetry.Counters

	// artefactDir is the on-disk path collect_artifacts blobs are
	// persisted under. Empty disables disk persistence (the blob
	// still lands in the response_actions row's result_blob column).
	// Set via NewHubWithOptions; main wires it to /var/lib/slither/artefacts.
	artefactDir string

	mu     sync.Mutex
	queues map[string]chan *pb.ResponseRequest // host_id -> pending dispatch channel
}

// HubOptions configures Hub. artefactDir, when non-empty, is the
// directory collect_artifacts result blobs land under as
// <action_id>.tgz. Phase 4 #81.
type HubOptions struct {
	ArtefactDir string
}

// NewHub constructs a Hub with no artefact-dir persistence. Existing
// callers (Phase 3 fleet) keep the original signature.
func NewHub(store *pg.Store, telem *telemetry.Counters) *Hub {
	return NewHubWithOptions(store, telem, HubOptions{})
}

// NewHubWithOptions is the artefact-dir-aware constructor. Phase 4
// #81 wires this in main with ArtefactDir set to the compose volume.
func NewHubWithOptions(store *pg.Store, telem *telemetry.Counters, opts HubOptions) *Hub {
	if store == nil {
		panic("respond.NewHub: nil store")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &Hub{
		store:       store,
		telem:       telem,
		artefactDir: opts.ArtefactDir,
		queues:      make(map[string]chan *pb.ResponseRequest),
	}
}

// DispatchInput is the input shape for the operator + rule paths.
type DispatchInput struct {
	HostID     string            // required
	AlertID    string            // optional
	Action     pg.ResponseAction // required
	Target     string            // required (pid/path/host_id)
	OperatorID string            // operator-driven path
	RuleUID    string            // rule-driven path
	Reason     string            // optional human-readable detail
	Deadline   time.Duration     // 0 = no deadline carried on the wire
}

// ErrPolicyDenied is returned when the host's policy does not permit
// the requested action class. The dispatcher still inserts a
// response_actions row with status=denied_by_policy so the audit
// trail captures the attempt.
var ErrPolicyDenied = errors.New("respond.Hub.Dispatch: action denied by host policy")

// Dispatch validates + persists + enqueues an action. Returns the
// pg.ResponseActionRow on success (status=pending) or on policy
// denial (status=denied_by_policy + ErrPolicyDenied wrapped).
//
// Caller is expected to short-circuit ErrPolicyDenied with a UI
// message rather than treating it as a server error — the row was
// still written so the audit chain is complete.
func (h *Hub) Dispatch(ctx context.Context, in DispatchInput) (pg.ResponseActionRow, error) {
	if in.HostID == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Dispatch: host_id required")
	}
	if in.Action == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Dispatch: action required")
	}
	if in.Target == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Dispatch: target required")
	}
	if in.OperatorID == "" && in.RuleUID == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Dispatch: operator_id or rule_uid required")
	}

	policy, err := h.store.GetHostPolicy(ctx, in.HostID)
	if err != nil {
		return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Dispatch: load policy: %w", err)
	}
	if !policy.PermitsAction(in.Action) {
		// Insert + transition to denied_by_policy so the audit chain
		// captures the rejection.
		row, ierr := h.store.InsertResponseAction(ctx, pg.ResponseActionInsert{
			HostID:     in.HostID,
			AlertID:    in.AlertID,
			Action:     in.Action,
			Target:     in.Target,
			OperatorID: in.OperatorID,
			RuleUID:    in.RuleUID,
			ReasonCode: in.Reason,
		})
		if ierr != nil {
			return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Dispatch: insert (denied path): %w", ierr)
		}
		denied, terr := h.store.TransitionResponseAction(ctx, pg.ResponseActionTransition{
			ActionID: row.ID,
			To:       pg.ResponseStatusDeniedByPolicy,
			Detail:   "host policy does not permit " + string(in.Action),
			ActorID:  in.OperatorID,
		})
		if terr != nil {
			return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Dispatch: deny: %w", terr)
		}
		return denied, fmt.Errorf("%w: action=%s", ErrPolicyDenied, in.Action)
	}

	row, err := h.store.InsertResponseAction(ctx, pg.ResponseActionInsert{
		HostID:     in.HostID,
		AlertID:    in.AlertID,
		Action:     in.Action,
		Target:     in.Target,
		OperatorID: in.OperatorID,
		RuleUID:    in.RuleUID,
		ReasonCode: in.Reason,
	})
	if err != nil {
		return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Dispatch: insert: %w", err)
	}

	req := &pb.ResponseRequest{
		ControlId:  row.ID,
		OperatorId: in.OperatorID,
		Action:     responseActionToProto(in.Action),
		Target:     in.Target,
	}
	if in.Deadline > 0 {
		req.Deadline = timestamppb.New(time.Now().Add(in.Deadline))
	}
	if !h.enqueue(in.HostID, req) {
		// Drop counter; row stays pending so an operator can re-dispatch.
		h.telem.IncResponseDropped()
		slog.Warn("respond: dispatch dropped (host queue full)",
			"host_id", in.HostID, "action_id", row.ID)
		return row, nil
	}
	h.telem.IncResponseDispatched()
	slog.Info("respond: dispatched",
		"host_id", in.HostID, "action_id", row.ID, "action", in.Action)
	return row, nil
}

// ErrNotReversible is returned by Revert when the parent's action
// class can't be reversed via the agent (e.g. KILL_PROCESS — once
// killed, a process can't be unkilled).
var ErrNotReversible = errors.New("respond.Hub.Revert: action class is not reversible")

// ErrParentNotDone is returned by Revert when the parent isn't in
// status=done. ADR-0034: only completed actions can be reverted; a
// failed/denied/already-reverted action stays in its terminal state.
var ErrParentNotDone = errors.New("respond.Hub.Revert: parent action is not in status=done")

// reverseActionFor maps a forward action class to its reversal. Two
// of the six classes are reversible:
//
//   - QUARANTINE_FILE → reverse via QUARANTINE_FILE + parent_action_id
//     (agent's handler dispatches to RestoreFromQuarantine).
//   - ISOLATE_HOST    → reverse via UNISOLATE_HOST.
//
// Everything else returns ErrNotReversible.
func reverseActionFor(a pg.ResponseAction) (pg.ResponseAction, error) {
	switch a {
	case pg.ResponseActionQuarantineFile:
		return pg.ResponseActionQuarantineFile, nil
	case pg.ResponseActionIsolateHost:
		return pg.ResponseActionUnisolateHost, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNotReversible, a)
}

// Revert is the operator-driven reversal entry point. Given the ID of
// a completed parent action, it:
//
//  1. Validates the parent exists and is in status=done.
//  2. Validates the parent's action class is reversible.
//  3. Validates the host's policy still permits the (parent's) action
//     class — un-isolate uses AllowIsolate per ADR-0034, un-quarantine
//     uses AllowQuarantine.
//  4. Inserts a new response_actions row with parent_action set + the
//     reverse action class.
//  5. Enqueues a ResponseRequest carrying parent_action_id so the
//     agent's handler reads the parent's sidecar / state to perform
//     the inverse.
//
// pg.TransitionResponseAction flips the parent to `reverted` when
// this child reaches done; that flow is already wired in the store.
//
// Returns the child row + ErrPolicyDenied wrapped if the host's
// policy refused (the row is still written with status=denied_by_policy
// so the audit chain captures the attempt).
func (h *Hub) Revert(ctx context.Context, parentID, operatorID string) (pg.ResponseActionRow, error) {
	if parentID == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Revert: parent_id required")
	}
	if operatorID == "" {
		return pg.ResponseActionRow{}, errors.New("respond.Hub.Revert: operator_id required")
	}

	parent, err := h.store.GetResponseAction(ctx, parentID)
	if err != nil {
		return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Revert: load parent: %w", err)
	}
	if parent.Status != pg.ResponseStatusDone {
		return pg.ResponseActionRow{}, fmt.Errorf("%w: parent status=%s", ErrParentNotDone, parent.Status)
	}
	revAction, err := reverseActionFor(parent.Action)
	if err != nil {
		return pg.ResponseActionRow{}, err
	}

	policy, err := h.store.GetHostPolicy(ctx, parent.HostID)
	if err != nil {
		return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Revert: load policy: %w", err)
	}
	// Permission check uses the *parent's* action class — un-isolate
	// inherits isolate, un-quarantine inherits quarantine. ADR-0034
	// reverse-inheritance rule.
	if !policy.PermitsAction(parent.Action) {
		row, ierr := h.store.InsertResponseAction(ctx, pg.ResponseActionInsert{
			HostID:       parent.HostID,
			AlertID:      parent.AlertID,
			Action:       revAction,
			Target:       parent.Target,
			OperatorID:   operatorID,
			ParentAction: parent.ID,
			ReasonCode:   "revert " + parent.ID,
		})
		if ierr != nil {
			return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Revert: insert (denied path): %w", ierr)
		}
		denied, terr := h.store.TransitionResponseAction(ctx, pg.ResponseActionTransition{
			ActionID: row.ID,
			To:       pg.ResponseStatusDeniedByPolicy,
			Detail:   "host policy does not permit revert of " + string(parent.Action),
			ActorID:  operatorID,
		})
		if terr != nil {
			return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Revert: deny: %w", terr)
		}
		return denied, fmt.Errorf("%w: revert action=%s", ErrPolicyDenied, revAction)
	}

	row, err := h.store.InsertResponseAction(ctx, pg.ResponseActionInsert{
		HostID:       parent.HostID,
		AlertID:      parent.AlertID,
		Action:       revAction,
		Target:       parent.Target,
		OperatorID:   operatorID,
		ParentAction: parent.ID,
		ReasonCode:   "revert " + parent.ID,
	})
	if err != nil {
		return pg.ResponseActionRow{}, fmt.Errorf("respond.Hub.Revert: insert: %w", err)
	}

	req := &pb.ResponseRequest{
		ControlId:      row.ID,
		OperatorId:     operatorID,
		Action:         responseActionToProto(revAction),
		Target:         parent.Target,
		ParentActionId: parent.ID,
	}
	if !h.enqueue(parent.HostID, req) {
		h.telem.IncResponseDropped()
		slog.Warn("respond: revert dropped (host queue full)",
			"host_id", parent.HostID, "action_id", row.ID, "parent_id", parent.ID)
		return row, nil
	}
	h.telem.IncResponseDispatched()
	slog.Info("respond: reverted",
		"host_id", parent.HostID, "action_id", row.ID,
		"parent_id", parent.ID, "reverse_action", revAction)
	return row, nil
}

// Subscribe is called by the SessionService send goroutine on Session
// open. Returns the per-host channel + an unsubscribe function. A
// session reconnecting to a host with queued (but undispatched)
// actions sees them on the channel immediately.
//
// Each host has at most one subscriber at a time — multiple agents
// claiming the same host_id is an enrolment-flow violation, not a
// dispatcher concern. If a duplicate Subscribe lands, the previous
// channel is closed (forces the previous send loop out) and the new
// session takes ownership.
func (h *Hub) Subscribe(hostID string) (queue <-chan *pb.ResponseRequest, unsubscribe func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.queues[hostID]; ok {
		close(old)
	}
	ch := make(chan *pb.ResponseRequest, queueDepth)
	h.queues[hostID] = ch
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if cur, ok := h.queues[hostID]; ok && cur == ch {
			close(cur)
			delete(h.queues, hostID)
		}
	}
}

// OnResult is the path the SessionService calls when an agent emits
// a ResponseResult. Resolves the response_actions row by control_id
// (which the dispatcher set to row.ID at enqueue time) and
// transitions to done/failed.
//
// hostID is the trusted Session host (set from the verified peer
// cert); used when the result is from an agent-initiated rule-driven
// action whose row doesn't exist yet — we insert a fresh row scoped
// to that host so the audit chain captures the firing.
func (h *Hub) OnResult(ctx context.Context, hostID string, result *pb.ResponseResult) error {
	if result == nil {
		return errors.New("respond.Hub.OnResult: nil result")
	}
	actionID := result.GetControlId()
	if actionID == "" {
		return errors.New("respond.Hub.OnResult: empty control_id")
	}
	// Validate that control_id is a UUID — both the server dispatcher
	// (operator-driven) and the agent's AutoResponder
	// (rule-driven, Phase 4 #83) generate UUIDs. A non-UUID is a
	// protocol violation from a future ad-hoc test client.
	if _, err := uuid.Parse(actionID); err != nil {
		return fmt.Errorf("respond.Hub.OnResult: control_id not a uuid: %w", err)
	}

	to := pg.ResponseStatusDone
	if result.GetStatus() == pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		to = pg.ResponseStatusFailed
	}

	// Look up the row by control_id. The dispatcher always sets
	// control_id = row.ID at enqueue time, so server-driven actions
	// resolve. Agent-initiated rule-driven actions (#83) have no
	// pre-existing row — when the lookup fails AND the result carries
	// the rule_uid + action + target stamps, insert a fresh row so the
	// audit chain captures the firing.
	current, err := h.store.GetResponseAction(ctx, actionID)
	if errors.Is(err, pg.ErrResponseActionNotFound) && result.GetRuleUid() != "" {
		ruleAction := protoToResponseAction(result.GetAction())
		if ruleAction == "" {
			return fmt.Errorf("respond.Hub.OnResult: agent-initiated result %s has unknown action enum %s",
				actionID, result.GetAction())
		}
		inserted, ierr := h.store.InsertResponseAction(ctx, pg.ResponseActionInsert{
			HostID:        hostID,
			Action:        ruleAction,
			Target:        result.GetTarget(),
			RuleUID:       result.GetRuleUid(),
			InitialStatus: pg.ResponseStatusRunning,
			ReasonCode:    "agent auto-respond",
		})
		if ierr != nil {
			return fmt.Errorf("respond.Hub.OnResult: insert agent-initiated row: %w", ierr)
		}
		// Override the row ID so subsequent transitions land on the
		// just-inserted row. The agent's control_id stays correlated
		// via reason_code; pg's row id is server-canonical.
		actionID = inserted.ID
		current = inserted
		err = nil
	}
	if err != nil {
		return fmt.Errorf("respond.Hub.OnResult: lookup %s: %w", actionID, err)
	}
	if current.Status == pg.ResponseStatusPending {
		if _, err := h.store.TransitionResponseAction(ctx, pg.ResponseActionTransition{
			ActionID: actionID,
			To:       pg.ResponseStatusRunning,
			ActorID:  current.OperatorID,
		}); err != nil {
			return fmt.Errorf("respond.Hub.OnResult: pending→running: %w", err)
		}
	}
	if _, err := h.store.TransitionResponseAction(ctx, pg.ResponseActionTransition{
		ActionID:   actionID,
		To:         to,
		Detail:     result.GetDetail(),
		ResultBlob: result.GetResultBlob(),
		ActorID:    current.OperatorID,
	}); err != nil {
		return fmt.Errorf("respond.Hub.OnResult: terminal: %w", err)
	}
	// Phase 4 #81: collect_artifacts blobs also land on disk under
	// the configured artefact dir so an analyst can `tar tf` them
	// without round-tripping through pg. The pg copy stays
	// authoritative; the disk copy is a convenience.
	if h.artefactDir != "" &&
		current.Action == pg.ResponseActionCollectArtifacts &&
		to == pg.ResponseStatusDone &&
		len(result.GetResultBlob()) > 0 {
		if perr := h.persistArtefact(actionID, result.GetResultBlob()); perr != nil {
			// Disk persistence is best-effort: the audit row + pg blob
			// are already committed. Log and move on so a wedged disk
			// can't fail the action retroactively.
			slog.Warn("respond: persist artefact to disk failed",
				"action_id", actionID, "err", perr)
		}
	}
	h.telem.IncResponseCompleted()
	return nil
}

// persistArtefact writes the result_blob to <artefactDir>/<action_id>.tgz.
// 0o600 keeps it inert to other UIDs sharing the host (the volume in
// compose is bind-mounted with the slither user only).
func (h *Hub) persistArtefact(actionID string, blob []byte) error {
	if mkErr := os.MkdirAll(h.artefactDir, 0o750); mkErr != nil {
		return fmt.Errorf("mkdir artefact dir: %w", mkErr)
	}
	path := filepath.Join(h.artefactDir, actionID+".tgz")
	if wErr := os.WriteFile(path, blob, 0o600); wErr != nil {
		return fmt.Errorf("write %s: %w", path, wErr)
	}
	return nil
}

// enqueue tries to push req onto the per-host channel. Returns false
// if the channel is full or no subscriber is attached — both cases
// surface as IncResponseDropped at the call site.
func (h *Hub) enqueue(hostID string, req *pb.ResponseRequest) bool {
	h.mu.Lock()
	ch, ok := h.queues[hostID]
	h.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- req:
		return true
	default:
		return false
	}
}

// protoToResponseAction is the inverse of responseActionToProto.
// Returns "" for UNSPECIFIED + any unknown enum value so callers can
// reject loudly rather than insert a row with a bogus action class.
func protoToResponseAction(a pb.ResponseAction) pg.ResponseAction {
	switch a {
	case pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS:
		return pg.ResponseActionKillProcess
	case pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE:
		return pg.ResponseActionKillTree
	case pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE:
		return pg.ResponseActionQuarantineFile
	case pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST:
		return pg.ResponseActionIsolateHost
	case pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST:
		return pg.ResponseActionUnisolateHost
	case pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS:
		return pg.ResponseActionCollectArtifacts
	}
	return ""
}

// responseActionToProto maps the pg-side string enum to the proto
// enum. Six action classes; ADR-0034 freezes both vocabularies.
func responseActionToProto(a pg.ResponseAction) pb.ResponseAction {
	switch a {
	case pg.ResponseActionKillProcess:
		return pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS
	case pg.ResponseActionKillTree:
		return pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE
	case pg.ResponseActionQuarantineFile:
		return pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE
	case pg.ResponseActionIsolateHost:
		return pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST
	case pg.ResponseActionUnisolateHost:
		return pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST
	case pg.ResponseActionCollectArtifacts:
		return pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS
	}
	return pb.ResponseAction_RESPONSE_ACTION_UNSPECIFIED
}
