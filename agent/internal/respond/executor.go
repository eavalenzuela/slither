// Package respond is the Phase 4 #77 agent-side response executor.
//
// The Executor sits between the gRPC sink (which receives
// ServerMessage_ResponseRequest from the server) and the per-action
// handlers that actually do the kill / quarantine / isolate / collect
// work. Per-action handlers (#78-#81) hang off the executor as plain
// functions so they parallel-land cleanly once this scaffold is in
// place.
//
// Concurrency:
//
//   - Submit() is non-blocking. The executor maintains a worker pool
//     (default 4) that runs Handle in goroutines.
//   - When the worker pool is saturated, Submit returns false +
//     emits a synthetic FAILED ResponseResult on the result channel
//     so the server-side dispatcher's state machine still moves the
//     row off `running` even when the agent's executor is wedged.
//
// Result channel ownership: the sink owns the channel; Submit just
// pushes onto it. Executor never closes the channel — that's the
// sink's call when the Session tears down.
package respond

import (
	"context"
	"fmt"
	"sync"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Handler is the per-action implementation. ctx is bounded by the
// ResponseRequest's deadline (or a default if zero); req carries the
// target + action enum the handler dispatches on. Handler returns the
// terminal status + a human-readable detail + an optional result
// blob (COLLECT_ARTIFACTS uses this; everything else leaves it nil).
//
// A handler that hits an unrecoverable bug should still return —
// returning RESPONSE_STATUS_FAILED with a meaningful detail beats
// panicking the executor goroutine.
type Handler func(ctx context.Context, req *pb.ResponseRequest) (status pb.ResponseStatus, detail string, blob []byte)

// Executor dispatches ResponseRequests to per-action handlers. Safe
// for concurrent Submit + SetHandler callers.
type Executor struct {
	mu       sync.RWMutex
	handlers map[pb.ResponseAction]Handler

	results chan<- *pb.ResponseResult
	telem   *telemetry.Counters
	chain   ChainAppender

	// sem caps in-flight handlers; Submit returns false when full.
	// Capacity matches Options.Concurrency and is set at construction
	// time.
	sem chan struct{}
}

// Options configures Executor.
type Options struct {
	// Results is the outbound channel the sink reads from. Required.
	Results chan<- *pb.ResponseResult
	// Concurrency caps in-flight handlers. <= 0 falls back to 4.
	Concurrency int
	// Telem may be nil; gets a fresh counters value when zero.
	Telem *telemetry.Counters
	// AuditChain, when non-nil, receives one record per terminal
	// ResponseResult. Phase 5 #95 — local tamper-evidence trail.
	// Append errors are logged via the package's slog facade rather
	// than tearing down the executor; the chain is best-effort
	// alongside the live audit_log on the server.
	AuditChain ChainAppender
}

// ChainAppender is the executor's view of selfprotect.ChainWriter.
// Decoupled here so the package can stay test-friendly (a stub
// counter satisfies the interface) and so a future remote-chain
// implementation can plug in without touching this package.
type ChainAppender interface {
	Append(kind string, summary any) error
}

// New constructs an Executor with the per-action surface ADR-0034
// freezes, all initially mapped to a "not implemented" handler. Tasks
// #78-#81 SetHandler their real implementations on top.
func New(opts Options) *Executor {
	if opts.Results == nil {
		panic("respond.New: Results channel required")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Telem == nil {
		opts.Telem = telemetry.NewCounters()
	}
	e := &Executor{
		handlers: make(map[pb.ResponseAction]Handler),
		results:  opts.Results,
		telem:    opts.Telem,
		chain:    opts.AuditChain,
		sem:      make(chan struct{}, opts.Concurrency),
	}
	// Default every action to a clearly-failing handler so an early
	// rollout (executor wired but #78-#81 still landing) at least
	// completes the wire round-trip and surfaces a useful error in
	// the audit chain.
	for _, a := range []pb.ResponseAction{
		pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE,
		pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE,
		pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST,
		pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST,
		pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS,
	} {
		e.handlers[a] = notImplementedHandler(a)
	}
	return e
}

// SetHandler installs a per-action handler. Phase 4 #78-#81 use this
// to replace the default not-implemented handlers with the real
// implementations.
func (e *Executor) SetHandler(action pb.ResponseAction, h Handler) {
	if h == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[action] = h
}

// Submit hands one ResponseRequest off to a worker. Non-blocking;
// returns false when the worker pool is saturated (in which case it
// also emits a synthetic FAILED ResponseResult so the server-side
// row state machine still progresses).
//
// Caller is the gRPC sink's Recv goroutine — Submit must not block
// the receive loop.
func (e *Executor) Submit(ctx context.Context, req *pb.ResponseRequest) bool {
	if req == nil {
		return false
	}
	select {
	case e.sem <- struct{}{}:
	default:
		// Pool full — emit a synthetic FAILED result so the
		// server's response_actions row doesn't sit in `running`
		// forever waiting on this agent.
		e.emit(&pb.ResponseResult{
			ControlId: req.GetControlId(),
			Status:    pb.ResponseStatus_RESPONSE_STATUS_FAILED,
			Detail:    "agent executor queue full",
		})
		e.telem.IncResponseExecQueueFull()
		return false
	}

	go func() {
		defer func() { <-e.sem }()
		e.handle(ctx, req)
	}()
	return true
}

// handle runs the per-action handler with a recover guard so a panic
// in any handler still emits a FAILED result rather than tearing down
// the executor goroutine.
func (e *Executor) handle(ctx context.Context, req *pb.ResponseRequest) {
	defer func() {
		if r := recover(); r != nil {
			e.emit(&pb.ResponseResult{
				ControlId: req.GetControlId(),
				Status:    pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				Detail:    fmt.Sprintf("agent handler panic: %v", r),
			})
			e.telem.IncResponseExecPanic()
		}
	}()

	action := req.GetAction()
	e.mu.RLock()
	h, ok := e.handlers[action]
	e.mu.RUnlock()
	if !ok || h == nil {
		e.emit(&pb.ResponseResult{
			ControlId: req.GetControlId(),
			Status:    pb.ResponseStatus_RESPONSE_STATUS_FAILED,
			Detail:    fmt.Sprintf("no handler for action %s", action.String()),
		})
		return
	}

	status, detail, blob := h(ctx, req)
	switch status {
	case pb.ResponseStatus_RESPONSE_STATUS_DONE:
		e.telem.IncResponseExecDone()
	case pb.ResponseStatus_RESPONSE_STATUS_FAILED:
		e.telem.IncResponseExecFailed()
	}
	// Phase 5 #95 — append a tamper-evident audit row for this
	// terminal transition. Best-effort: chain append errors don't
	// surface to the caller. result_blob is excluded from the chain
	// summary to keep the chain file size bounded — operators have
	// the full blob in the server's response_actions.result_blob
	// column.
	//
	// Order matters: chain.Append runs before emit so a consumer that
	// has received the result on `e.results` is guaranteed the audit
	// row is already written. The previous order let a fast consumer
	// observe the result and inspect the chain before this goroutine
	// got to Append, producing flaky tests / ordering surprises.
	if e.chain != nil {
		_ = e.chain.Append("response_action", map[string]any{
			"control_id": req.GetControlId(),
			"rule_uid":   req.GetRuleUid(),
			"action":     req.GetAction().String(),
			"target":     req.GetTarget(),
			"status":     status.String(),
			"detail":     truncateChainDetail(detail),
		})
	}
	// Phase 4 #83/#86: rule_uid + action + target stamps on the result
	// let the server's OnResult insert a response_actions row for
	// agent-initiated actions whose control_id it has never seen.
	// The fields are echoed for server-initiated actions too — pg's
	// row already carries them, so duplicates are harmless.
	e.emit(&pb.ResponseResult{
		ControlId:  req.GetControlId(),
		Status:     status,
		Detail:     detail,
		ResultBlob: blob,
		RuleUid:    req.GetRuleUid(),
		Action:     req.GetAction(),
		Target:     req.GetTarget(),
	})
}

// truncateChainDetail caps a detail string at 256 bytes so a
// pathological handler returning a kilobyte of stack trace doesn't
// bloat the chain file. Callers wanting full detail consult the
// server-side audit_log row.
func truncateChainDetail(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max] + "…[truncated]"
}

// emit pushes a result onto the outbound channel without blocking.
// A wedged sink would otherwise stall every handler goroutine; the
// counter bump on drop surfaces the symptom in the agent's
// telemetry stderr line.
func (e *Executor) emit(r *pb.ResponseResult) {
	select {
	case e.results <- r:
	default:
		e.telem.IncResponseExecResultDropped()
	}
}

// EmitSnapshotResult is the Phase 6 #111 fast path for the
// AutoResponder's snapshot fanout. The reassembled tarball is already
// in hand by the time the responder calls in, so the regular handler
// dispatch (which would re-tar /var/lib/slither) would be wrong.
// EmitSnapshotResult synthesises the ResponseResult directly,
// preserving the executor's audit-chain + telemetry contract while
// short-circuiting the tar handler.
//
// The req's SnapshotAlertId + SnapshotExtensionName ride through to
// the result so the server's persistArtefact lands the blob under
// <artefactDir>/<alert_id>/<extension_name>.tgz. RuleUid + Action +
// Target are echoed exactly like the standard handler path so OnResult
// inserts a response_actions row identically.
func (e *Executor) EmitSnapshotResult(req *pb.ResponseRequest, blob []byte) {
	if req == nil {
		return
	}
	status := pb.ResponseStatus_RESPONSE_STATUS_DONE
	detail := fmt.Sprintf("snapshot from extension %q (%d bytes)",
		req.GetSnapshotExtensionName(), len(blob))
	e.telem.IncResponseExecDone()
	// Same ordering invariant as runHandler: chain.Append before emit so
	// a consumer that has received the result is guaranteed the audit
	// row is already written.
	if e.chain != nil {
		_ = e.chain.Append("response_action", map[string]any{
			"control_id":     req.GetControlId(),
			"rule_uid":       req.GetRuleUid(),
			"action":         req.GetAction().String(),
			"target":         req.GetTarget(),
			"status":         status.String(),
			"detail":         truncateChainDetail(detail),
			"snapshot_alert": req.GetSnapshotAlertId(),
			"snapshot_ext":   req.GetSnapshotExtensionName(),
		})
	}
	e.emit(&pb.ResponseResult{
		ControlId:             req.GetControlId(),
		Status:                status,
		Detail:                detail,
		ResultBlob:            blob,
		RuleUid:               req.GetRuleUid(),
		Action:                req.GetAction(),
		Target:                req.GetTarget(),
		SnapshotAlertId:       req.GetSnapshotAlertId(),
		SnapshotExtensionName: req.GetSnapshotExtensionName(),
	})
}

// notImplementedHandler returns a handler that fails cleanly with a
// useful detail. Used as the default for every action class; #78-#81
// replace these via SetHandler.
func notImplementedHandler(a pb.ResponseAction) Handler {
	return func(_ context.Context, _ *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
			fmt.Sprintf("action %s not implemented (Phase 4 #78-#81 pending)", a.String()),
			nil
	}
}
