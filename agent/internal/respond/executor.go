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
	e.emit(&pb.ResponseResult{
		ControlId:  req.GetControlId(),
		Status:     status,
		Detail:     detail,
		ResultBlob: blob,
	})
	switch status {
	case pb.ResponseStatus_RESPONSE_STATUS_DONE:
		e.telem.IncResponseExecDone()
	case pb.ResponseStatus_RESPONSE_STATUS_FAILED:
		e.telem.IncResponseExecFailed()
	}
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
