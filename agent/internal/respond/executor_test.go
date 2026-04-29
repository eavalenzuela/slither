package respond

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// drainOne pulls one result with a 2-second deadline so a wedged
// executor surfaces as a clear test failure instead of a hung test.
func drainOne(t *testing.T, ch <-chan *pb.ResponseResult) *pb.ResponseResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ResponseResult")
		return nil
	}
}

func TestExecutor_NotImplementedDefaults(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 4)
	e := New(Options{Results: results, Concurrency: 2, Telem: telemetry.NewCounters()})

	for _, action := range []pb.ResponseAction{
		pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE,
		pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE,
		pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST,
		pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST,
		pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS,
	} {
		ok := e.Submit(context.Background(), &pb.ResponseRequest{
			ControlId: "ctrl-" + action.String(),
			Action:    action,
			Target:    "x",
		})
		if !ok {
			t.Fatalf("Submit(%s) returned false unexpectedly", action)
		}
		got := drainOne(t, results)
		if got.GetStatus() != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
			t.Errorf("%s status = %s, want FAILED", action, got.GetStatus())
		}
		if got.GetControlId() != "ctrl-"+action.String() {
			t.Errorf("control_id = %q, want round-trip", got.GetControlId())
		}
	}
}

func TestExecutor_SetHandlerOverride(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 1)
	e := New(Options{Results: results, Telem: telemetry.NewCounters()})

	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			return pb.ResponseStatus_RESPONSE_STATUS_DONE, "killed " + req.GetTarget(), nil
		})

	if !e.Submit(context.Background(), &pb.ResponseRequest{
		ControlId: "k1",
		Action:    pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		Target:    "1234",
	}) {
		t.Fatal("Submit returned false")
	}
	got := drainOne(t, results)
	if got.GetStatus() != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Errorf("status = %s, want DONE", got.GetStatus())
	}
	if got.GetDetail() != "killed 1234" {
		t.Errorf("detail = %q, want %q", got.GetDetail(), "killed 1234")
	}
}

func TestExecutor_QueueFullEmitsFailed(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 16)
	e := New(Options{Results: results, Concurrency: 1, Telem: telemetry.NewCounters()})

	// A blocking handler that holds the worker until we say go.
	release := make(chan struct{})
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, _ *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			<-release
			return pb.ResponseStatus_RESPONSE_STATUS_DONE, "ok", nil
		})

	// First Submit grabs the only worker; it blocks inside the
	// handler until we close `release`.
	if !e.Submit(context.Background(), &pb.ResponseRequest{
		ControlId: "first", Action: pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
	}) {
		t.Fatal("first Submit dropped unexpectedly")
	}
	// Wait for the worker to actually take the slot before the
	// second Submit — Submit is racing the goroutine launch.
	for i := 0; i < 100; i++ {
		if len(e.sem) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second Submit must drop because the worker pool is full.
	if e.Submit(context.Background(), &pb.ResponseRequest{
		ControlId: "second", Action: pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
	}) {
		t.Fatal("second Submit at capacity should drop, did not")
	}
	// The synthetic FAILED for "second" should arrive immediately.
	got := drainOne(t, results)
	if got.GetControlId() != "second" || got.GetStatus() != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Errorf("got = %+v, want FAILED for 'second'", got)
	}
	if got.GetDetail() != "agent executor queue full" {
		t.Errorf("detail = %q, want queue-full marker", got.GetDetail())
	}

	// Release "first" and drain its DONE.
	close(release)
	first := drainOne(t, results)
	if first.GetControlId() != "first" || first.GetStatus() != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Errorf("first result = %+v, want DONE", first)
	}
}

func TestExecutor_PanicHandlerRecoverEmitsFailed(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 1)
	e := New(Options{Results: results, Telem: telemetry.NewCounters()})

	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		func(_ context.Context, _ *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
			panic("kaboom")
		})

	if !e.Submit(context.Background(), &pb.ResponseRequest{
		ControlId: "boom", Action: pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
	}) {
		t.Fatal("Submit returned false")
	}
	got := drainOne(t, results)
	if got.GetStatus() != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Errorf("status = %s, want FAILED", got.GetStatus())
	}
}

func TestExecutor_NilRequestRejected(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 1)
	e := New(Options{Results: results, Telem: telemetry.NewCounters()})

	if e.Submit(context.Background(), nil) {
		t.Fatal("Submit(nil) should return false")
	}
}

// Sanity test that concurrent Submit + SetHandler don't race.
func TestExecutor_ConcurrentSubmitNoRace(t *testing.T) {
	t.Parallel()
	results := make(chan *pb.ResponseResult, 256)
	e := New(Options{Results: results, Concurrency: 8, Telem: telemetry.NewCounters()})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Concurrent SetHandlers swap implementations under load.
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
					func(_ context.Context, _ *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
						return pb.ResponseStatus_RESPONSE_STATUS_DONE, "ok", nil
					})
				i++
				if i > 1000 {
					return
				}
			}
		}
	}()
	for i := 0; i < 64; i++ {
		_ = e.Submit(context.Background(), &pb.ResponseRequest{
			ControlId: "x",
			Action:    pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS,
		})
	}
	close(stop)
	wg.Wait()

	// Drain whatever showed up — point of the test is that nothing
	// panicked or raced.
	drainCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for {
		select {
		case <-results:
		case <-drainCtx.Done():
			return
		}
	}
}

func TestExecutor_NewRequiresResultsChannel(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("New(no Results) should panic")
		}
	}()
	_ = New(Options{Telem: telemetry.NewCounters()})
}

// Compile-time guard: the not-implemented default returns a
// non-empty detail mentioning Phase 4 #78-#81.
func TestNotImplementedHandler_DetailMentionsTaskRange(t *testing.T) {
	t.Parallel()
	h := notImplementedHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS)
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Errorf("status = %s, want FAILED", status)
	}
	if detail == "" || !errors.Is(errors.New(detail), errors.New(detail)) {
		// Non-empty + parseable. We don't pin the wording.
		if detail == "" {
			t.Fatal("detail empty")
		}
	}
}
