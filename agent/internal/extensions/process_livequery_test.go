//go:build linux

package extensions

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// TestProcess_DispatchLiveQuery_RoutesRowsAndComplete spins up a stub
// extension that, on receiving a LiveQueryRequest, replies with two
// LiveQueryRow envelopes and one LiveQueryComplete. The test asserts
// the supervisor's DispatchLiveQuery channel sees all three in order.
func TestProcess_DispatchLiveQuery_RoutesRowsAndComplete(t *testing.T) {
	bin := stubLiveQueryBinary(t)
	cfg := liveQueryConfig(bin)
	telem := newCountersForTest()
	out := newOcsfChan()
	device := testDevice()

	p := NewProcess(cfg, DisabledVerifier{}, device, telem, out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start the cycle in a goroutine; it's a long-running supervisor.
	cycleDone := make(chan error, 1)
	go func() { cycleDone <- p.runOnce(ctx) }()

	// Wait until the supervisor has wired sendCh by polling.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		ready := p.sendCh != nil && p.HasCapability(pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND)
		p.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	resCh, err := p.DispatchLiveQuery(ctx, &pb.LiveQueryRequest{
		QueryId: "q1",
		Sql:     "SELECT 1",
		MaxRows: 100,
	})
	if err != nil {
		t.Fatalf("DispatchLiveQuery: %v", err)
	}

	rowCount := 0
	gotComplete := false
	timer := time.NewTimer(3 * time.Second)
	for !gotComplete {
		select {
		case env, ok := <-resCh:
			if !ok {
				t.Fatal("result channel closed without complete")
			}
			switch env.Payload.(type) {
			case *pb.ExtensionToAgent_LiveQueryRow:
				rowCount++
			case *pb.ExtensionToAgent_LiveQueryComplete:
				gotComplete = true
			}
		case <-timer.C:
			t.Fatal("timeout waiting for live-query reply")
		}
	}
	if rowCount != 2 {
		t.Errorf("row count = %d, want 2", rowCount)
	}

	cancel()
	select {
	case <-cycleDone:
	case <-time.After(2 * time.Second):
		t.Error("runOnce did not exit after ctx cancel")
	}
}

func TestProcess_DispatchLiveQuery_PreHelloFails(t *testing.T) {
	cfg := liveQueryConfig("")
	telem := newCountersForTest()
	p := NewProcess(cfg, DisabledVerifier{}, testDevice(), telem, newOcsfChan())
	_, err := p.DispatchLiveQuery(context.Background(), &pb.LiveQueryRequest{QueryId: "q"})
	if !errors.Is(err, ErrCapabilityViolation) && !errors.Is(err, ErrExtensionUnavailable) {
		t.Errorf("expected ErrCapabilityViolation or ErrExtensionUnavailable, got %v", err)
	}
}
