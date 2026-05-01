package console

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Phase 5 #96 — replay-bypass: live-tail SSE filters out events
// whose observed_at is older than replayBypassWindow. The CH writer
// downstream still sees them; this is a UX guard, not a security
// boundary.
func TestIsReplayEvent_OlderThanWindowReturnsTrue(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Minute)
	env := &pb.Envelope{ObservedAt: timestamppb.New(old)}
	if !isReplayEvent(env, now) {
		t.Error("event 2m old should be classified as replay")
	}
}

func TestIsReplayEvent_FreshEventReturnsFalse(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-5 * time.Second)
	env := &pb.Envelope{ObservedAt: timestamppb.New(fresh)}
	if isReplayEvent(env, now) {
		t.Error("event 5s old should NOT be classified as replay")
	}
}

func TestIsReplayEvent_EdgeOfWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	// Strictly greater-than: at the exact boundary, NOT replay.
	atBoundary := now.Add(-replayBypassWindow)
	env := &pb.Envelope{ObservedAt: timestamppb.New(atBoundary)}
	if isReplayEvent(env, now) {
		t.Error("event exactly at window edge should NOT be replay (strict >)")
	}
	pastBoundary := now.Add(-replayBypassWindow - time.Millisecond)
	env2 := &pb.Envelope{ObservedAt: timestamppb.New(pastBoundary)}
	if !isReplayEvent(env2, now) {
		t.Error("event 1ms past window edge should be replay")
	}
}

func TestIsReplayEvent_MissingObservedAtIsLive(t *testing.T) {
	t.Parallel()
	// No timestamp = treat as live, not replay. Better to over-show
	// on live-tail than silently swallow events that arrive without
	// a stamp (which would be a data-quality issue worth surfacing).
	env := &pb.Envelope{}
	if isReplayEvent(env, time.Now()) {
		t.Error("missing observed_at should NOT be classified as replay")
	}
}
