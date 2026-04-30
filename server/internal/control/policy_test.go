package control

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// stubPolicySource is a hand-driven PolicySource for unit tests.
type stubPolicySource struct {
	mu   sync.Mutex
	rows []pg.HostPolicy
	err  error
}

func (s *stubPolicySource) ListHostPolicies(_ context.Context) ([]pg.HostPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	out := make([]pg.HostPolicy, len(s.rows))
	copy(out, s.rows)
	return out, nil
}

func (s *stubPolicySource) set(rows []pg.HostPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = rows
}

func TestPolicyHub_SubscribeDeliversBaselineWhenNoRows(t *testing.T) {
	t.Parallel()
	src := &stubPolicySource{}
	h := NewPolicyHub(src, nil)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	ch, unsub := h.Subscribe("host-1")
	defer unsub()

	select {
	case p := <-ch:
		if p == nil {
			t.Fatal("baseline policy = nil")
		}
		if p.GetAllowKillProcess() || p.GetAllowKillTree() ||
			p.GetAllowQuarantine() || p.GetAllowIsolate() || p.GetAllowCollect() {
			t.Errorf("baseline should be all-false, got %+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("Subscribe didn't deliver baseline within 1s")
	}
}

func TestPolicyHub_RefreshFanoutDeliversLatest(t *testing.T) {
	t.Parallel()
	src := &stubPolicySource{
		rows: []pg.HostPolicy{
			{HostID: "host-1", AllowKillProcess: true},
		},
	}
	h := NewPolicyHub(src, nil)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	ch, unsub := h.Subscribe("host-1")
	defer unsub()

	// Drain the synchronous-on-subscribe value.
	first := drainPolicy(t, ch)
	if !first.GetAllowKillProcess() {
		t.Errorf("initial = %+v, want kill enabled", first)
	}

	// Operator flips kill off, quarantine on.
	src.set([]pg.HostPolicy{
		{HostID: "host-1", AllowQuarantine: true},
	})
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	second := drainPolicy(t, ch)
	if second.GetAllowKillProcess() {
		t.Errorf("post-update kill = true, want false")
	}
	if !second.GetAllowQuarantine() {
		t.Errorf("post-update quarantine = false, want true")
	}
	if second.GetVersion() == first.GetVersion() {
		t.Errorf("version unchanged across refresh: %q", second.GetVersion())
	}
}

func TestPolicyHub_DropStaleOnSlowSubscriber(t *testing.T) {
	t.Parallel()
	src := &stubPolicySource{
		rows: []pg.HostPolicy{{HostID: "host-1", AllowKillProcess: true}},
	}
	h := NewPolicyHub(src, nil)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	ch, unsub := h.Subscribe("host-1")
	defer unsub()
	// Don't drain — let the channel back up. Multiple Refreshes should
	// not block; the subscriber should eventually see the latest.
	for i := 0; i < 5; i++ {
		src.set([]pg.HostPolicy{{HostID: "host-1", AllowQuarantine: i == 4}})
		if err := h.Refresh(context.Background()); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
	}
	// Drain everything; the most recent value should be visible.
	var last *pb.HostPolicy
	deadline := time.After(time.Second)
loop:
	for {
		select {
		case p := <-ch:
			last = p
		case <-deadline:
			break loop
		case <-time.After(100 * time.Millisecond):
			break loop
		}
	}
	if last == nil {
		t.Fatal("subscriber received no policies")
	}
	if !last.GetAllowQuarantine() {
		t.Errorf("subscriber latest = %+v, want quarantine=true", last)
	}
}

func TestPolicyHub_DuplicateSubscribeClosesPrevious(t *testing.T) {
	t.Parallel()
	src := &stubPolicySource{}
	h := NewPolicyHub(src, nil)
	if err := h.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	first, _ := h.Subscribe("host-1")
	// Drain initial.
	drainPolicy(t, first)
	second, unsub2 := h.Subscribe("host-1")
	defer unsub2()
	select {
	case _, ok := <-first:
		if ok {
			t.Error("first channel still open after duplicate subscribe")
		}
	case <-time.After(time.Second):
		t.Error("first channel not closed after duplicate subscribe")
	}
	// Second subscriber should receive baseline immediately.
	if drainPolicy(t, second) == nil {
		t.Error("second subscriber missed baseline delivery")
	}
}

func drainPolicy(t *testing.T, ch <-chan *pb.HostPolicy) *pb.HostPolicy {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for policy")
		return nil
	}
}
