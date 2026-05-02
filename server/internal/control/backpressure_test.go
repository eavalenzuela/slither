package control

import (
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestBackpressureHub_SubscribePreloadsCurrent(t *testing.T) {
	t.Parallel()
	h := NewBackpressureHub()
	h.Set(pb.BackpressureSignal_LEVEL_ELEVATED, 0.1)

	updates, unsub := h.Subscribe("session-A")
	defer unsub()

	select {
	case sig := <-updates:
		if sig.GetLevel() != pb.BackpressureSignal_LEVEL_ELEVATED {
			t.Errorf("preload level = %v, want ELEVATED", sig.GetLevel())
		}
	default:
		t.Fatal("Subscribe didn't preload the current signal")
	}
}

func TestBackpressureHub_SetSkipsUnchanged(t *testing.T) {
	t.Parallel()
	h := NewBackpressureHub()
	updates, unsub := h.Subscribe("a")
	defer unsub()
	// Drain the preload (NORMAL/0).
	<-updates

	// Set NORMAL/0 again — should NOT broadcast.
	h.Set(pb.BackpressureSignal_LEVEL_NORMAL, 0)
	select {
	case <-updates:
		t.Error("identical Set broadcast a duplicate signal")
	default:
		// expected
	}

	// Set ELEVATED — broadcasts.
	h.Set(pb.BackpressureSignal_LEVEL_ELEVATED, 0.1)
	select {
	case sig := <-updates:
		if sig.GetLevel() != pb.BackpressureSignal_LEVEL_ELEVATED {
			t.Errorf("level = %v, want ELEVATED", sig.GetLevel())
		}
	default:
		t.Error("level change wasn't broadcast")
	}
}

func TestBackpressureHub_DropStaleOnFullChannel(t *testing.T) {
	t.Parallel()
	h := NewBackpressureHub()
	updates, unsub := h.Subscribe("a")
	defer unsub()
	<-updates // drain preload

	// Burst: 3 sets, channel cap is 1. Latest must win.
	h.Set(pb.BackpressureSignal_LEVEL_ELEVATED, 0.1)
	h.Set(pb.BackpressureSignal_LEVEL_CRITICAL, 0.5)
	h.Set(pb.BackpressureSignal_LEVEL_ELEVATED, 0.2)

	sig := <-updates
	if sig.GetLevel() != pb.BackpressureSignal_LEVEL_ELEVATED {
		t.Errorf("latest-wins: level = %v, want ELEVATED", sig.GetLevel())
	}
	if sig.GetObservedDropRate() != 0.2 {
		t.Errorf("rate = %v, want 0.2", sig.GetObservedDropRate())
	}
}

func TestBackpressureHub_UnsubscribeCleansUp(t *testing.T) {
	t.Parallel()
	h := NewBackpressureHub()
	_, unsub := h.Subscribe("a")
	unsub()

	h.mu.Lock()
	_, present := h.subscribers["a"]
	h.mu.Unlock()
	if present {
		t.Error("subscriber slot leaked after unsubscribe")
	}
}

type fakeProbe struct {
	events, drops uint64
}

func (f *fakeProbe) SnapshotForBackpressure() (uint64, uint64) {
	return f.events, f.drops
}

func TestClassifyServer_DefaultsAndBoundaries(t *testing.T) {
	t.Parallel()
	opts := BackpressureMonitorOptions{}
	// 1000 events, 0 drops → NORMAL.
	level, _ := classifyServer(0, 0, 0, 1000, opts)
	if level != pb.BackpressureSignal_LEVEL_NORMAL {
		t.Errorf("0 drops = %v, want NORMAL", level)
	}
	// 1000 events, 6 drops (0.6 %) → ELEVATED (default 0.5 %).
	level, _ = classifyServer(0, 0, 6, 1000, opts)
	if level != pb.BackpressureSignal_LEVEL_ELEVATED {
		t.Errorf("0.6 %% drops = %v, want ELEVATED", level)
	}
	// 1000 events, 60 drops (6 %) → CRITICAL.
	level, _ = classifyServer(0, 0, 60, 1000, opts)
	if level != pb.BackpressureSignal_LEVEL_CRITICAL {
		t.Errorf("6 %% drops = %v, want CRITICAL", level)
	}
	// No events flowed.
	level, _ = classifyServer(0, 1000, 0, 1000, opts)
	if level != pb.BackpressureSignal_LEVEL_NORMAL {
		t.Errorf("idle window = %v, want NORMAL", level)
	}
}
