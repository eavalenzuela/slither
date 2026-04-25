package ingest

import (
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestBus_FanOut(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()

	a := b.Subscribe("a", 8)
	c := b.Subscribe("b", 8)

	for i := 0; i < 3; i++ {
		b.Publish(&pb.Envelope{EventId: "e"})
	}

	for i, ch := range []<-chan *pb.Envelope{a, c} {
		got := 0
		deadline := time.After(time.Second)
	loop:
		for got < 3 {
			select {
			case <-ch:
				got++
			case <-deadline:
				break loop
			}
		}
		if got != 3 {
			t.Errorf("subscriber %d got %d events, want 3", i, got)
		}
	}
}

func TestBus_DropOnFull(t *testing.T) {
	var drops atomic.Int64
	b := NewBus(func(string) { drops.Add(1) })
	defer b.Close()

	_ = b.Subscribe("slow", 1) // never drained

	for i := 0; i < 10; i++ {
		b.Publish(&pb.Envelope{})
	}
	if got := drops.Load(); got != 9 {
		t.Errorf("drops = %d, want 9", got)
	}
}

func TestBus_UnsubscribeClosesChannel(t *testing.T) {
	b := NewBus(nil)
	defer b.Close()
	ch := b.Subscribe("x", 1)
	b.Unsubscribe("x")
	if _, ok := <-ch; ok {
		t.Errorf("expected channel closed after Unsubscribe")
	}
}

func TestBus_CloseIsIdempotent(t *testing.T) {
	b := NewBus(nil)
	ch := b.Subscribe("y", 1)
	b.Close()
	b.Close()
	if _, ok := <-ch; ok {
		t.Errorf("expected channel closed after Close")
	}
	// Subscribe after Close returns a closed channel.
	c := b.Subscribe("z", 1)
	if _, ok := <-c; ok {
		t.Errorf("expected closed channel from Subscribe-after-Close")
	}
	// Publish after Close is a no-op (no panic, no goroutine leak).
	b.Publish(&pb.Envelope{})
}
