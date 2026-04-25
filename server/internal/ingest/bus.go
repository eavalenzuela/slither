// Package ingest owns the in-process event bus that fans out agent events
// to subscribers (ClickHouse writer in #38, live-tail SSE in #43, future
// detection engine).
//
// Phase 2 §4.1 task #37: Session handler in grpcserv pulls events off the
// stream and Publishes them onto the Bus; subscribers register a buffered
// channel via Subscribe. Backpressure is per-subscriber drop-newest: if a
// subscriber's channel is full Publish does not block; the slow consumer
// loses the event and the server-side telemetry counter records the drop.
// This keeps a stalled subscriber from stalling ingest for the others.
package ingest

import (
	"sync"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// DropFunc is invoked once per dropped envelope per slow subscriber.
// The default no-op is fine for tests; production passes
// telemetry.IncDropSubscriber so operator dashboards see the loss.
type DropFunc func(subscriber string)

// Bus is a fan-out hub. Publish is non-blocking; Subscribe returns a
// receive-only channel the caller drains. Bus is safe for concurrent
// use from many publishers and subscribers.
type Bus struct {
	mu     sync.RWMutex
	subs   map[string]chan *pb.Envelope
	dropFn map[string]func() // optional per-subscriber drop callback
	closed bool
	onDrop DropFunc
}

// NewBus returns an empty Bus. onDrop, when non-nil, is called every
// time a subscriber's channel was full at Publish time. Pass nil for
// tests; production wires telemetry.
func NewBus(onDrop DropFunc) *Bus {
	if onDrop == nil {
		onDrop = func(string) {}
	}
	return &Bus{
		subs:   make(map[string]chan *pb.Envelope),
		dropFn: make(map[string]func()),
		onDrop: onDrop,
	}
}

// SetDropObserver registers a per-subscriber callback fired in
// addition to the global onDrop whenever name's channel was full at
// Publish time. Used by the live-tail SSE handler so each connection
// surfaces its own drop count to its UI footer. Safe to call before
// or after Subscribe; cleared automatically by Unsubscribe.
func (b *Bus) SetDropObserver(name string, fn func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	if fn == nil {
		delete(b.dropFn, name)
		return
	}
	b.dropFn[name] = fn
}

// Subscribe registers a new subscriber under name with a buffered channel
// of the given capacity. Re-registering the same name replaces the prior
// subscription and closes the old channel — callers must observe close to
// stop their consumer goroutine cleanly.
func (b *Bus) Subscribe(name string, capacity int) <-chan *pb.Envelope {
	if capacity <= 0 {
		capacity = 1024
	}
	ch := make(chan *pb.Envelope, capacity)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		close(ch)
		return ch
	}
	if old, ok := b.subs[name]; ok {
		close(old)
	}
	b.subs[name] = ch
	return ch
}

// Unsubscribe removes name, closing its channel and dropping any
// drop-observer registered for it.
func (b *Bus) Unsubscribe(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[name]; ok {
		close(ch)
		delete(b.subs, name)
	}
	delete(b.dropFn, name)
}

// Publish fans env out to every subscriber. Drops on a full subscriber
// channel; the publisher is never blocked. Both the global onDrop and
// any per-subscriber observer fire on a drop.
func (b *Bus) Publish(env *pb.Envelope) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for name, ch := range b.subs {
		select {
		case ch <- env:
		default:
			b.onDrop(name)
			if fn := b.dropFn[name]; fn != nil {
				fn()
			}
		}
	}
}

// Close marks the bus closed and drops all subscriptions. Idempotent.
// After Close, Publish is a no-op and Subscribe returns a closed channel.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, ch := range b.subs {
		close(ch)
	}
	b.subs = nil
	b.dropFn = nil
}
