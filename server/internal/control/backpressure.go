// Phase 5 #97 — server-side backpressure hub. Owns the canonical
// pb.BackpressureSignal (one global level for the whole fleet — load
// affects every connected agent equally on a single-replica server)
// and fans it out to every Session's send loop.
//
// Why one global signal instead of per-host? The CH writer is the
// shared bottleneck. When it falls behind, every agent's events are
// equally affected; per-host dispatch would imply per-host
// contention, which doesn't reflect the actual constraint. Phase
// 6+ HA work may revisit this when there are multiple writer pods.

package control

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// BackpressureHub fans the current global signal out to every
// connected Session via per-subscriber capacity-1 channels with
// drop-stale-not-block semantics. Latest signal always wins.
type BackpressureHub struct {
	mu          sync.Mutex
	current     *pb.BackpressureSignal
	subscribers map[string]chan *pb.BackpressureSignal
}

// NewBackpressureHub returns an empty hub at LEVEL_NORMAL.
func NewBackpressureHub() *BackpressureHub {
	return &BackpressureHub{
		current: &pb.BackpressureSignal{
			Level:            pb.BackpressureSignal_LEVEL_NORMAL,
			ObservedDropRate: 0,
			Since:            timestamppb.Now(),
		},
		subscribers: make(map[string]chan *pb.BackpressureSignal),
	}
}

// Set updates the canonical signal and fans the new value to every
// subscriber. Called by the monitor goroutine in app.Run.
func (h *BackpressureHub) Set(level pb.BackpressureSignal_Level, dropRate float32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Skip the broadcast when nothing changed — collectors don't need
	// repeated NORMAL pings, and an unchanged ELEVATED at unchanged
	// drop rate is also a no-op for the agent's cache.
	if h.current != nil && h.current.GetLevel() == level &&
		h.current.GetObservedDropRate() == dropRate {
		return
	}
	h.current = &pb.BackpressureSignal{
		Level:            level,
		ObservedDropRate: dropRate,
		Since:            timestamppb.Now(),
	}
	for _, ch := range h.subscribers {
		h.publishOne(ch, h.current)
	}
}

// Subscribe registers a session for hub updates. The returned channel
// is pre-loaded with the current signal so a fresh session immediately
// sees the latest level. unsubscribe returns the slot.
func (h *BackpressureHub) Subscribe(name string) (updates <-chan *pb.BackpressureSignal, unsubscribe func()) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if existing, ok := h.subscribers[name]; ok {
		// Replace any prior channel under the same name so a session
		// reopen doesn't leak the old one.
		close(existing)
	}
	ch := make(chan *pb.BackpressureSignal, 1)
	h.subscribers[name] = ch
	if h.current != nil {
		h.publishOne(ch, h.current)
	}
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if got, ok := h.subscribers[name]; ok && got == ch {
			delete(h.subscribers, name)
			close(ch)
		}
	}
}

// Current returns the latest broadcast signal. Used by the monitor
// goroutine to compute hysteresis without re-deriving level from
// scratch on every poll.
func (h *BackpressureHub) Current() *pb.BackpressureSignal {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.current
}

// publishOne writes sig to ch, dropping a stale value if the channel
// is full. Caller must hold h.mu. Same drop-stale semantics as
// PolicyHub: latest wins, never blocks.
func (h *BackpressureHub) publishOne(ch chan *pb.BackpressureSignal, sig *pb.BackpressureSignal) {
	select {
	case ch <- sig:
	default:
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- sig:
		default:
		}
	}
}

// SnapshotProbe is the minimal surface BackpressureMonitor needs to
// observe the CH writer's drop pressure. *telemetry.Counters satisfies
// this via Snapshot; tests inject a stub. Returning the two counters
// every poll is cheap (atomic loads) — pre-aggregated rate windows
// belong in the monitor itself, not in telemetry.
type SnapshotProbe interface {
	SnapshotForBackpressure() (eventsReceived, dropsSubscriber uint64)
}

// BackpressureMonitorOptions tunes the polling cadence + thresholds.
// Zero values fall back to defaults that match Phase 5 #97 spec.
type BackpressureMonitorOptions struct {
	// Cadence is how often the monitor samples the writer.
	Cadence time.Duration
	// ElevatedThreshold is the drop_rate fraction that triggers
	// LEVEL_ELEVATED. Default 0.005 (0.5 % — server-side bar is
	// stricter than agent-side because the agent already sheds
	// some events to absorb spikes).
	ElevatedThreshold float32
	// CriticalThreshold triggers LEVEL_CRITICAL. Default 0.05 (5 %).
	CriticalThreshold float32
}

func (o *BackpressureMonitorOptions) withDefaults() {
	if o.Cadence <= 0 {
		o.Cadence = 10 * time.Second
	}
	if o.ElevatedThreshold <= 0 {
		o.ElevatedThreshold = 0.005
	}
	if o.CriticalThreshold <= 0 {
		o.CriticalThreshold = 0.05
	}
}

// RunBackpressureMonitor polls the CH writer's drop counter at opts.Cadence
// and updates hub when the rolling drop_rate crosses thresholds.
// Blocks until ctx cancellation.
func RunBackpressureMonitor(ctx context.Context, hub *BackpressureHub, probe SnapshotProbe, opts BackpressureMonitorOptions) {
	opts.withDefaults()
	if hub == nil || probe == nil {
		return
	}
	t := time.NewTicker(opts.Cadence)
	defer t.Stop()

	prevEvents, prevDrops := probe.SnapshotForBackpressure()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			curEvents, curDrops := probe.SnapshotForBackpressure()
			level, frac := classifyServer(prevDrops, prevEvents, curDrops, curEvents, opts)
			hub.Set(level, frac)
			prevDrops = curDrops
			prevEvents = curEvents
		}
	}
}

// classifyServer mirrors the agent-side classify but with
// server-tighter thresholds. Returns NORMAL when no events flowed.
func classifyServer(prevDrops, prevEvents, curDrops, curEvents uint64, opts BackpressureMonitorOptions) (level pb.BackpressureSignal_Level, dropFraction float32) {
	opts.withDefaults()
	dEvents := int64(curEvents) - int64(prevEvents)
	dDrops := int64(curDrops) - int64(prevDrops)
	if dEvents <= 0 {
		return pb.BackpressureSignal_LEVEL_NORMAL, 0
	}
	frac := float32(dDrops) / float32(dEvents)
	switch {
	case frac >= opts.CriticalThreshold:
		return pb.BackpressureSignal_LEVEL_CRITICAL, frac
	case frac >= opts.ElevatedThreshold:
		return pb.BackpressureSignal_LEVEL_ELEVATED, frac
	}
	return pb.BackpressureSignal_LEVEL_NORMAL, frac
}
