package backpressure

import (
	"context"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// SelfWatchOptions tunes the agent-self-pressure poller. Zero values
// fall back to defaults that match Phase 5 #97 spec.
type SelfWatchOptions struct {
	// Cadence is how often the watcher samples telemetry. Defaults
	// to 10 s — a fresh sample every cadence, so a 30 s window
	// covers ~3 samples for the running drop_rate computation.
	Cadence time.Duration

	// ElevatedThreshold is the drop_rate fraction that triggers
	// LevelElevated. Default 0.05 (5 %).
	ElevatedThreshold float32

	// CriticalThreshold is the drop_rate fraction that triggers
	// LevelCritical. Default 0.20 (20 %).
	CriticalThreshold float32
}

func (o *SelfWatchOptions) withDefaults() {
	if o.Cadence <= 0 {
		o.Cadence = 10 * time.Second
	}
	if o.ElevatedThreshold <= 0 {
		o.ElevatedThreshold = 0.05
	}
	if o.CriticalThreshold <= 0 {
		o.CriticalThreshold = 0.20
	}
}

// RunSelfWatch polls telemetry every Cadence and updates cache's
// self-pressure level when the recent drop_rate crosses the
// configured thresholds. Blocks until ctx cancellation.
//
// The drop_rate is computed as a delta — events dropped between two
// adjacent samples ÷ events produced between those same samples.
// Cumulative ratios would smear bursty drops across hours of clean
// data; the running delta surfaces the current pressure shape.
//
// The watcher always SetSelfs (even at NORMAL) so a cleared signal
// decays the cache without waiting for the ttl path. ttl is the
// safety net for "watcher goroutine died"; SetSelf(NORMAL) is the
// fast path for "agent recovered".
func RunSelfWatch(ctx context.Context, cache *Cache, telem *telemetry.Counters, opts SelfWatchOptions) {
	opts.withDefaults()
	if cache == nil || telem == nil {
		return
	}
	t := time.NewTicker(opts.Cadence)
	defer t.Stop()

	prev := telem.Snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := telem.Snapshot()
			level, dropPct := classify(prev, cur, opts)
			cache.SetSelf(level, dropPct)
			prev = cur
		}
	}
}

// classify computes the running drop_rate between prev and cur and
// returns the corresponding Level + the observed fraction.
//
// Returns NORMAL when no events flowed in the window — an idle
// agent has no pressure regardless of any prior drops. Zero-valued
// thresholds in opts get the same defaults RunSelfWatch applies, so
// classify is callable in isolation by tests + ad-hoc consumers.
func classify(prev, cur telemetry.Snapshot, opts SelfWatchOptions) (level Level, fraction float32) {
	opts.withDefaults()
	dEvents := int64(cur.EventsProduced) - int64(prev.EventsProduced)
	dDrops := int64(cur.EventsDropped) - int64(prev.EventsDropped)
	if dEvents <= 0 {
		return LevelNormal, 0
	}
	frac := float32(dDrops) / float32(dEvents)
	switch {
	case frac >= opts.CriticalThreshold:
		return LevelCritical, frac
	case frac >= opts.ElevatedThreshold:
		return LevelElevated, frac
	}
	return LevelNormal, frac
}
