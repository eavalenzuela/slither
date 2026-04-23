// Package telemetry holds the agent's internal self-metrics.
//
// Phase 1 scope: counters for events-produced, events-dropped, detection-fired,
// and ringbuffer-occupancy samples. No external exporter in Phase 1 — values
// are dumped into a DiagReport-shaped log line on shutdown (exit-criterion #3).
package telemetry

import "sync/atomic"

// Counters aggregates agent-wide metrics. All methods are safe for concurrent use.
//
// Drops are split per-stage so load-test output identifies exactly which
// backpressure boundary is saturating; the public IncDrops still exists as a
// generic fallback and is folded into EventsDropped in the Snapshot.
type Counters struct {
	eventsProduced   atomic.Uint64
	eventsDropped    atomic.Uint64
	dropsCollector   atomic.Uint64
	dropsDispatch    atomic.Uint64
	dropsEnricher    atomic.Uint64
	dropsEngine      atomic.Uint64
	detectionsFired  atomic.Uint64
	ringbufOverflows atomic.Uint64
}

// NewCounters returns a zero-valued Counters.
func NewCounters() *Counters { return &Counters{} }

// IncEvents bumps the events-produced counter.
func (c *Counters) IncEvents() { c.eventsProduced.Add(1) }

// IncDrops bumps the generic events-dropped counter. Callers should prefer a
// stage-specific method (IncDropCollector, IncDropDispatch, IncDropEnricher,
// IncDropEngine) so the DiagReport can attribute drops.
func (c *Counters) IncDrops() { c.eventsDropped.Add(1) }

// IncDropCollector — collector ringbuf-drain to stage-input channel was full.
func (c *Counters) IncDropCollector() {
	c.eventsDropped.Add(1)
	c.dropsCollector.Add(1)
}

// IncDropDispatch — enricher's pid-sharded dispatcher found a worker inbox
// full; the offending event never reached /proc backfill.
func (c *Counters) IncDropDispatch() {
	c.eventsDropped.Add(1)
	c.dropsDispatch.Add(1)
}

// IncDropEnricher — enricher worker's non-blocking emit to the rule engine
// input was full (downstream slow).
func (c *Counters) IncDropEnricher() {
	c.eventsDropped.Add(1)
	c.dropsEnricher.Add(1)
}

// IncDropEngine — rule engine's non-blocking emit to the output sink was
// full. Detection-priority sends never take this path.
func (c *Counters) IncDropEngine() {
	c.eventsDropped.Add(1)
	c.dropsEngine.Add(1)
}

// IncDetections bumps the detections-fired counter.
func (c *Counters) IncDetections() { c.detectionsFired.Add(1) }

// IncRingOverflows bumps the ringbuffer-overflow counter.
func (c *Counters) IncRingOverflows() { c.ringbufOverflows.Add(1) }

// Snapshot captures the current counter values.
type Snapshot struct {
	EventsProduced   uint64
	EventsDropped    uint64
	DropsCollector   uint64
	DropsDispatch    uint64
	DropsEnricher    uint64
	DropsEngine      uint64
	DetectionsFired  uint64
	RingbufOverflows uint64
}

// Snapshot returns a point-in-time view of the counters.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		EventsProduced:   c.eventsProduced.Load(),
		EventsDropped:    c.eventsDropped.Load(),
		DropsCollector:   c.dropsCollector.Load(),
		DropsDispatch:    c.dropsDispatch.Load(),
		DropsEnricher:    c.dropsEnricher.Load(),
		DropsEngine:      c.dropsEngine.Load(),
		DetectionsFired:  c.detectionsFired.Load(),
		RingbufOverflows: c.ringbufOverflows.Load(),
	}
}
