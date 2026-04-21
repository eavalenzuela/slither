// Package telemetry holds the agent's internal self-metrics.
//
// Phase 1 scope: counters for events-produced, events-dropped, detection-fired,
// and ringbuffer-occupancy samples. No external exporter in Phase 1 — values
// are dumped into a DiagReport-shaped log line on shutdown (exit-criterion #3).
package telemetry

import "sync/atomic"

// Counters aggregates agent-wide metrics. All methods are safe for concurrent use.
type Counters struct {
	eventsProduced   atomic.Uint64
	eventsDropped    atomic.Uint64
	detectionsFired  atomic.Uint64
	ringbufOverflows atomic.Uint64
}

// NewCounters returns a zero-valued Counters.
func NewCounters() *Counters { return &Counters{} }

// IncEvents bumps the events-produced counter.
func (c *Counters) IncEvents() { c.eventsProduced.Add(1) }

// IncDrops bumps the events-dropped counter.
func (c *Counters) IncDrops() { c.eventsDropped.Add(1) }

// IncDetections bumps the detections-fired counter.
func (c *Counters) IncDetections() { c.detectionsFired.Add(1) }

// IncRingOverflows bumps the ringbuffer-overflow counter.
func (c *Counters) IncRingOverflows() { c.ringbufOverflows.Add(1) }

// Snapshot captures the current counter values.
type Snapshot struct {
	EventsProduced   uint64
	EventsDropped    uint64
	DetectionsFired  uint64
	RingbufOverflows uint64
}

// Snapshot returns a point-in-time view of the counters.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		EventsProduced:   c.eventsProduced.Load(),
		EventsDropped:    c.eventsDropped.Load(),
		DetectionsFired:  c.detectionsFired.Load(),
		RingbufOverflows: c.ringbufOverflows.Load(),
	}
}
