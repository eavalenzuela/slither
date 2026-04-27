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
	dropsOutput      atomic.Uint64
	outputReconnects atomic.Uint64
	heartbeatsSent   atomic.Uint64
	detectionsFired  atomic.Uint64
	ringbufOverflows atomic.Uint64
	stateEvicted     atomic.Uint64
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

// IncDropOutput — the grpc sink's outbound buffer was full and dropped
// the oldest pending event to make room. Only the grpc sink uses this;
// stdout is write-or-block.
func (c *Counters) IncDropOutput() {
	c.eventsDropped.Add(1)
	c.dropsOutput.Add(1)
}

// IncOutputReconnect — the grpc sink's Session stream closed and the
// sink reopened it. Useful for operators watching for network flaps.
func (c *Counters) IncOutputReconnect() { c.outputReconnects.Add(1) }

// IncHeartbeatSent — the grpc sink sent one Heartbeat ClientMessage.
func (c *Counters) IncHeartbeatSent() { c.heartbeatsSent.Add(1) }

// IncDetections bumps the detections-fired counter.
func (c *Counters) IncDetections() { c.detectionsFired.Add(1) }

// IncRingOverflows bumps the ringbuffer-overflow counter.
func (c *Counters) IncRingOverflows() { c.ringbufOverflows.Add(1) }

// IncStateEvicted bumps the per-rule bounded-state eviction counter.
// Phase 3 #56 — fires once per by-key dropped from a stateful rule's
// ring when a new key would push over ADR-0018's 1024-keys-per-rule
// cap. Operators reading the DiagReport line see this stay near zero
// for healthy rules; sustained growth signals either a too-tight cap
// or a misbehaving by-tuple choice.
func (c *Counters) IncStateEvicted() { c.stateEvicted.Add(1) }

// Snapshot captures the current counter values.
type Snapshot struct {
	EventsProduced   uint64
	EventsDropped    uint64
	DropsCollector   uint64
	DropsDispatch    uint64
	DropsEnricher    uint64
	DropsEngine      uint64
	DropsOutput      uint64
	OutputReconnects uint64
	HeartbeatsSent   uint64
	DetectionsFired  uint64
	RingbufOverflows uint64
	StateEvicted     uint64
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
		DropsOutput:      c.dropsOutput.Load(),
		OutputReconnects: c.outputReconnects.Load(),
		HeartbeatsSent:   c.heartbeatsSent.Load(),
		DetectionsFired:  c.detectionsFired.Load(),
		RingbufOverflows: c.ringbufOverflows.Load(),
		StateEvicted:     c.stateEvicted.Load(),
	}
}
