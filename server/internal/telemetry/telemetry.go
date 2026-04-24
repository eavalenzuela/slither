// Package telemetry holds server-side self-metrics.
//
// Phase 2 §4.1 task #31 scaffold: counters mirror the agent's split-attribution
// shape so operators see the same vocabulary on both sides of the wire. Real
// bumpers land with #37 ingest (events/drops), #38 ClickHouse writer
// (batches/flushes), and #39 control plane (rulesets pushed). #31 only wires
// the struct + final-snapshot DiagReport line.
package telemetry

import "sync/atomic"

// Counters aggregates server-wide metrics. Methods are safe for concurrent use.
type Counters struct {
	eventsReceived  atomic.Uint64
	eventsDropped   atomic.Uint64
	dropsIngest     atomic.Uint64
	dropsSubscriber atomic.Uint64
	batchesFlushed  atomic.Uint64
	rulesetsPushed  atomic.Uint64
	enrollSuccess   atomic.Uint64
	enrollRejected  atomic.Uint64
	sessionsActive  atomic.Int64
}

// NewCounters returns a zero-valued Counters.
func NewCounters() *Counters { return &Counters{} }

// IncEventsReceived bumps the ingest event counter.
func (c *Counters) IncEventsReceived() { c.eventsReceived.Add(1) }

// IncDropIngest — ingest Session read-loop couldn't fan out (bus full).
func (c *Counters) IncDropIngest() {
	c.eventsDropped.Add(1)
	c.dropsIngest.Add(1)
}

// IncDropSubscriber — a bus subscriber's queue was full; this subscriber
// missed the event but ingest did not stall.
func (c *Counters) IncDropSubscriber() {
	c.eventsDropped.Add(1)
	c.dropsSubscriber.Add(1)
}

// IncBatchesFlushed — ClickHouse writer flushed one batch.
func (c *Counters) IncBatchesFlushed() { c.batchesFlushed.Add(1) }

// IncRulesetsPushed — server pushed a RuleSet to one agent session.
func (c *Counters) IncRulesetsPushed() { c.rulesetsPushed.Add(1) }

// IncEnrollSuccess — Enroll RPC returned a signed cert.
func (c *Counters) IncEnrollSuccess() { c.enrollSuccess.Add(1) }

// IncEnrollRejected — Enroll RPC rejected (bad/expired/reused token, etc.).
func (c *Counters) IncEnrollRejected() { c.enrollRejected.Add(1) }

// SessionOpened / SessionClosed track in-flight agent Sessions.
func (c *Counters) SessionOpened() { c.sessionsActive.Add(1) }
func (c *Counters) SessionClosed() { c.sessionsActive.Add(-1) }

// Snapshot captures the current counter values.
type Snapshot struct {
	EventsReceived  uint64
	EventsDropped   uint64
	DropsIngest     uint64
	DropsSubscriber uint64
	BatchesFlushed  uint64
	RulesetsPushed  uint64
	EnrollSuccess   uint64
	EnrollRejected  uint64
	SessionsActive  int64
}

// Snapshot returns a point-in-time view of the counters.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		EventsReceived:  c.eventsReceived.Load(),
		EventsDropped:   c.eventsDropped.Load(),
		DropsIngest:     c.dropsIngest.Load(),
		DropsSubscriber: c.dropsSubscriber.Load(),
		BatchesFlushed:  c.batchesFlushed.Load(),
		RulesetsPushed:  c.rulesetsPushed.Load(),
		EnrollSuccess:   c.enrollSuccess.Load(),
		EnrollRejected:  c.enrollRejected.Load(),
		SessionsActive:  c.sessionsActive.Load(),
	}
}
