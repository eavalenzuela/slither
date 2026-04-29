// Package telemetry holds server-side self-metrics.
//
// Phase 2 §4.1 task #31 scaffold: counters mirror the agent's split-attribution
// shape so operators see the same vocabulary on both sides of the wire. Real
// bumpers land with #37 ingest (events/drops), #38 ClickHouse writer
// (batches/flushes), and #39 control plane (rulesets pushed). #31 only wires
// the struct + final-snapshot DiagReport line.
package telemetry

import (
	"sync"
	"sync/atomic"
)

// Counters aggregates server-wide metrics. Methods are safe for concurrent use.
type Counters struct {
	eventsReceived   atomic.Uint64
	eventsDropped    atomic.Uint64
	dropsIngest      atomic.Uint64
	dropsSubscriber  atomic.Uint64
	batchesFlushed   atomic.Uint64
	rulesetRefreshes atomic.Uint64
	rulesetsPushed   atomic.Uint64
	enrollSuccess    atomic.Uint64
	enrollRejected   atomic.Uint64
	sessionsActive   atomic.Int64
	sessionsClosed   atomic.Uint64
	heartbeats       atomic.Uint64
	authnFailures    atomic.Uint64

	// detect — Phase 3 #58 server detection engine. Events seen by the
	// engine, findings emitted, findings dropped because the alert
	// sink wasn't draining, and per-rule LRU window evictions when a
	// rule's group_key cardinality exceeds the configured cap.
	detectEvents          atomic.Uint64
	detectFindings        atomic.Uint64
	detectFindingsDropped atomic.Uint64
	detectStateEvicted    atomic.Uint64

	// alerts — Phase 3 #60 alert sink. Inserted is the count of
	// rows landed in alerts; deduped fires when a finding hit the
	// rules.dedupe_window_secs path; errored fires on a pg insert
	// failure (transient or hard-fail). Both detect.Findings and
	// the bus router (edge DetectionFindings) share these counters.
	alertsInserted atomic.Uint64
	alertsDeduped  atomic.Uint64
	alertsErrored  atomic.Uint64

	// response — Phase 4 #75 dispatcher. Dispatched bumps when the
	// dispatcher hands a ResponseRequest off to a session's send
	// channel; dropped bumps when the per-host queue is full and the
	// dispatch is dropped (operator-visible signal that an agent's
	// session is congested or absent). Completed bumps on every
	// terminal ResponseResult the agent emits.
	responseDispatched atomic.Uint64
	responseDropped    atomic.Uint64
	responseCompleted  atomic.Uint64

	// subscriberPublishes counts pushes per Session subscriber name
	// (e.g. "session:host-1"). Populated by IncSubscriberPublish on
	// every successful stream.Send of a RuleSet so operators can see
	// which agents are converging without hunting through Session
	// goroutines. sync.Map fits the read-heavy snapshot path; the
	// stored values are *atomic.Uint64 so per-key increments stay
	// lock-free.
	subscriberPublishes sync.Map
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

// IncRulesetRefreshes — control hub recompiled and fanned out a RuleSet
// snapshot. Bumped once per Refresh regardless of subscriber count.
func (c *Counters) IncRulesetRefreshes() { c.rulesetRefreshes.Add(1) }

// IncRulesetsPushed — server pushed a RuleSet to one agent session.
func (c *Counters) IncRulesetsPushed() { c.rulesetsPushed.Add(1) }

// IncSubscriberPublish bumps the per-subscriber publish counter for
// name. Names are arbitrary strings (the SessionService uses
// "session:<hostID>"); lazy-initialised on first observation.
func (c *Counters) IncSubscriberPublish(name string) {
	v, ok := c.subscriberPublishes.Load(name)
	if !ok {
		v, _ = c.subscriberPublishes.LoadOrStore(name, &atomic.Uint64{})
	}
	if counter, ok := v.(*atomic.Uint64); ok {
		counter.Add(1)
	}
}

// IncEnrollSuccess — Enroll RPC returned a signed cert.
func (c *Counters) IncEnrollSuccess() { c.enrollSuccess.Add(1) }

// IncEnrollRejected — Enroll RPC rejected (bad/expired/reused token, etc.).
func (c *Counters) IncEnrollRejected() { c.enrollRejected.Add(1) }

// SessionOpened / SessionClosed track in-flight agent Sessions.
func (c *Counters) SessionOpened() { c.sessionsActive.Add(1) }
func (c *Counters) SessionClosed() {
	c.sessionsActive.Add(-1)
	c.sessionsClosed.Add(1)
}

// IncHeartbeat — Session handler received and applied one Heartbeat.
func (c *Counters) IncHeartbeat() { c.heartbeats.Add(1) }

// IncAuthnFailure — Session refused a stream (missing peer cert,
// host_id parse error, host_id not in DB, ...).
func (c *Counters) IncAuthnFailure() { c.authnFailures.Add(1) }

// IncDetectEvents — server detection engine processed one envelope.
func (c *Counters) IncDetectEvents() { c.detectEvents.Add(1) }

// IncDetectFindings — engine fired one Finding (any plan, any rule).
func (c *Counters) IncDetectFindings() { c.detectFindings.Add(1) }

// IncDetectFindingsDropped — findings channel was full at fire time;
// the alert sink never saw this finding. Operator-visible signal that
// downstream alert handling can't keep up.
func (c *Counters) IncDetectFindingsDropped() { c.detectFindingsDropped.Add(1) }

// IncDetectStateEvicted — engine dropped one group key from a rule's
// bounded window because cardinality crossed the configured cap. Same
// vocabulary as the agent's StateEvicted (#56) so dashboards group on
// either side without a separate metric name.
func (c *Counters) IncDetectStateEvicted() { c.detectStateEvicted.Add(1) }

// IncAlertsInserted — alert sink (#60) landed one row in alerts.
// Both detect.Findings and the bus router (edge DetectionFindings)
// bump this counter so /alerts traffic is split-attributed.
func (c *Counters) IncAlertsInserted() { c.alertsInserted.Add(1) }

// IncAlertsDeduped — finding suppressed by rules.dedupe_window_secs.
// Operators reading the snapshot see how often dedupe is active.
func (c *Counters) IncAlertsDeduped() { c.alertsDeduped.Add(1) }

// IncAlertsErrored — pg insert failed. Sustained growth signals a pg
// outage or a malformed payload (rule_uid empty, host_id unparseable).
func (c *Counters) IncAlertsErrored() { c.alertsErrored.Add(1) }

// IncResponseDispatched — Phase 4 #75 dispatcher accepted one action
// onto a session's send channel.
func (c *Counters) IncResponseDispatched() { c.responseDispatched.Add(1) }

// IncResponseDropped — per-host send queue was full when the
// dispatcher tried to enqueue. The corresponding response_actions
// row stays in `pending` until either the agent reconnects (so the
// hub Subscribe replays the latest snapshot) or an operator manually
// re-dispatches.
func (c *Counters) IncResponseDropped() { c.responseDropped.Add(1) }

// IncResponseCompleted — agent emitted a terminal ResponseResult
// (DONE or FAILED). Sustained growth without a matching
// IncResponseDispatched signals stuck pending actions.
func (c *Counters) IncResponseCompleted() { c.responseCompleted.Add(1) }

// Snapshot captures the current counter values.
type Snapshot struct {
	EventsReceived        uint64
	EventsDropped         uint64
	DropsIngest           uint64
	DropsSubscriber       uint64
	BatchesFlushed        uint64
	RulesetRefreshes      uint64
	RulesetsPushed        uint64
	EnrollSuccess         uint64
	EnrollRejected        uint64
	SessionsActive        int64
	SessionsClosed        uint64
	Heartbeats            uint64
	AuthnFailures         uint64
	DetectEvents          uint64
	DetectFindings        uint64
	DetectFindingsDropped uint64
	DetectStateEvicted    uint64
	AlertsInserted        uint64
	AlertsDeduped         uint64
	AlertsErrored         uint64
	ResponseDispatched    uint64
	ResponseDropped       uint64
	ResponseCompleted     uint64
	SubscriberPublishes   map[string]uint64
}

// Snapshot returns a point-in-time view of the counters.
func (c *Counters) Snapshot() Snapshot {
	subs := make(map[string]uint64)
	c.subscriberPublishes.Range(func(k, v any) bool {
		name, nameOK := k.(string)
		counter, counterOK := v.(*atomic.Uint64)
		if nameOK && counterOK {
			subs[name] = counter.Load()
		}
		return true
	})
	return Snapshot{
		EventsReceived:        c.eventsReceived.Load(),
		EventsDropped:         c.eventsDropped.Load(),
		DropsIngest:           c.dropsIngest.Load(),
		DropsSubscriber:       c.dropsSubscriber.Load(),
		BatchesFlushed:        c.batchesFlushed.Load(),
		RulesetRefreshes:      c.rulesetRefreshes.Load(),
		RulesetsPushed:        c.rulesetsPushed.Load(),
		EnrollSuccess:         c.enrollSuccess.Load(),
		EnrollRejected:        c.enrollRejected.Load(),
		SessionsActive:        c.sessionsActive.Load(),
		SessionsClosed:        c.sessionsClosed.Load(),
		Heartbeats:            c.heartbeats.Load(),
		AuthnFailures:         c.authnFailures.Load(),
		DetectEvents:          c.detectEvents.Load(),
		DetectFindings:        c.detectFindings.Load(),
		DetectFindingsDropped: c.detectFindingsDropped.Load(),
		DetectStateEvicted:    c.detectStateEvicted.Load(),
		AlertsInserted:        c.alertsInserted.Load(),
		AlertsDeduped:         c.alertsDeduped.Load(),
		AlertsErrored:         c.alertsErrored.Load(),
		ResponseDispatched:    c.responseDispatched.Load(),
		ResponseDropped:       c.responseDropped.Load(),
		ResponseCompleted:     c.responseCompleted.Load(),
		SubscriberPublishes:   subs,
	}
}
