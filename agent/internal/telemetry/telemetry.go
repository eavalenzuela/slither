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

	// response — Phase 4 #77 agent executor metrics. ExecQueueFull
	// fires when Submit hits the worker-pool cap; the dispatch is
	// completed by emitting a synthetic FAILED ResponseResult so
	// the server-side row never sticks in `running`. ExecPanic is
	// the recover() fallback. ResultDropped fires when the outbound
	// result channel is full at emit time.
	responseExecDone          atomic.Uint64
	responseExecFailed        atomic.Uint64
	responseExecQueueFull     atomic.Uint64
	responseExecPanic         atomic.Uint64
	responseExecResultDropped atomic.Uint64

	// extensions — Phase 6 #107 supervisor metrics. ExtSpawned counts
	// successful spawn-and-Hello cycles (per extension, per restart).
	// ExtSignatureFailures records cosign verify failures at spawn time
	// (fail-closed; the extension is not spawned). ExtCapabilityViolations
	// fires when an extension emits a message kind it didn't declare on
	// Hello — connection torn down, restart counter ticked.
	// ExtRestarts ticks every supervisor backoff cycle. ExtEventsEmitted
	// is the count of OCSFEvent envelopes the supervisor passed through
	// after capability gating + agent stamping.
	extSpawned              atomic.Uint64
	extRestarts             atomic.Uint64
	extSignatureFailures    atomic.Uint64
	extCapabilityViolations atomic.Uint64
	extEventsEmitted        atomic.Uint64

	// Phase 6 #111 snapshot-on-alert metrics. Requested ticks per
	// extension targeted at dispatch time (so a fanout to two
	// providers is two requests). Completed and Failed are terminal
	// counters; together they sum to Requested for finished runs.
	extSnapshotsRequested atomic.Uint64
	extSnapshotsCompleted atomic.Uint64
	extSnapshotsFailed    atomic.Uint64
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

// IncResponseExecDone — agent executor finished one ResponseRequest
// with status=DONE.
func (c *Counters) IncResponseExecDone() { c.responseExecDone.Add(1) }

// IncResponseExecFailed — agent executor finished one ResponseRequest
// with status=FAILED (handler returned a non-DONE terminal status).
func (c *Counters) IncResponseExecFailed() { c.responseExecFailed.Add(1) }

// IncResponseExecQueueFull — Submit hit the worker-pool cap; the
// request was rejected synchronously and a FAILED result was emitted
// so the server-side state machine still moves the row.
func (c *Counters) IncResponseExecQueueFull() { c.responseExecQueueFull.Add(1) }

// IncResponseExecPanic — handler panicked; the recover guard caught
// it and emitted a FAILED result. Sustained growth means a handler
// bug.
func (c *Counters) IncResponseExecPanic() { c.responseExecPanic.Add(1) }

// IncResponseExecResultDropped — outbound result channel was full at
// emit time. Indicates the sink is wedged or the channel is too
// small for the burst rate.
func (c *Counters) IncResponseExecResultDropped() { c.responseExecResultDropped.Add(1) }

// IncExtSpawned bumps the extension-spawned counter — one per Hello-
// completed connection. Restart cycles tick this again.
func (c *Counters) IncExtSpawned() { c.extSpawned.Add(1) }

// IncExtRestart bumps the extension-restart counter. Every supervisor
// backoff cycle adds one regardless of the failure cause.
func (c *Counters) IncExtRestart() { c.extRestarts.Add(1) }

// IncExtSignatureFailure bumps the cosign-verify-failed counter.
// Verifies happen pre-spawn; failures keep the extension off the
// agent and tick this counter once per attempt.
func (c *Counters) IncExtSignatureFailure() { c.extSignatureFailures.Add(1) }

// IncExtCapabilityViolation bumps the capability-violation counter.
// Fires when an extension emits a message kind it didn't declare on
// Hello, or claims a capability not in the operator's allow list.
func (c *Counters) IncExtCapabilityViolation() { c.extCapabilityViolations.Add(1) }

// IncExtEventEmitted bumps the per-event passthrough counter. Counts
// every OCSFEvent envelope the supervisor forwarded after capability
// gate + stamping, regardless of whether the engine ultimately matched
// it.
func (c *Counters) IncExtEventEmitted() { c.extEventsEmitted.Add(1) }

// IncExtSnapshotRequested ticks once per snapshot dispatched to an
// extension. A fanout to two snapshot providers ticks twice. Phase 6
// #111.
func (c *Counters) IncExtSnapshotRequested() { c.extSnapshotsRequested.Add(1) }

// IncExtSnapshotCompleted ticks when an extension delivered a complete
// snapshot (chunks + SnapshotComplete with empty error) and the
// reassembled tarball survived rolling-SHA256 verification.
func (c *Counters) IncExtSnapshotCompleted() { c.extSnapshotsCompleted.Add(1) }

// IncExtSnapshotFailed ticks for any non-success terminal: extension
// returned SnapshotComplete with error set, the cycle ended before
// completion, the chunk SHA-256 chain diverged, or the per-snapshot
// timeout elapsed.
func (c *Counters) IncExtSnapshotFailed() { c.extSnapshotsFailed.Add(1) }

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

	ResponseExecDone          uint64
	ResponseExecFailed        uint64
	ResponseExecQueueFull     uint64
	ResponseExecPanic         uint64
	ResponseExecResultDropped uint64

	ExtSpawned              uint64
	ExtRestarts             uint64
	ExtSignatureFailures    uint64
	ExtCapabilityViolations uint64
	ExtEventsEmitted        uint64

	ExtSnapshotsRequested uint64
	ExtSnapshotsCompleted uint64
	ExtSnapshotsFailed    uint64
}

// Snapshot returns a point-in-time view of the counters.
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		EventsProduced:            c.eventsProduced.Load(),
		EventsDropped:             c.eventsDropped.Load(),
		DropsCollector:            c.dropsCollector.Load(),
		DropsDispatch:             c.dropsDispatch.Load(),
		DropsEnricher:             c.dropsEnricher.Load(),
		DropsEngine:               c.dropsEngine.Load(),
		DropsOutput:               c.dropsOutput.Load(),
		OutputReconnects:          c.outputReconnects.Load(),
		HeartbeatsSent:            c.heartbeatsSent.Load(),
		DetectionsFired:           c.detectionsFired.Load(),
		RingbufOverflows:          c.ringbufOverflows.Load(),
		StateEvicted:              c.stateEvicted.Load(),
		ResponseExecDone:          c.responseExecDone.Load(),
		ResponseExecFailed:        c.responseExecFailed.Load(),
		ResponseExecQueueFull:     c.responseExecQueueFull.Load(),
		ResponseExecPanic:         c.responseExecPanic.Load(),
		ResponseExecResultDropped: c.responseExecResultDropped.Load(),
		ExtSpawned:                c.extSpawned.Load(),
		ExtRestarts:               c.extRestarts.Load(),
		ExtSignatureFailures:      c.extSignatureFailures.Load(),
		ExtCapabilityViolations:   c.extCapabilityViolations.Load(),
		ExtEventsEmitted:          c.extEventsEmitted.Load(),
		ExtSnapshotsRequested:     c.extSnapshotsRequested.Load(),
		ExtSnapshotsCompleted:     c.extSnapshotsCompleted.Load(),
		ExtSnapshotsFailed:        c.extSnapshotsFailed.Load(),
	}
}
