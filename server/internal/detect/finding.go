// Package detect is the server-side detection engine: it subscribes to
// the ingest bus, runs server-only Sigma rules against the streaming
// OCSF events, and emits internal Findings on a channel that the alert
// sink (#60) drains into the alerts table.
//
// Phase 3 #58 ships the engine + plan executor + bounded windowing for
// `count() by …` aggregations and `near` temporal joins. ServerPlan IR
// is read straight off rules.server_plan jsonb (#55) but each rule's
// boolean predicate still comes from the YAML — we recompile via
// ruleast.Compile at rule load so the detection engine never owns a
// parallel deserialiser.
//
// Backpressure: the engine subscribes to ingest.Bus with a bounded
// channel and applies drop-newest semantics on its own findings sink.
// Slow downstream alert handling drops findings; ingest never blocks.
package detect

import "time"

// Finding is what the engine emits when a rule fires. It's an
// internal-server type — the alert sink (#60) will turn it into an
// `alerts` table row, and the existing `DetectionFinding` OCSF event
// shape is what edge-fired rules emit; server-only rules go through
// this struct instead so we can carry the synthetic `event_ids`
// (the set of envelopes that contributed to the aggregation) without
// stuffing them inside an OCSF JSON blob.
type Finding struct {
	RuleID      string
	RuleTitle   string
	Severity    uint32
	HostID      string // empty for cross-host aggregations
	GroupKey    string // by-tuple value or "L→R" for near joins
	FiredAt     time.Time
	WindowStart time.Time
	WindowEnd   time.Time
	EventIDs    []string // contributing envelope event IDs
	Reason      string   // human-readable: "count(*)>5 over 60s"
}
