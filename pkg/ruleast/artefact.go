package ruleast

// Phase 3 §5.1 #54 / ADR-0032 introduces the two-artefact compile shape.
// Compile returns three things per rule:
//
//   - EdgeArtefact: what the agent loads into its rule engine. Holds a
//     compiled *Rule plus the runtime bounds the agent enforces against
//     ADR-0018. nil when classification is ServerOnly.
//   - ServerPlan:   the server detection engine's executable plan for
//     stateful or cross-host rules. nil for rules that fully run on the
//     edge. Populated by #54d / #54e; #54a leaves it empty so the API
//     surface lands without dragging the plan IR with it.
//   - Classification: enum routing the rule between agents and the
//     server detection engine.
//
// #54a (this commit) keeps Compile producing only EdgeOnly results so
// the existing rule corpus continues to round-trip. Stateful + server-
// only behaviour lights up with #54d/#54e.

// ASTVersion identifies the wire-format bucket an EdgeArtefact belongs
// to. Phase 2 / Phase 3 stateless rules ride v1 (YAML pass-through).
// Stateful Phase 3 rules will ride v2 (protobuf-defined AST) when
// #54d lands. Agents that don't speak v2 skip the rule and emit a
// DiagReport entry per ADR-0032.
type ASTVersion uint32

const (
	ASTVersionV1 ASTVersion = 1
	ASTVersionV2 ASTVersion = 2
)

// Classification routes a compiled rule to the agent, the server
// detection engine, or both. The values are wire-stable strings so they
// round-trip cleanly through the rules.classification text column added
// in migration 00010.
type Classification string

const (
	// ClassificationEdgeOnly: rule runs only on agents. ServerPlan is
	// nil. EdgeArtefact is non-nil.
	ClassificationEdgeOnly Classification = "edge_only"

	// ClassificationServerOnly: rule runs only on the server detection
	// engine. EdgeArtefact is nil. ServerPlan is non-nil.
	ClassificationServerOnly Classification = "server_only"

	// ClassificationBoth: rule runs in both places. Currently rare —
	// reserved for force-edge overrides on rules that are also
	// server-classifiable. Both EdgeArtefact and ServerPlan are
	// non-nil.
	ClassificationBoth Classification = "both"
)

// EdgeArtefact is the in-process form of a rule destined for the agent.
// The wire form (proto3 EdgeRule) is derived from this struct by the
// control hub: ASTVersion, StateWindowSecs, StateCap, and the bytes
// that re-decode into Rule on the agent side.
//
// In #54a the bytes shipped on the wire stay YAML (ASTVersionV1 for
// every rule). #54d will introduce a protobuf-encoded AST for stateful
// rules (ASTVersionV2). Either way, the in-process EdgeArtefact owns
// the *Rule that the agent's engine actually evaluates.
type EdgeArtefact struct {
	// Rule is the compiled boolean-tree AST.
	Rule *Rule

	// ASTVersion identifies the wire-format encoding the control hub
	// will use when serialising this artefact.
	ASTVersion ASTVersion

	// StateWindowSecs is the bounded-stateful window in seconds, or 0
	// for stateless rules. Capped at 300 (ADR-0018 predicate 2);
	// rules that exceed are classified ServerOnly at compile time.
	StateWindowSecs uint32

	// StateCap is the max number of distinct keys held in the rule's
	// per-host state ring, or 0 for stateless rules. Capped at 1024
	// (ADR-0018 predicate 2).
	StateCap uint32

	// Lookback signals the agent should request a CH replay of the
	// rule's timeframe window at rule push (#59 stateful cold-start,
	// opt-in per rule via top-level `lookback: true`). Stateless rules
	// always carry false.
	Lookback bool

	// IOCFeeds names every IOC feed_id the rule's `|ioc` predicates
	// reference. Empty for rules that don't use IOC matching. The
	// agent's IOC store (#67) preloads these feeds before the rule
	// is enabled so an IOC predicate never silently misses.
	IOCFeeds []string

	// Response is the optional auto-respond intent compiled from the
	// rule's top-level `slither.response` block. nil when the rule
	// has no response block. Phase 4 #82 lands this field; Phase 4
	// #83 wires the agent's edge auto-respond engine that consumes it.
	Response *ResponseIntent
}

// IsStateful reports whether the artefact carries non-zero state
// bounds. The agent uses this to decide whether to allocate a state
// ring on rule load.
func (a *EdgeArtefact) IsStateful() bool {
	if a == nil {
		return false
	}
	return a.StateWindowSecs > 0 || a.StateCap > 0
}

// ResponseAction names a per-rule auto-respond intent. The vocabulary
// is frozen by ADR-0034 (six action classes); names round-trip
// verbatim with the proto enum's snake_case form so authors see the
// same string in the YAML, the audit row, and the wire request.
type ResponseAction string

const (
	ResponseActionKillProcess      ResponseAction = "kill_process"
	ResponseActionKillProcessTree  ResponseAction = "kill_process_tree"
	ResponseActionQuarantineFile   ResponseAction = "quarantine_file"
	ResponseActionIsolateHost      ResponseAction = "isolate_host"
	ResponseActionUnisolateHost    ResponseAction = "unisolate_host"
	ResponseActionCollectArtifacts ResponseAction = "collect_artifacts"
)

// allResponseActions backs the validation switch + the linker error
// surface — adding a new action class to this list (and ADR-0034 +
// the proto enum) wires it through the compiler in one go.
var allResponseActions = []ResponseAction{
	ResponseActionKillProcess,
	ResponseActionKillProcessTree,
	ResponseActionQuarantineFile,
	ResponseActionIsolateHost,
	ResponseActionUnisolateHost,
	ResponseActionCollectArtifacts,
}

// ResponseIntent is the compiled form of a Sigma rule's optional
// `slither.response` block (Phase 4 #82). The agent's edge auto-
// respond engine (#83) reads this off the EdgeArtefact when the
// rule fires; the server-side dispatcher reads it off the
// ServerPlan when stateful/correlated rules fire.
//
// TargetField names the OCSF/event field whose value the action's
// Target should be drawn from. The compiler validates that the
// field appears in at least one of the rule's selection predicates
// — a typo'd target_field at compile time beats a silent miss at
// runtime when the field never resolves.
type ResponseIntent struct {
	Action      ResponseAction `json:"action"`
	TargetField string         `json:"target_field"`
	// Immediate signals the agent should run the action without
	// waiting for the server to dispatch a ResponseRequest. False
	// (default) means the rule still emits a DetectionFinding +
	// the operator (or server auto-respond pipeline) decides. ADR-
	// 0021 governs the "immediate" opt-in.
	Immediate bool `json:"immediate,omitempty"`
}

// ServerPlan is the in-process form of a rule destined for the server
// detection engine. #54a defined the shell; #54d fills in aggregation
// IR + windowing; #54e adds temporal-join specs. The struct is
// JSON-serialised into the rules.server_plan jsonb column; do not
// change field tags without a migration.
type ServerPlan struct {
	// RuleID echoes Rule.ID so server-side queries against
	// rules.server_plan can join back without a second lookup.
	RuleID string `json:"rule_id"`

	// Aggregation, when non-nil, describes the stateful pipe expression
	// the server detection engine should evaluate against the ingest bus.
	// The detection engine recompiles SourceYAML through ruleast.Compile
	// at load to rebuild the boolean tree; this struct only carries the
	// fields that don't survive YAML round-trip without ambiguity.
	Aggregation *Aggregation `json:"aggregation,omitempty"`

	// TimeframeSecs mirrors Aggregation.TimeframeSecs but stays populated
	// even on rules whose stateful shape lights up via #54e (`near`,
	// cross-host) where the aggregation field may instead carry a join
	// spec.
	TimeframeSecs uint32 `json:"timeframe_secs,omitempty"`

	// Lookback opts the server-side stateful evaluator into the same
	// CH-replay cold-start path as the agent (#59).
	Lookback bool `json:"lookback,omitempty"`

	// TemporalJoin describes a Sigma `near` correlation between two
	// selections. Populated by #54e for rules whose condition is the
	// binary form `IDENT near IDENT`. The detection engine joins the
	// two streams on a per-WithinSecs window.
	TemporalJoin *TemporalJoin `json:"temporal_join,omitempty"`

	// CrossHost is true when the operator declared `cross_host: true`.
	// Forces ServerOnly classification regardless of timeframe; signals
	// the detection engine to keep the rule's window keyed across hosts
	// rather than per host.
	CrossHost bool `json:"cross_host,omitempty"`

	// IOCFeeds names every IOC feed_id the rule references. Server
	// detection engine #58 reads this directly when rebuilding plans
	// after a feed reload; empty for rules that don't use `|ioc`.
	IOCFeeds []string `json:"ioc_feeds,omitempty"`

	// Response is the auto-respond intent for server-side firings
	// (mirrors EdgeArtefact.Response). The server dispatcher (#75)
	// reads this when a server-only rule fires and routes the
	// resulting ResponseRequest with rule_uid set. Phase 4 #82.
	Response *ResponseIntent `json:"response,omitempty"`
}

// TemporalJoin is the wire form of a Sigma `near` join.
type TemporalJoin struct {
	Left       string `json:"left"`
	Right      string `json:"right"`
	WithinSecs uint32 `json:"within_secs"`
}
