# ADR 0032 — Two-artefact rule shape: edge AST + server plan

- **Status:** Accepted
- **Date:** 2026-04-26

## Context

Phase 3 (`IMPLEMENTATION.md §5.1`) promotes the Sigma compiler from
the Phase 1 stateless subset to the full grammar (`N of`, pipe
aggregations, `near`, list-of-maps, `base64`/`utf16*` modifiers,
`timeframe`). ADR-0008 chose hybrid detection; ADR-0018 fixed the
four-predicate edge-eligibility gate; ADR-0019 phased edge engine
capability so Phase 3 lifts the agent into bounded-stateful
evaluation.

The compiler now needs to emit two distinct artefacts per rule:

- An **edge artefact** the agent can decode and evaluate locally.
  Shape covers stateless predicates plus bounded `count() by … |
  > N` within a per-host window — nothing that crosses hosts or
  joins streams.
- A **server plan** the server-side detection engine (#58) executes
  against the ingest bus. Shape covers cross-host aggregations,
  `near` joins, and any rule whose inputs aren't locally observable
  on the agent.

Some rules emit both (force-edge classification on a rule that's
also server-classifiable). Some emit only one. Some emit neither
(`force: edge` on a rule that fails an edge predicate is a compile
error — ADR-0018 cited by name).

The wire question: does the server plan ride the existing
`slither.v1` namespace, or does the two-artefact split warrant a
`slither.v2` discussion?

The storage question: where does the server plan live? Existing
`rules` table has `source_yaml` and (Phase 2) the compiled bytecode
inside the wire `EdgeRule.compiled_ast`. The server plan needs a
home that the detection engine can read on every rule push without
recompiling Sigma every time.

The agent-side question: when a v1 agent encounters a v2 rule (or
a v2 agent encounters an over-cap spec from a future server with a
looser policy), how does it refuse without dropping the ruleset
silently?

## Decision

### Wire format: additive within `slither.v1`

The server plan never touches the wire. Agents receive only edge
artefacts. `slither.v1` stays — no `slither.v2` namespace.

`EdgeRule.ast_version` bumps from `1` to `2` for stateful rules.
v1 agents that don't understand v2 emit a `DiagReport.warnings`
entry and skip that rule; v1-only rules continue to ride
`ast_version = 1` so v1 agents keep working unmodified.

`EdgeRule` gains two additive fields exposing the runtime bounds
the compiler computed, so agents can enforce ADR-0018 at runtime
even if a misconfigured server pushes an over-cap rule:

```proto
message EdgeRule {
  // ... existing fields 1-8 unchanged ...
  uint32 state_window_secs = 9;   // 0 = stateless
  uint32 state_cap         = 10;  // 0 = stateless
}
```

These are the *output* of the compiler's classification — they
describe what the agent should expect, not what the operator
requested. Operators encode the request in YAML (`force: edge` on
the rule); the compiler evaluates the four ADR-0018 predicates and
emits the runtime-bound metadata above.

`force_edge` itself is **not** on the wire — agents don't need it
(the compiler has already filtered which rules ride `EdgeRule` at
all). It lives only in pg (`rules.force_edge boolean`) so the
console + audit log can show whether a row got onto the agent via
operator override vs natural classification. Keeping it server-side
also means the wire stays minimal and a future telemetry surface
(e.g., agent-side counters per force-edged rule) becomes a
deliberate ADR rather than a quiet wire add.

### Storage: `rules.server_plan jsonb` + `rules.classification text`

A new goose migration (`00010_rules_server_plan.sql`) extends the
`rules` table:

```sql
ALTER TABLE rules
  ADD COLUMN server_plan    jsonb,
  ADD COLUMN classification text    NOT NULL DEFAULT 'edge_only',
  ADD COLUMN force_edge     boolean NOT NULL DEFAULT false;

ALTER TABLE rules
  ADD CONSTRAINT rules_classification_chk
  CHECK (classification IN ('edge_only', 'server_only', 'both'));
```

`server_plan` is the JSON-serialised server plan IR (defined in the
new `pkg/ruleast/serverplan/` package landing in #54). Stored as
`jsonb` so the detection engine can index over plan facets later
(e.g., "find rules touching `network_connection` events") without
parsing every row.

`classification` is the redundant-but-explicit string the control
hub uses to decide where a rule goes:

- `edge_only` — push to agents (in `EdgeRule` wire form), do not
  run on server.
- `server_only` — load into detection engine, do not push to
  agents.
- `both` — push to agents *and* run on server. Currently rare —
  it's force-edge with an additionally-server-eligible rule, kept
  in the model for completeness.

`server_plan` is `NULL` for `edge_only` rows. `compiled_ast` (in
the wire form derived from `source_yaml`) is empty for
`server_only` rows.

### Agent-side refusal: `DiagReport.warnings` per rejected rule

When the agent decodes an `EdgeRule` and finds either:

- An `ast_version` it doesn't recognise, or
- A `state_window_secs > 300` or `state_cap > 1024` (ADR-0018
  hard caps), or
- A malformed AST that fails agent-side validation (sanity check
  — server should have caught this at compile),

it skips the rule (does not load it into the engine) and appends
one entry to `DiagReport.warnings` of the form:

```
rule:<rule_id>:<reason>
```

with reasons drawn from a fixed vocabulary:

- `ast_version_unsupported` — version newer than agent supports.
- `state_window_too_large` — `state_window_secs > 300`.
- `state_cap_too_large` — `state_cap > 1024`.
- `compile_failed` — defensive; agent-side validation rejected
  the AST.

The server logs each warning at `level=WARN` via the `pkg/log`
slog facade (#49) so operators see them in `journalctl -u
slither-server` without scraping agent stderr. The agent does not
return an error — one bad rule never black-holes the rest of the
ruleset.

`DiagReport.warnings` is already a `repeated string` on the wire,
so this is structural-only — no proto change needed.

## Consequences

**Easier:**

- Phase 3 stateful agents are deployable alongside Phase 1/2
  agents. v1 agents skip v2 rules with a structured warning;
  operators upgrade at their own pace.
- Server-only rules never round-trip through the wire — saves
  bandwidth on rule pushes, particularly for rules with large
  `near` join specs. The detection engine reads the JSON plan
  directly from pg.
- Compile-time classification is mechanical: the four ADR-0018
  predicates output the `classification` enum + the metadata
  fields, no hand-tagging.
- Agents enforce ADR-0018 at runtime, not just at compile-time —
  defends against a misconfigured server that would otherwise
  push an over-cap rule.

**Harder:**

- Two artefacts per rule means the compiler now has two output
  surfaces. `pkg/ruleast/serverplan/` is a new package; tests
  cover both edge and server-plan emission per rule.
- The server's control hub (#55) needs to filter `EdgeRule`
  pushes on `classification` so agents don't receive
  `server_only` rules in their wire form. Existing `Refresh()`
  fans out everything; that needs a single SQL-level filter
  added.
- The wire format gains two new `EdgeRule` fields. Field numbers
  9 and 10 are now claimed; a future ADR that wants to add a
  *third* metadata field needs to use 11+ (proto3 field-number
  stability rule).

**Follow-up work:**

- #54 ships the compiler with classification + dual-artefact
  emit.
- #55 ships the wire/storage plumbing (proto bump, migration,
  hub filter).
- #57 ships the agent's runtime refusal + DiagReport emission.
- A future Phase 4+ ADR may revisit: if the server plan ever
  *needs* to round-trip through the wire (e.g., to support
  agent-as-server hops in a federation topology), that's
  non-additive and warrants `slither.v2`.

## Alternatives considered

- **Server plan on the wire as a second `bytes` field on
  `EdgeRule`.** Adds wire weight even on agents that ignore it;
  forces agents to know about a payload they don't execute.
  Rejected.
- **`slither.v2` namespace for the two-artefact split.** Forces
  agents to upgrade in lockstep with the server; breaks the wire
  freeze for no functional reason. Rejected per
  `IMPLEMENTATION.md §2.4`.
- **Server plan as a separate Postgres table joined on
  `rule_id`.** Over-modelled — there's exactly one server plan
  per rule, and the rule row is the natural place. Rejected.
- **Agent rejects the whole ruleset on any malformed rule.** Too
  brittle; one bad rule from a misconfigured server would take
  the agent offline. Rejected — partial-success with structured
  warnings is the model already used by Phase 2 #39.

## References

- ADR-0008 (hybrid detection), ADR-0018 (edge-eligibility four
  predicates), ADR-0019 (phased edge engine), ADR-0030 (Postgres
  schema v1 + migrations), ADR-0031 (ClickHouse schema).
- `IMPLEMENTATION.md §5.1` tasks #54, #55, #57.
- `proto/slither/v1/control.proto` (`EdgeRule` definition).
- `proto/slither/v1/agent.proto` (`DiagReport.warnings`).
