// Package ruleast is slither's internal detection rule AST and the Sigma
// compiler that targets it.
//
// # Scope
//
// Phase 1 supports a strict subset of Sigma (IMPLEMENTATION.md §3.5, ADR-0019):
//
//   - logsource.product must be "linux"; category must be one of
//     "process_creation", "file_event", "network_connection".
//   - detection is a map of named selections plus a final "condition" string.
//     No aggregation (count, near, timeframe, pipe operators).
//   - Field modifiers supported: equals (default), contains, startswith,
//     endswith, re / regex. "all" list-AND, "cased", base64* and number
//     comparison modifiers are explicitly rejected so rule authors get a
//     compile-time error instead of a silently wrong match.
//   - The condition expression is a boolean tree of selection references
//     built from "and", "or", "not", and parentheses. "N of selection*"
//     forms are rejected — they arrive with bounded-stateful support in
//     Phase 3.
//
// # Entry points
//
//   - CompileSigma parses one Sigma YAML document into a *Rule.
//   - Rule.Match evaluates against an Env the caller supplies (typically an
//     OCSF-event-backed Env assembled by the agent's ruleengine in Phase 1
//     task #20).
//
// # Non-goals
//
// This package does not resolve Sigma field names to OCSF paths — that
// taxonomy is the ruleengine's responsibility, so the compiler stays
// independent of OCSF class shape.
package ruleast
