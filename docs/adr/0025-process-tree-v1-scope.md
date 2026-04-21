# ADR 0025 — Process tree v1 scope: flat list + parent-chain mini-graph

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

A full interactive process-tree explorer (expand/collapse, lazy-load children, search-within-tree, jump-to-event) is a genuinely useful investigator tool. It is also a substantial piece of frontend work — the exact kind of widget that pushes a HTMX console toward a SPA.

The project's operating principle is protection-first (ADR-0022), which pushes investigative depth to a later phase. The question is what the minimum useful process-visibility experience looks like in v1.

## Decision

For v1, the web console exposes process information via two surfaces:

1. **Flat searchable process list per host.** Sort by start time, user, parent-pid, command; filter by any field. Server-rendered, HTMX-paginated. No tree UI.
2. **Parent-chain mini-graph on alert detail.** For any alert, render the involved process plus its ancestor chain (up to N generations) via D2 (ADR-0024). This is static SVG, not interactive.

A full interactive process-tree explorer is **out of scope for v1** and is tracked as a Phase 6 deliverable.

## Consequences

- Investigators can still answer "what process did this, and where did it come from?" via the parent-chain graph.
- Operators can still sweep a host for suspicious processes via the searchable flat list.
- The frontend stays within HTMX's comfort zone — no lazy-load tree state machine, no client-side filtering.
- Users who need the full explorer will notice its absence; this is the tradeoff protection-first buys us.

## Alternatives considered

- **Full interactive tree in v1.** Pushes scope and frontend complexity beyond what protection-first warrants.
- **Only the mini-graph, no flat list.** Loses the "sweep this host" use case.
- **Only the flat list, no mini-graph.** Alert detail becomes a wall of text; loses the "how did this process get here?" answer.

## References

- PROJECT.md §3.5, §9.1 row 26; ADR-0022, ADR-0023, ADR-0024.
