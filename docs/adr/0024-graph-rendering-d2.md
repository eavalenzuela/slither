# ADR 0024 — Alert graph rendering: server-side SVG via D2

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Alert detail needs to show the detection flow — the chain of events (process exec → network connect → file write, etc.) that led to a finding. A visual graph is meaningfully clearer than a flat event list, especially for multi-step alerts.

Options for producing the graph:

- **Client-side JS graph library** (cytoscape, vis.js, dagre-d3). Interactive but pulls a JS toolchain into a HTMX-first console (ADR-0023).
- **Graphviz via CLI shell-out.** Proven but requires the `dot` binary on the server and subprocess management.
- **D2** (MIT, Go-native). Pure-Go library; renders to SVG in-process.
- **Mermaid** (server-side via headless Chromium). Heavy and fragile.

## Decision

**D2** for server-side rendering. The server builds a D2 source string from the event chain, calls D2's Go API, and returns SVG inline in the response HTML.

## Consequences

- No client-side JS for graph rendering — keeps the HTMX posture intact.
- No extra runtime dependency (no `dot`, no headless browser) — D2 is a Go import.
- Apache 2.0 / MIT licensing is compatible with the project's MIT license.
- SVG is cached per alert-id + ruleset-version; re-renders happen only when the underlying data changes.
- Interactivity is limited to what SVG + a little HTMX can do (click a node to open the event in the side drawer). This is acceptable for v1; a richer interactive explorer is deferred to Phase 6.

## Alternatives considered

- **Graphviz shell-out.** Works, but adds an ops burden (package on every host running the server) and subprocess management.
- **Client-side cytoscape.** Violates the HTMX-first decision and adds a JS toolchain for one widget.
- **Hand-written SVG layout.** Reinventing a graph layout engine. Rejected.

## Implementation pin

- Version: `oss.terrastruct.com/d2 v0.7.1` (pinned in `server/go.mod`).
- Transitive: `oss.terrastruct.com/util-go` (helpers; pulled by D2).
- Layout engine: `d2dagrelayout` (pure-Go via embedded JS — no extra runtime dep).
- Theme: `d2themescatalog.NeutralDefault` (matches the console's plain styling).
- Library facade: `server/internal/graph.Render(ctx, source) ([]byte, error)`. All other server code goes through it; no other package imports `oss.terrastruct.com/d2/...` directly.
- Binary impact: server binary grew from ~2.4 MB to ~26 MB (≈+24 MB) due to D2's embedded fonts + Dagre.js bundle. Acceptable given the ADR's "no extra runtime dependency" property; revisit only if release-image size becomes a deployment problem.

## Licensing

D2 ships under MPL-2.0 (per `oss.terrastruct.com/d2`'s `LICENSE`). MPL-2.0 is file-level copyleft and compatible with the project's MIT licence — D2 is consumed as a separate Go module with no source modification, so the file-level reciprocity obligation has no practical reach into Slither code. The earlier draft of this ADR mentioned "Apache 2.0 / MIT" speculatively; the actual upstream licence is recorded here for clarity.

## References

- PROJECT.md §3.5, §4.3, §9.1 row 25; ADR-0023.
