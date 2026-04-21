# ADR 0023 — Web console: HTMX + templ + Tailwind, no SPA framework

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

The web console needs to render alert lists, alert detail, rule management, host inventory, and a live event tail. Two broadly viable stacks:

- **SPA (React/Vue/Svelte + REST or tRPC backend).** Rich client-side interactivity, familiar hiring market, but introduces a JS toolchain, two separate deployables, a second language, and state-sync complexity (server truth vs. client cache).
- **HTMX + server-rendered templates.** Single Go deployable, no client-side build, server is always the source of truth. UX ceiling is lower for highly-interactive widgets.

A widget-by-widget walkthrough (process tree, rule editor, live tail, alert detail) confirmed that only two widgets materially benefit from SPA richness: interactive process-tree exploration and a fully client-side rule editor. Both can be scoped narrower without losing core value.

## Decision

- **Templates:** `templ` — type-checked Go templates that compile to Go functions. Errors are caught at `go build`, not at render time.
- **Interactivity:** `HTMX` — server-rendered partials swapped into the page via `hx-get`/`hx-post`/`hx-swap`.
- **Live updates:** Server-Sent Events for the live tail and alert stream.
- **Styling:** Tailwind CSS via a single prebuilt stylesheet (no per-page PostCSS build).
- **Heavy editors:** Monaco is loaded as a vanilla script only on the rule-editor page (ADR-0026).
- **No SPA framework.** No React, Vue, Svelte, or equivalent.

## Consequences

- One binary, one deployable, one language. The server is the web app.
- Page-level state is always fresh — no client cache to invalidate.
- `templ` gives compile-time safety that Go's stdlib `html/template` does not, without the runtime complexity of a separate JS stack.
- The process-tree explorer is deliberately scoped down for v1 (ADR-0025).
- Hiring is narrower for frontend specialists, but the team is small and Go-centric — this is an acceptable tradeoff.

## Alternatives considered

- **React + REST API.** Richer UX but doubles the build surface and splits truth between client and server.
- **Go `html/template` without HTMX.** Every interaction becomes a full-page reload. Rejected — the live tail and alert-detail drawers need partial updates.
- **Alpine.js.** Small, but HTMX covers more of the interaction patterns we actually need (swaps, SSE) with one idiom.

## References

- PROJECT.md §3.5, §4.3, §9.1 row 24.
