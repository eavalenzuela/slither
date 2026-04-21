# ADR 0026 — Rule editor: Monaco vanilla + click-to-validate

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Rule authors need a reasonable editing experience for Sigma rules in the web console: syntax highlighting, structure validation, and a "will this compile?" check before deploying. A full IDE-like live-validate-on-keystroke experience would require a client-side Sigma parser and is out of scope for an HTMX-first console (ADR-0023).

## Decision

- **Editor component:** Monaco, loaded as a vanilla script on the rule-editor page only. No React wrapper, no module bundler integration. YAML mode with a Sigma-aware schema for hover hints.
- **Validation model:** **click-to-validate.** The editor has a "Validate" button that POSTs the current buffer to the server. The server runs the Sigma compiler, and returns either (a) a success response showing the computed edge/server placement and the failing predicates if any, or (b) a structured error list with line numbers. Errors are rendered as HTMX-swapped inline annotations.
- **Deploy:** a separate "Deploy" action, disabled until the current buffer has passed validation.

## Consequences

- One compiler, one source of truth — the server's compiler is authoritative. There is no risk of the client saying "valid" when the server disagrees.
- Monaco gives authors syntax highlighting, bracket matching, and keyboard comfort without a JS toolchain.
- Every validation is a network round-trip. Acceptable given the user pattern (write, then validate, then deploy — not continuous typing feedback).
- The click-to-validate button is an explicit checkpoint, which naturally aligns with "review before you ship this rule."

## Alternatives considered

- **Live client-side validation.** Requires a Sigma parser in JS (doesn't exist in mature form) or shipping the Go compiler to WASM. Both are substantial work for marginal UX gain.
- **No editor — plain textarea.** Loses syntax highlighting. Hostile to rule authors.
- **Full IDE integration (LSP).** Out of scope; revisit if a VS Code extension is ever built.

## References

- PROJECT.md §3.5, §9.1 row 27; ADR-0023.
