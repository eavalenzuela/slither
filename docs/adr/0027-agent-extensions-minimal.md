# ADR 0027 — Agent extensions: minimal interface, first-party only

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

There are legitimate agent capabilities the project does not want in the core binary — osquery host inventory (ADR-0028), a future YARA file-scanning module, a future package-inventory collector. These have different release cadences, licences, or operational profiles than the core agent.

The question is what kind of extension surface the project exposes. Possibilities range from "none, monolith only" to "Splunk-style marketplace." Neither extreme fits: no-extensions forces either bundling or forks, while a marketplace is a multi-year governance project and invites supply-chain risk.

## Decision

- **Minimal extension interface, first-party extensions only** for the foreseeable future.
- **Interface shape:** an extension is an out-of-process binary (ADR-0029) that speaks a small gRPC interface — `Hello`, `Events` (streamed to the agent), and `Execute` (for action-taking extensions). The agent loads a list of extension binaries from config and supervises them.
- **No third-party plugin loading in v1.** The extension registry is the agent's config file; there is no dynamic download or marketplace.
- **Each first-party extension ships as a separate binary** and is versioned independently.

The goal is to make it cheap for *the project* to add a new capability as an extension, not to make it cheap for *strangers* to inject code into the agent.

## Consequences

- The core agent stays small and keeps a tight kernel-interaction surface.
- The first-party extensions (osquery bridge, eventually others) can evolve at their own pace.
- Operators who want a third-party integration have a clear path (fork the repo, ship a binary), but no drive-by plugin install attack surface.
- If the project later wants a true marketplace, it becomes a separate, deliberate ADR with its own governance, signing, and review requirements. Nothing done in v1 precludes that.

## Alternatives considered

- **No extensions — monolith only.** Forces either bundling every capability (licensing and binary-size bloat) or forking.
- **Full marketplace.** Too much governance surface area for a pre-alpha project with one maintainer.
- **In-process plugins (Go plugin package, cgo).** Crash blast radius is the whole agent; plugin ABI is notoriously fragile. Rejected in favor of out-of-process (ADR-0029).

## References

- PROJECT.md §3.7, §9.1 row 28; ADR-0028, ADR-0029.
