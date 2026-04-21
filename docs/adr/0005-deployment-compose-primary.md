# ADR 0005 — Deployment: docker compose primary, multi-step supported

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

First-run experience shapes who adopts the tool. Operators have two common profiles: container-native (docker compose / k8s) and bare-metal (systemd, manual installs). Supporting both is the goal; one of them is the first-class path.

## Decision

`docker compose up` is the primary deployment path for the server. A multi-step bare-metal install with systemd units is fully documented and supported, but compose is what docs and tutorials lead with. Agent install is a single static binary + systemd unit on endpoints (no compose on endpoints).

## Consequences

- Compose setup is a make target (`make compose-up`); the reference compose file is part of CI's verification surface.
- Server binaries must run unchanged inside or outside a container — no compose-only code paths.
- `.deb` / `.rpm` packages are deferred to Phase 5 (nfpm).

## Alternatives considered

- **Compose-only.** Excludes the bare-metal audience unnecessarily.
- **Helm/k8s-first.** Overkill at 50–500 host scale.

## References

- PROJECT.md §4.3, §9.1 row 5.
