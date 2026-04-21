# ADR 0014 — Contributions: DCO, not CLA

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Open-source projects use either a Contributor License Agreement (CLA) or the Developer Certificate of Origin (DCO) to establish rights on contributed code. CLAs impose friction (signing ceremony, lawyer involvement, identity verification). DCO is per-commit, tool-enforceable, and sufficient under MIT.

## Decision

Use DCO. Every commit must carry a `Signed-off-by:` trailer. CI rejects unsigned commits.

## Consequences

- Low friction — `git commit -s` is the only requirement.
- No CLA-tracking infrastructure or corporate-entity signing process.
- Enforceable via a single GitHub Actions workflow (`.github/workflows/dco.yml`).

## Alternatives considered

- **CLA.** Too much friction for a small FOSS project.
- **No contribution agreement.** Risk of licensing ambiguity.

## References

- PROJECT.md §8, §9.1 row 15; CONTRIBUTING.md.
