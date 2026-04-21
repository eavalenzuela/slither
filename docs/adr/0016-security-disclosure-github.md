# ADR 0016 — Security disclosure: GitHub private vulnerability reporting

- **Status:** Accepted
- **Date:** 2026-04-20

## Context

Security tools need a vulnerability-disclosure channel. Options: private PGP-encrypted email, a bug-bounty platform, or GitHub's built-in private vulnerability reporting. Friction on the reporter's side is the biggest concern — every extra step loses reports.

## Decision

Use GitHub private vulnerability reporting as the primary channel. Acknowledge within 72 hours. Default 90-day coordinated disclosure. Credit researchers by default.

## Consequences

- Zero infrastructure to maintain. Reports flow into the repo where issues get fixed.
- Researchers familiar with GitHub can report in minutes.
- Email fallback is documented in SECURITY.md for researchers who can't use GitHub.
- Explicit safe-harbor language included in `SECURITY.md`.

## Alternatives considered

- **PGP-encrypted email.** Raises friction; PGP usage is in decline among researchers.
- **HackerOne / Bugcrowd.** Overkill for pre-alpha; revisit post-v1 if report volume warrants.

## References

- PROJECT.md §8, §9.1 row 17; SECURITY.md.
