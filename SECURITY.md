# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository. If you cannot use GitHub, email the maintainer listed in the repository metadata.

## What to include

- A clear description of the issue and its impact.
- Reproduction steps, ideally with a minimal PoC.
- Affected versions / commits, if known.
- Suggested remediation, if you have one.

## What to expect

- **Acknowledgement within 72 hours.** We'll confirm we've seen your report and begin triage.
- **Status updates** at least weekly while the issue is open.
- **Coordinated disclosure.** We'll agree on a disclosure timeline with you before publishing fixes and advisories. The default is 90 days from report to public disclosure; we may shorten or extend by mutual agreement.
- **Credit** in the advisory, unless you prefer to remain anonymous.

## Scope

In scope:

- Slither agent (`slither-agent`) and server (`slither-server`) binaries.
- Agent↔server wire protocol.
- Default deployment configurations in `deploy/`.
- Slither-authored rule evaluation logic (injection, bypass, authorization flaws).

Out of scope:

- Vulnerabilities in third-party dependencies that have not yet been disclosed upstream — report those to the upstream project first.
- Denial-of-service that requires already having root on the monitored host (the agent runs as root by design; see PROJECT.md §6 threat model).
- Issues in development or test scaffolding that do not run in production deployments.

## Safe harbor

We will not pursue legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, service disruption, or data destruction.
- Give us reasonable time to address issues before public disclosure.

## Pre-release status

Slither is pre-alpha and has **not** undergone third-party security review. Assume vulnerabilities exist. Do not deploy to production systems yet.
