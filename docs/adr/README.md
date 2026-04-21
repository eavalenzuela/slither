# Architecture Decision Records

Every significant architectural or product decision is recorded here as an ADR.

## Format

Each ADR uses the lightweight template in `0000-template.md`:

- **Status** — Proposed, Accepted, Superseded, Deprecated.
- **Context** — what forced the decision.
- **Decision** — what we chose.
- **Consequences** — what follows, good and bad.

## Scope

ADRs are written when a decision:

- Closes an `[OPEN]` item in [PROJECT.md](../../PROJECT.md).
- Constrains a wide area of the codebase (language, framework, protocol, storage).
- Is likely to be questioned later — the ADR is the answer to "why did we do it this way?"

Day-to-day code decisions do not need ADRs. If it only affects one file, a code comment is enough.

## Index

ADRs 0001–0029 mirror the decisions locked in [PROJECT.md §9.1](../../PROJECT.md#9-decisions--remaining-open-items). They exist so the rationale survives if PROJECT.md is later restructured or replaced.

| # | Title |
|---|---|
| [0001](./0001-platform-linux-only-v1.md) | Platform: Linux-only for v1 |
| [0002](./0002-agent-language-go.md) | Agent language: Go (with eBPF C for kernel programs) |
| [0003](./0003-server-language-go.md) | Server language: Go |
| [0004](./0004-scale-target-50-500-hosts.md) | Scale target: 50–500 hosts per server |
| [0005](./0005-deployment-compose-primary.md) | Deployment: docker compose primary, multi-step supported |
| [0006](./0006-rule-format-sigma.md) | Rule format: Sigma |
| [0007](./0007-event-schema-ocsf.md) | Canonical event schema: OCSF |
| [0008](./0008-hybrid-detection.md) | Detection topology: hybrid (edge + server) |
| [0009](./0009-fully-foss.md) | Commercial model: fully FOSS |
| [0010](./0010-linux-telemetry-ebpf.md) | Linux telemetry primitive: eBPF via CO-RE |
| [0011](./0011-transport-grpc-mtls.md) | Transport: gRPC bidi streams over mTLS |
| [0012](./0012-control-plane-postgres.md) | Control-plane store: Postgres |
| [0013](./0013-no-message-bus.md) | Message bus: none in v1 |
| [0014](./0014-dco-not-cla.md) | Contributions: DCO, not CLA |
| [0015](./0015-no-code-of-conduct-yet.md) | Code of conduct: deferred |
| [0016](./0016-security-disclosure-github.md) | Security disclosure: GitHub private reporting |
| [0017](./0017-event-store-clickhouse.md) | Event store: ClickHouse |
| [0018](./0018-edge-eligibility-policy.md) | Edge-eligibility policy: four-predicate gate |
| [0019](./0019-edge-engine-phased-rollout.md) | Edge engine: phased rollout by rule complexity |
| [0020](./0020-operator-overrides.md) | Operator overrides: force-server-only, never force-edge |
| [0021](./0021-immediate-response-opt-in.md) | Immediate response: opt-in per rule + per host |
| [0022](./0022-protection-first-principle.md) | Operating principle: protection-first |
| [0023](./0023-web-console-htmx.md) | Web console: HTMX + templ + Tailwind, no SPA framework |
| [0024](./0024-graph-rendering-d2.md) | Alert graph rendering: server-side SVG via D2 |
| [0025](./0025-process-tree-v1-scope.md) | Process tree v1 scope: flat list + parent-chain mini-graph |
| [0026](./0026-rule-editor-click-validate.md) | Rule editor: Monaco vanilla + click-to-validate |
| [0027](./0027-agent-extensions-minimal.md) | Agent extensions: minimal interface, first-party only |
| [0028](./0028-osquery-optional-not-bundled.md) | osquery: optional, bridge extension, operator-installed |
| [0029](./0029-extension-execution-model.md) | Extension execution: out-of-process, supervised |

## Adding a new ADR

1. Copy `0000-template.md` to `NNNN-short-title.md` where `NNNN` is the next number.
2. Fill it in.
3. Add the row to the table above.
4. Submit via PR with DCO.
