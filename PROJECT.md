# Slither — FOSS EDR

> **Status:** Pre-implementation design. Core decisions locked (see §9). Remaining `[OPEN]` items are scoped and listed at the end.

---

## 1. Vision

Slither is a free, open-source Endpoint Detection and Response (EDR) platform built from the ground up with a focus on:

- **Protection-first.** Slither is designed for small teams that cannot "call in the cavalry" — there is no 24/7 SOC behind us. Blocking intrusions as early as possible beats preserving a pristine audit trail for later triage. Edge-side detection and opt-in immediate response are first-class, not an afterthought.
- **Transparency** — every detection, every action is auditable and inspectable. No black-box ML, no proprietary signatures.
- **Operator-first** — designed for small security teams, homelabs, and researchers who want real telemetry without a six-figure license.
- **Composability** — emits standard formats (OCSF / Sigma-compatible) so it plugs into existing SIEM / SOAR / data-lake pipelines instead of replacing them.
- **Honest scope** — does EDR well. Does not try to also be a vuln scanner, asset manager, or MDM.

### Non-goals

- Not an AV replacement for non-technical end users.
- Not a signature-based endpoint protection product competing with commercial AV on malware catalog size.
- Not trying to match the UI polish of commercial EDR suites in v1.
- Not a compliance-framework product (HIPAA/PCI/etc. dashboards are out of scope for v1).
- **Not cross-platform in v1.** Linux-only. macOS and Windows are post-v1 considerations.

---

## 2. Target Users

1. **Primary — Security engineers / blue teamers** at small-to-mid orgs who need endpoint visibility but can't justify CrowdStrike / SentinelOne licensing.
2. **Homelab / self-hosters** who want real EDR telemetry on their own boxes.
3. **Security researchers** studying attacker behavior, testing detections, or building custom rules.
4. **Red teamers** who want a realistic open defense to test against.

Explicit non-user: end-user consumers looking for a "set and forget" AV. Slither expects an operator.

### Scale target for v1

Designed for **50–500 hosts per server**. Architecture should not preclude later scale-out, but we will not pre-optimize for 10k+.

---

## 3. Core Capabilities (V1 Scope)

### 3.1 Telemetry collection (agent)
- Process lifecycle: exec, fork, exit, with full cmdline, cwd, uid/gid, parent chain.
- File events: create, write, rename, delete, chmod, chown on configurable paths.
- Network events: TCP/UDP connects, listens, DNS queries, with owning process.
- Authentication events: successful/failed logins, sudo, su, ssh session open/close.
- Kernel/module events: module load, kprobe/uprobe attach (defense-in-depth for rootkit detection).
- Container events (if Docker/containerd/runc present): container create/start/stop, image pulls.

### 3.2 Detection
- **Hybrid detection.** Rule engine runs on both agent (fast-path, low-latency for response primitives) and server (full cross-host correlation).
- **Sigma rule compatibility** as the primary rule format — we translate Sigma → internal rule AST. The compiler classifies each rule as edge-eligible or server-only per the policy in §3.6.
- YARA scanning for on-disk and in-memory artifacts (triggered by rule actions, not continuous).
- IOC matching: hash, IP, domain, filename feeds.
- MITRE ATT&CK tagging on every rule.

### 3.3 Response
- Manual (operator-triggered from console):
  - Kill process / process tree
  - Quarantine file (move to encrypted store, preserve for forensics)
  - Network isolate host (allow management traffic only)
  - Collect artifact bundle (memory, /proc snapshot, logs)
- Automated: same primitives, gated behind explicit rule-level `auto_respond: true` + operator-confirmed allowlist. **No auto-response by default.**

### 3.4 Server / management plane
- Agent enrollment with mTLS + enrollment token.
- Event ingestion, storage, search.
- Alert triage UI: timeline, **detection flow graph** (SSR, per-alert DAG of events in the attack chain), raw event inspection.
- Per-host process list (flat, searchable) + parent-chain mini-graph on-demand.
- Rule management: author, test, deploy, version.
- Host inventory: agent status, version, last seen.
- Audit log of every operator action.
- *(Deferred post-v1)* Fully-interactive live process-tree explorer.

### 3.5 Operational
- Agent self-protection: resist unprivileged kill, tamper-evident logs.
- Offline buffering: agent stores events locally when server unreachable, replays on reconnect.
- Agent updates: signed, server-pushed, with rollback.
- Backpressure: agent drops low-priority telemetry before high-priority when overloaded, and reports drops.

### 3.6 Edge vs. server rule partitioning

A rule is **edge-eligible** iff all of the following hold:

1. Inputs are **locally observable** — no fields requiring server-side enrichment, no cross-host joins.
2. If stateful, the window is **bounded per-host** with window ≤ **300s** and state ≤ **1024 entries** per (host, rule).
3. Any IOC lists referenced are ≤ **100k entries** (configurable).
4. No dependency on baselines older than agent uptime.

Everything else is **server-only**.

**Compilation.** The Sigma compiler is the sole classifier. It labels every rule `edge` or `server-only` and pushes the edge ruleset to agents on updates.

**Operator overrides.**
- Force `server-only` on an edge-eligible rule: allowed (noise control, expensive rule management).
- Force `edge` on a non-eligible rule: **compile error** with the failed predicate reported. No silent downgrade.

**Phased rollout of edge capability:**
- **Phase 1 (agent MVP):** stateless single-event rules only. Simplest possible edge engine.
- **Phase 3 (detection phase):** bounded-stateful rules on edge, small IOC feed push.
- **Phase 4+:** hybrid rules (same rule both sides), edge baselines via bloom filter / sketch.

**Immediate response coupling.** Edge-eligible rules may carry `immediate: true` response actions (kill, isolate) that fire **without** server round-trip, gated by:

- rule-level `auto_respond: true`,
- per-host allowlist of response primitives,
- the action + triggering event still being streamed to the server for audit log.

This directly serves the protection-first operating principle (§1): for teams without 24/7 SOC coverage, blocking a reverse shell before network pivot is worth the small cost to centralized review.

### 3.7 Agent extensions (post-v1, Phase 6)

Slither's core agent collects events via eBPF. Some telemetry — particularly *system state* (installed packages, kernel modules, suid binaries, authorized_keys, cron, systemd units) and periodic hunt queries — is better served by dedicated tools. Rather than re-implement that catalog, Slither defines a narrow extension interface for out-of-process collectors.

**Scope posture (deliberately minimal).**
- First-party extensions only. There is **no extension marketplace**, no public plugin SDK, no in-console install flow.
- Expected set at launch: one or two first-party extensions (osquery bridge; possibly a systemd-journal forwarder). Additional integrations added deliberately and sparingly.
- Operators source third-party binaries themselves. Slither does **not** redistribute osquery, osqueryd, or any other third-party tool.

**osquery integration specifics.**
- Slither provides the bridge extension; operators install osquery on endpoints through their own package management.
- Bridge subscribes to a curated set of osquery tables and translates results into OCSF events through the standard agent pipeline.
- Evented tables in osquery (`process_events`, `socket_events`) are disabled by default — eBPF is authoritative.
- Live-query hunt ("run this SQL on every host") is delivered through the same control channel that pushes rule updates.

---

## 4. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         ENDPOINT (Linux)                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  slither-agent (Go + eBPF)                                  │  │
│  │   ├─ collector: eBPF (libbpf/CO-RE) + ringbuf reader        │  │
│  │   ├─ enricher: process tree, container context, hashing     │  │
│  │   ├─ edge rule engine (fast-path Sigma subset)              │  │
│  │   ├─ response executor                                      │  │
│  │   ├─ local buffer (offline/backpressure)                    │  │
│  │   └─ transport: mTLS gRPC bidi stream to server             │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────┬────────────────────────────────────┘
                              │ mTLS / gRPC bidi
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                         SERVER (Go, single-node)                  │
│  ┌──────────────┐    ┌─────────────────────────────────────────┐ │
│  │ ingest API   │──▶ │ detection engine (Sigma + correlation)  │ │
│  │ (gRPC)       │    └──────────────────┬──────────────────────┘ │
│  └──────┬───────┘                       │                         │
│         │                               ▼                         │
│         ▼                        ┌────────────────┐               │
│  ┌──────────────┐                │ alerts, rules, │               │
│  │ event store  │                │ hosts, users,  │               │
│  │ (ClickHouse) │                │ audit log      │               │
│  │              │                │  (Postgres)    │               │
│  └──────────────┘                └────────────────┘               │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ mgmt API     │◀ │ auth / RBAC  │  │ web console            │  │
│  │ (HTML+gRPC)  │  │              │  │ (HTMX + templ + D2)    │  │
│  └──────────────┘  └──────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.1 Agent (locked)

- **Language: Go.** Chosen for velocity, single-binary distribution, mature gRPC/Prometheus ecosystems, and shared types with the server. eBPF bytecode is compiled C; Go userspace loads/manages it via `cilium/ebpf` (pure-Go loader, no libbpf runtime dep).
- **Linux telemetry primitive: eBPF via CO-RE.** `cilium/ebpf` for loader, BTF for CO-RE compatibility across kernels.
- **Platform: Linux only.** macOS / Windows are not in scope.

### 4.2 Server (locked, one [OPEN])

- **Language: Go.** Shared protobuf types with agent; single toolchain.
- **Transport: gRPC bidirectional streaming over mTLS.**
- **Control-plane store: Postgres.** Rules, users, hosts, alerts, audit log, enrollment tokens.
- **Event store: ClickHouse** (Apache 2.0). Columnar OLAP, purpose-built for telemetry firehose; handles 50–500 host scale target comfortably on one node; real-time queryable for live-tail UX.
- **Message bus: none in v1.** Single-node server. In-process channels between ingest and detection. If we later split nodes, NATS is the first add.

### 4.3 Web console stack (locked)

- **Transport to browser:** HTML fragments over HTTP, driven by **HTMX**. SSE (`hx-ext=sse`) for live tail.
- **Templating:** **`templ`** (type-checked Go components). No Node toolchain, no bundler on the server build path.
- **Styling:** Tailwind CSS compiled once into a static stylesheet (standalone CLI, no Node needed).
- **Graph rendering:** **D2** (Go-native, MIT) for server-rendered SVG. Detection flow graphs and parent-chain mini-graphs are computed server-side on demand, cached per-alert.
- **Vendored JS (no build step, served as static assets):**
  - `htmx.min.js` — HTMX core.
  - `svg-pan-zoom` (~10 KB) — pan/zoom on rendered SVG graphs.
  - **Monaco (vanilla, not the React wrapper)** — Sigma YAML rule editor. Click-to-validate loop against server `/rules/compile` endpoint (not live squigglies — accepted UX trade-off for simplicity).
  - **uPlot** (~40 KB) — timeline charts.
- **Interaction pattern:** SVG graph nodes carry `hx-get` attributes; clicks load detail HTML fragments into a side panel.
- **No client-side framework.** No React, no Vue, no Svelte. Alpine.js permitted for small localized sprinkles if genuinely needed, but not a dependency we lean on.

### 4.4 Extension interface (sketch — full design in Phase 6 planning)

- **Transport:** unix domain socket, protobuf framing. Same schema types as agent↔server gRPC where they overlap.
- **Extensions are separate processes.** Agent does not dynamically load code. An extension crash, leak, or hang cannot take down the agent.
- **Launched by the agent**, supervised with restart + exponential backoff; logs routed through the agent's log pipeline.
- **Config-declared, signature-checked.** Every extension is listed in agent config with an expected binary path and signing identity. Unknown or unsigned extensions are refused.
- **Capability-gated.** Each extension declares the OCSF event classes it may emit and the control messages it may handle. Agent enforces.
- **Backpressure-aware.** Extensions respect the same drop-low-priority policy as the core collector when the agent is overloaded.
- **No shell-out from extensions into privileged APIs.** All privileged operations (response actions, eBPF map writes) stay in the core agent; extensions can *request* them via the control channel but cannot execute them directly.

Deliberately **not** included: dynamic discovery, auto-update, remote install, third-party extension registry, user-uploaded extensions via console. Keeping the surface small is the point.

### 4.5 Deployment

- **Single-node server** is the only supported topology in v1 (matches 50–500 host scale target).
- **Preferred install:** `docker compose up` reference deployment with the server, Postgres, and event store.
- **Acceptable install:** multi-step (systemd unit for server, separate DB setup) for operators who prefer bare-metal. Docs cover both; compose is the first-class path.
- **Agent install:** single static binary + systemd unit + enrollment token. `.deb` / `.rpm` packaging post-MVP.
- **No SaaS.** Self-hosted only.

---

## 5. Data Model

### 5.1 Canonical event format

**OCSF (Open Cybersecurity Schema Framework) is the canonical on-the-wire and at-rest format.** We emit OCSF-conformant events from the agent; internal code works against OCSF types directly rather than maintaining a parallel native schema.

Rationale:
- OCSF has strong and growing adoption among SIEM and data-lake vendors; consumers can ingest slither events with zero translation.
- Removes a whole class of schema-drift bugs between "our schema" and "the OCSF mapping we publish."
- OCSF is versioned; we pin to a specific OCSF version per release and migrate deliberately.

Trade-off accepted: OCSF classes are sometimes more verbose than a minimal native schema would be, and its versioning will impose migration work. We take this as the cost of interoperability.

OCSF event classes we'll use in v1 (non-exhaustive):
- `process_activity` (1007) — process.exec/exit
- `file_system_activity` (1001)
- `network_activity` (4001) / `dns_activity` (4003)
- `authentication` (3002)
- `kernel_activity` (1003)
- `container_lifecycle` (when containerd/docker present)
- `detection_finding` (2004) for alerts

### 5.2 Agent-added context

On top of OCSF, every event carries:
- `host_id` (UUID, agent-assigned at enrollment, stable across reboots)
- `agent_version` (semver)
- `event_id` (UUID, agent-assigned)
- `observable_time` vs. `collected_time` (event timestamp vs. agent-stamp) to detect clock skew

---

## 6. Security Model

- Agent runs as root — unavoidable for kernel telemetry. This means:
  - Agent binary and config are integrity-protected (signed, verified on load).
  - Agent-to-server auth uses mTLS with per-host certs, rotatable.
  - Enrollment token is single-use, short-lived.
  - Server admin console requires auth; RBAC from v1 (roles: viewer, analyst, admin).
  - All response actions are audit-logged with operator identity.
- Threat model explicitly includes: an attacker with local root trying to blind/tamper with the agent. We can't fully defeat that on Linux without a TPM-based anchor, but we can make it noisy — tamper-evident logs shipped before kill, heartbeat timeouts alert, etc.
- Supply chain: reproducible builds, SBOM, signed releases (cosign / sigstore).

---

## 7. Roadmap

**Phase 0 — Foundations**
- Repo scaffolding (Go workspaces: `agent/`, `server/`, `proto/`, `deploy/`).
- CI: build, test, lint, `go vet`, `govulncheck`, DCO check.
- OCSF event schema pinning + codegen.
- gRPC wire protocol spec (versioned).

**Phase 1 — Linux agent MVP (single-host, no server)**
- eBPF collector for process + file + net events.
- Local JSON/stdout output.
- Basic YAML rule matcher (Sigma subset on edge).

**Phase 2 — Server MVP**
- Ingestion API, event store, web console (HTMX + templ + Tailwind) with live tail (SSE) + search.
- Agent enrollment flow (mTLS, tokens).
- Flat per-host process list + on-demand parent-chain mini-graph (SSR via D2).
- `docker compose` reference deploy.

**Phase 3 — Detection**
- Full Sigma rule compiler (edge + server partitioning per §3.6).
- Alert lifecycle (new → triaged → closed).
- Detection flow graph (SSR via D2) on alerts.
- Bounded-stateful rules on edge; small IOC feed push to agents.
- Hybrid detection: edge rules push alerts directly; server rules run on stream.

**Phase 4 — Response**
- Manual response primitives (kill, isolate, quarantine, collect).
- Audit log.
- Opt-in `auto_respond` + `immediate: true` gating per §3.6.

**Phase 5 — Hardening**
- Agent self-protection, tamper evidence.
- Offline buffering, backpressure.
- Reproducible builds, signed releases, SBOM.

**Phase 6 — Extensions & console expansion**
- Agent extension interface (unix socket, protobuf, signature + capability gated, supervised).
- Reference osquery bridge extension (operator-installed osqueryd).
- Live-query hunt workflow: server-dispatched queries across hosts, aggregated results in console.
- Forensic snapshot-on-alert: alert creation optionally triggers a state capture via enabled extensions.
- Fully-interactive live process-tree explorer (deferred from v1).
- Richer search, saved queries, dashboards.

**Phase 7 — Platform expansion (demand-driven)**
- macOS agent (if funding for Apple dev program materializes).
- Windows agent (if driver signing path materializes).

---

## 8. Project Governance

- **License:** MIT (already in repo).
- **Sustainability model:** Fully FOSS. No paid tier or hosted SaaS planned.
- **Contributions:** DCO (`Signed-off-by:` trailer), enforced via GitHub Actions.
- **Code of conduct:** deferred — not adding one at this stage.
- **Security disclosure:** `SECURITY.md` pointing to GitHub private vulnerability reporting.
- **Release cadence:** TBD after MVP ships.

---

## 9. Decisions & Remaining Open Items

### 9.1 Locked decisions (from review round 1)

| # | Decision | Choice |
|---|---|---|
| 1 | Platform priority | Linux-only for v1 |
| 2 | Agent language | Go (+ eBPF C for kernel-side programs) |
| 3 | Server language | Go |
| 4 | Scale target | 50–500 hosts per server |
| 5 | Deployment preference | `docker compose` primary; multi-step supported |
| 6 | Rule format | Sigma (primary) |
| 7 | Canonical event schema | OCSF |
| 8 | Detection topology | Hybrid (edge + server) |
| 9 | Commercial model | Fully FOSS |
| 10 | Scope exclusions | None additional |
| 11 | Linux telemetry primitive | eBPF via CO-RE (`cilium/ebpf`) |
| 12 | Transport | gRPC bidi streams over mTLS |
| 13 | Control-plane store | Postgres |
| 14 | Message bus | None (single-node) |
| 15 | CLA vs. DCO | DCO |
| 16 | Code of conduct | Deferred |
| 17 | Security disclosure | GitHub private vuln reporting + `SECURITY.md` |
| 18 | Event store | ClickHouse (Apache 2.0) |
| 19 | Edge-eligibility policy | 4-predicate gate: local-observable, bounded-window (≤300s, ≤1024 entries), IOC feeds ≤100k, no long-baseline deps |
| 20 | Edge engine scope per phase | Phase 1 stateless-only; Phase 3 bounded-stateful; Phase 4+ hybrid & baselines |
| 21 | Operator overrides | Force server-only = allowed; force edge on non-eligible = compile error |
| 22 | Immediate response at edge | Opt-in via `immediate: true` + `auto_respond: true` + per-host allowlist; action still streamed to server audit log |
| 23 | Operating principle | Protection-first — early blocking prioritized over pristine audit trail; designed for teams without 24/7 SOC |
| 24 | Web console stack | HTMX + `templ` + Tailwind; vendored JS (HTMX core, svg-pan-zoom, Monaco vanilla, uPlot); no SPA framework |
| 25 | Alert graph rendering | Server-side SVG via **D2** (Go-native, MIT); cached per alert |
| 26 | v1 process-tree scope | **No** interactive live explorer. Replaced with flat per-host process list + on-demand SSR parent-chain mini-graph. Full explorer deferred to Phase 6. |
| 27 | Rule editor UX trade-off | Monaco vanilla + click-to-validate against `/rules/compile`; no live-squiggly loop (accepted for stack simplicity) |
| 28 | Agent extensions | Deliberately minimal interface for a small set of first-party extensions. No marketplace, no public SDK, no dynamic loading. Phase 6. |
| 29 | osquery integration | First-party bridge extension, opt-in. Slither does **not** redistribute osquery; operator installs it on endpoints via their own package management. Phase 6. |
| 30 | Extension execution model | Separate processes over unix socket (protobuf). Config-declared, signature-checked, capability-gated, supervised. Cannot execute privileged operations directly. |

### 9.2 Remaining [OPEN] items

*(None — all shaping decisions resolved. Ready for implementation planning.)*
