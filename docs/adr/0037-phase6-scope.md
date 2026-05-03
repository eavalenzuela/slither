# ADR-0037: Phase 6 scope + sequencing

**Status:** accepted

**Date:** 2026-05-03

## Context

Phases 0–5 closed end-to-end with cloud-validated exit criteria
(`docs/phase5-validation.md`, 2026-05-02). The agent collects + detects +
responds + defends itself; the server ingests + dispatches + audits +
packages a signed release surface; the console drives every operator
workflow today. What's missing is the breadth promised in the original
project shape (PROJECT.md §3.7 / §7) but deferred from v1:

- **No extension surface.** The agent is a single binary; capability
  expansion requires recompiling + reshipping the agent. PROJECT.md
  §3.7 promised a small first-party extension model precisely so the
  core stays focused on eBPF + Sigma + the response surface.
- **No reference extension.** osquery is the obvious first integration —
  fills the LSM/syscall-arg gaps eBPF can't safely cover, and operators
  almost always already run it. We need a working bridge, not just an
  interface.
- **Console gaps deferred from v1.** ADR-0024 / PROJECT.md §3.6 deferred
  the fully-interactive process-tree explorer in favour of the SSR mini-
  graph (#65). Saved queries, dashboards, and richer event search were
  also deferred. Phase 6 is when those land.
- **Live-query hunt.** Server-dispatched ad-hoc queries across hosts,
  aggregated in the console. Non-trivial — needs the extension interface
  (osquery does the actual querying), the dispatch path on the server,
  and the aggregation UI.
- **Snapshot-on-alert.** Operators want a one-shot state capture (process
  tree, network state, on-disk artefacts) attached to the alert at fire
  time, via whatever extensions the host has enabled. Today
  `collect_artifacts` is a manual response action; this makes it
  automatic and rule-driven.
- **Console auth backends.** §10.7 parked SSO/OIDC for "Phase 5 or 6".
  Phase 5 didn't take it. Phase 6 does.
- **Phase 5 follow-ups activated.** §10.5 (rule-pack signing) was parked
  to Phase 6 by ADR-0035 because the right signing infra is the *extension*
  signing infra — same trust root, same verification path. §10.2 Phase 6+
  piece (TPM-sealed cert variant) and the keyring-strategy decision from
  Gap A (Phase 5 #103 validation) belong here too.
- **Distribution polish.** Phase 5 #93 shipped a single-arch amd64 OCI
  build with daemonset YAML; multi-arch buildx + live k8s cluster
  validation were explicitly deferred to "first v-tag release" — i.e.
  Phase 6.

This ADR locks Phase 6's shape so the §8 task breakdown can proceed in
parallel. Subsequent ADRs (0038+) will document the specific protocol +
trust + UI choices as they land.

## Decision

### Phase 6 is "extensions + console expansion", not v1.5

Phase 6 ships two real new operator-facing surfaces:

1. **A first-party extension model** — small, opinionated, signature- and
   capability-gated. Used in Phase 6 by exactly one shipped extension
   (osquery bridge). Designed to host two or three more without rework
   (auditd bridge, FIM, canary) but explicitly **not** a marketplace and
   explicitly **not** a public SDK.
2. **Console expansion** — saved queries, dashboards, the live process-
   tree explorer, SSO. The console gets *richer*; the agent gets *more
   sources*. Detection content (new rules) and response content (new
   actions) are out of scope unless they're a direct consequence of an
   extension landing.

The action surface stays at Phase 4's six-action freeze. New actions
still need an ADR + an additive enum bump per §2.4.

### Extension interface: opinionated, narrow, in-tree

| Property | Phase 6 |
|----------|---------|
| Transport | Unix domain socket per extension, agent-side abstract namespace path. No TCP, no shared memory, no fifos. |
| Framing | Length-delimited protobuf. New `proto/slither/v1/extension.proto` namespace; **agent.proto and control.proto stay frozen** (extensions never touch the server-facing wire). |
| Discovery | Operator-declared in `agent.yaml` `extensions:` list; one entry per extension binary path + signature path. No autodiscovery. |
| Trust | Each extension binary is cosign-signed using the same keyless OIDC chain as the slither release artefacts (Phase 5 #91). Agent verifies signature on every spawn — no signature, no spawn. |
| Capabilities | Per-extension capability declaration (a small enum: `OCSFEmit`, `LiveQueryRespond`, `SnapshotProvide`). Agent enforces — an extension that didn't declare `OCSFEmit` cannot push events. |
| Lifecycle | Agent supervises: spawn, monitor stdout/stderr, restart with exponential backoff (1s → 60s ±25% jitter, mirroring #35), kill on agent shutdown. One stuck extension cannot wedge the agent's BPF or detection paths. |
| Resource bounds | Per-extension RSS cap (default 256 MiB, configurable) and CPU cgroup share. Bounded out-of-the-box; no operator surprise. |
| OCSF passthrough | Extensions emit OCSF events; agent stamps `device.uid` + `time` + audit fields and forwards on the existing gRPC sink. The bus and ClickHouse schema don't grow new tables — extension events ride the existing OCSF classes. |
| Public SDK | **Explicit non-goal.** First-party only in Phase 6. The proto + Go scaffolding sit at `proto/slither/v1/extension.proto` + `pkg/extsdk/` so first-party extensions share the plumbing, but no published Go module, no language bindings beyond Go. |
| Dynamic loading | **Explicit non-goal.** Extensions are separate binaries spawned by the agent, not Go plugins / dlopen / WASM modules. |

### Extension binary distribution (closes §10.6)

| Mode | Phase 6 |
|------|---------|
| Operator-installed | ✅ default. Operator drops the signed binary in `/usr/lib/slither/extensions/`, declares the path in `agent.yaml`, agent verifies + spawns. Mirrors how operators install osqueryd today (Slither doesn't redistribute osquery — see ADR-0028). |
| Server-pushed | ❌ Phase 6+. Adds a binary-distribution channel that needs versioning + rollback semantics + integrity-against-MITM-on-control-channel concerns we don't want to design before we've operated one extension in the wild. |
| Bundled in agent package | ❌. The whole point of the extension model is decoupling the release cadence. If a bridge ships in the agent's own .deb, we've just added complexity for no decoupling benefit. |

### Rule-pack signing (closes §10.5)

Folded into the extension-signing infra. Same cosign chain, same
verification path. Concretely: rules pushed over the control channel
remain unsigned (mTLS + server-trust covers the in-band threat); rules
distributed *out-of-band* — operator pulling a rule pack from a public
or partner repo, then ingesting via `slither-db insert-rule` — get a
detached cosign signature that the CLI verifies before insert.

This is the smallest signing scope that actually matters: in-band rule
push trusts the server, out-of-band rule import trusts a signature.

### osquery bridge as the reference extension

Reference extension lives in-tree at `extensions/osquery/`. Behaviour:

- Subscribes to a curated set of osquery tables (process_events,
  socket_events, file_events, listening_ports, kernel_modules, ssh_keys,
  authorized_keys — the obvious LSM-shaped gaps).
- Per-table OCSF mapper in the bridge — the agent does not learn osquery
  schema. Mappers are tested against fixtures.
- Emits via `OCSFEmit`. Live-query response via `LiveQueryRespond`.
- Operator installs osqueryd themselves (ADR-0028 holds — Slither doesn't
  bundle osquery).

Phase 6 does **not** ship a second extension. Phase 7+ may ship
auditd-bridge / FIM / canary; the Phase 6 interface is designed assuming
those are coming, but only osquery is a Phase 6 deliverable.

### Live-query hunt

Server-dispatched ad-hoc queries, aggregated in the console:

- New `HuntQuery` server message (additive `slither.v1` bump on
  `ServerMessage` per §2.4).
- Hub fans out to subscribed sessions; agent forwards to the
  declared `LiveQueryRespond` extension (osquery bridge, in v1).
- Bridge runs the query, responds with rows; agent wraps in
  `HuntResult` and ships back over the existing Session stream.
- Server aggregates per `hunt_id`, surfaces in console at
  `/hunt/{id}` with pagination + CSV export.
- Hard cap on rows per host (default 10k) + per-hunt timeout (default
  60s) — runaway queries don't melt the fleet.

Authorisation: `analyst` role can dispatch hunts; `viewer` cannot. Hunt
dispatch is audited like response actions (`hunts` table, full history).

### Snapshot-on-alert

Optional per-rule field `slither.snapshot: true`. When the rule fires,
the agent's auto-respond path (#83) submits a synthetic
`SnapshotRequest` to every extension declaring `SnapshotProvide`.
Snapshot artefacts ride the same `collect_artifacts` upload path
(Phase 4 #81) — landed under `/var/lib/slither/artefacts/<alert_id>/`,
visible from the alert detail page.

Snapshot extensions in Phase 6: **none shipped.** The infra lands; the
osquery bridge is a candidate snapshot provider but is not wired to
provide one in Phase 6 (osquery's snapshot tables are a Phase 7
exercise). The point of shipping the infra empty is to lock the wire
and the alert-detail UX without coupling rollout to a second extension.

### Console expansion

| Surface | Phase 6 | Phase 7+ |
|---------|---------|----------|
| Live process-tree explorer (replaces SSR mini-graph #65 in the alert detail UI; mini-graph stays as fallback) | ✅ | — |
| Saved queries (`/events` + `/alerts` filter combinations bookmarked per-user) | ✅ | — |
| Dashboards (operator-authored layout of saved queries + counters; per-user) | ✅ | shared/team dashboards |
| Search refinements (richer query language on `/events`, query history) | ✅ | — |
| SSO (OIDC) | ✅ closes §10.7 | SAML, LDAP |
| Reopen alert (`closed → in_progress` transition) | ✅ small UX nit deferred from Phase 3 #61 | — |

OIDC scope is intentionally narrow: discover via well-known URL,
auth-code flow with PKCE, role mapping via configurable claim → role
table, no group sync, no SCIM. SSO sits *alongside* local users, not
as a replacement (operator can still log in as the bootstrap admin if
the IdP is down).

### Server-side tamper-chain cross-check

Phase 5 #95 tagged this as "Phase 6+". It lands here as a server-side
periodic compare: the server walks each host's `log.chain` records (sent
opportunistically over the existing Session stream as a new
`ChainSummary` ClientMessage) and cross-references against the
equivalent CH `response_actions` + `detection_findings` rows. Mismatch
fires a `ChainMismatch` audit event with severity 4 (high — agent state
diverges from server state, suggests local tamper or replay).

Wire: additive `ClientMessage.chain_summary` field. Audit-only — no new
alert class, no new response action. Operators see the chain-mismatch
in the audit log and at `/hosts/{id}/chain-status` in the console.

### Keystore Gap A (Phase 5 #103 follow-up)

Phase 5 #98 shipped kernel-keyring storage with file fallback. Validation
exposed Gap A — the chosen keyring type (`KEY_SPEC_SESSION_KEYRING`) is
per-PAM-session, not durable across the enroll subprocess → agent
service boundary. The hot-fix made keyring writes best-effort additive;
the durable cert store is files.

Phase 6 chooses one of:

| Option | Trade |
|--------|-------|
| (a) Drop kernel-keyring storage entirely; files-only | Smallest code surface; loses the in-RAM-only privacy property of the keyring |
| (b) `KEY_SPEC_USER_KEYRING` (`@u`) — per-uid persistent | Survives session boundary; still in RAM; matches typical EDR-ish "key in keyring" expectation. Available on every kernel ≥ 3.5. |
| (c) Systemd helper unit pre-populating keys at boot via `KeyringMode=shared` | Most operationally complex; requires a second unit |

ADR-0038 (drafted as part of #117) records the chosen strategy.

### TPM-sealed cert variant (Phase 6+ piece of §10.2)

Lands behind `agent.keystore.tpm: true` opt-in. Uses TPM 2.0 PCR-bound
sealing — cert key sealed against PCR 7 (Secure Boot state); host that
boots un-Secure-Boot can't unseal. Falls back to the chosen Gap A
strategy when TPM is absent or `/dev/tpmrm0` is unreadable.

Operationally narrow: container hosts skip it (no TPM); bare-metal
hosts with TPM 2.0 can opt in. **Not the default** — the configuration
matrix gets large fast and the ROI without measured boot is small.

### Multi-arch + live k8s validation (Phase 5 #93 carry-over)

Phase 5 #93 shipped single-arch amd64 OCI + daemonset YAML; multi-arch
buildx and live k8s cluster validation were deferred to first v-tag
release. Phase 6 includes a numbered task to do both — buildx for
amd64 + arm64, live cluster bring-up against k3s on a Phase 6
validation VM, daemonset enrolment + event-flow + revoke-cycle smoke.

### Default-detect-only carries forward

Per ADR-0034: every freshly-enrolled host lands at all-false for
response policy. Phase 6 doesn't change that. New extensions
inherit the same posture — capability declarations are operator-scoped,
not auto-granted.

## Consequences

- **Phase 6 is end-state for v1 console.** After this phase, the
  console covers every workflow PROJECT.md described as "v1" — including
  the live process-tree explorer that ADR-0024 deferred. Phase 7+ console
  work is demand-driven (custom plugins, theming, multi-tenancy).
- **Extension model is real but narrow.** First-party only, signed by
  the project, in-tree code, opinionated capabilities. We get the
  decoupling benefit (osquery's release cadence, our release cadence,
  no entanglement) without the surface area cost of a public SDK.
- **§10 deferred-questions table closes for v1.** §10.5 (rule signing),
  §10.6 (extension distribution), §10.7 (console SSO) all resolved here.
  §10.2's TPM piece resolves here. Only §10.3 (CH schema evolution under
  OCSF version bumps) remains open — we have the harness (Phase 5 #99),
  we don't yet have a forced bump.
- **Wire grows additively.** New `slither.v1` fields:
  `ServerMessage.hunt_query`, `ClientMessage.hunt_result`,
  `ClientMessage.chain_summary`. The extension wire (`extension.proto`)
  is a *new* namespace, not a v1 bump. ADR-0011's wire-freeze invariant
  on `slither.v1` holds (additive only).
- **Snapshot-on-alert lands empty.** The wire and UX ship; no extension
  in Phase 6 actually provides snapshots. This is deliberate — locks the
  shape so Phase 7's auditd / FIM / canary additions slot in cleanly.
- **Phase 7 is well-prepared.** macOS / Windows agents have a precedent
  for "different platform, same wire, additional extensions"; the
  extension model is the natural seam for those.

## References

- ADR-0011 (transport gRPC mTLS — wire-freeze invariant)
- ADR-0024 (alert flow-graph — process-tree explorer deferral)
- ADR-0028 (osquery optional, not bundled)
- ADR-0034 (response model + auth boundary — default-detect-only)
- ADR-0035 (Phase 5 scope; deferred §10.5 rule-pack signing here, deferred TPM here)
- ADR-0036 (stateful cold-start hybrid declined)
- IMPLEMENTATION.md §8 (Phase 6 outline) + §8.1 (task breakdown — written as part of #104)
- IMPLEMENTATION.md §10.5 / §10.6 / §10.7 (deferred technical questions resolved here)
- PROJECT.md §3.7 (Agent extensions outline) + §7 (Phase 6 bullets)
- `docs/phase5-validation.md` (Gap A keyring carry-over)
