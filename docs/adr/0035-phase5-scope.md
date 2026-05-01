# ADR-0035: Phase 5 scope + sequencing

**Status:** accepted

**Date:** 2026-05-01

## Context

Phases 0–4 closed end-to-end with cloud-validated exit criteria. The
agent collects + detects + responds, the server ingests + dispatches +
audits, the console drives every operator workflow. What's missing is
everything between "works on a freshly-rsynced source tree on a cloud
VM" and "operators can confidently run this in production":

- **Distribution.** No deb/rpm packages, no OCI images, no signed
  releases, no SBOM. Phase 4 #86 caught the deploy-posture cost
  (Gap A: sysctl drop-in not provisioned at install time) and the
  Phase 3 close required a manual rsync + `docker compose build`.
- **Self-protection.** Agent runs root, holds kill/net_admin/dac
  capabilities, but has no `PR_SET_DUMPABLE=0`, no cap-drop after
  BPF load, no lockdown on `/var/lib/slither` or `/etc/slither`. A
  local-root attacker on a target host can inspect / tamper with the
  EDR.
- **Resilience.** No offline buffering — agent disconnect drops events
  on the floor instead of replaying on reconnect. No end-to-end
  backpressure — when the server's CH writer falls behind, agents
  don't slow down or shed low-value classes.
- **Operational debt from Phase 4.** Four carry-over gaps (detect
  engine doesn't refresh on rule change, auto-respond emits dup rows,
  `hosts.agent_version` not populated, sysctl drop-in install posture)
  that are correctness/UX papercuts, not architectural decisions.
- **Deferred technical questions activated.** §10.2 (cert storage),
  §10.3 (CH migration harness), §10.5 (rule signing — partially)
  all said "Phase 5".

This ADR locks Phase 5's shape so the §7.1 task breakdown can
proceed in parallel. Subsequent ADRs (0036+) will document the
specific runtime + crypto choices as they land.

## Decision

### Phase 5 is "production-readiness", not feature scope

Phase 5 ships **zero new operator-facing capabilities**. Every line
of code is in service of one of:
- distribution (package, image, sign)
- self-protection (the agent defends itself from local tampering)
- resilience (no event loss on disconnect; no thundering-herd on
  reconnect; no silent drops under server backpressure)
- closing deferred technical questions (cert storage, CH migration)

New detection capability, new response actions, new console pages
all belong to Phase 6+ unless they're a direct consequence of a
Phase 5 hardening decision.

### Distribution surface

| Artefact | Phase 5 | Phase 6+ |
|----------|---------|----------|
| `slither-agent` binary | ✅ signed via cosign keyless | — |
| `slither-server` binary | ✅ signed | — |
| `.deb` (Debian/Ubuntu) | ✅ via nfpm; postinst handles sysctl drop-in + unit + agent.yaml.sample | — |
| `.rpm` (RHEL family) | ✅ via nfpm; postinst symmetric to deb | — |
| OCI image (agent) | ✅ multi-arch (amd64 + arm64); k8s daemonset shape via cap-only, no `privileged: true` | TPM/attestation-aware variant |
| OCI image (server) | ✅ productionised distroless + signed | — |
| SBOM (syft) | ✅ attached to every release artefact | — |

Container packaging is in scope for v1 because k8s daemonset
deployments are a real distribution shape — running on bare-metal
hosts via deb/rpm is one path; running as a daemonset against a
managed control plane is the other. Both deploy `slither-agent`;
both must be first-class.

### Signing scope

Cosign keyless via GitHub OIDC for **artefact distribution** —
binaries, deb/rpm packages, OCI images. Verification documented in
`docs/install.md` for both `cosign verify` and the deb/rpm signing
keyring case.

**Rule-pack signing (closing §10.5) is parked for Phase 6.** Rules
already flow over mTLS-trusted server-push (#39 / Hub.Refresh); the
signature would only protect the rule definition's integrity if an
attacker compromised the postgres write path, in which case they
already have signing-key access. Signing is the right move once an
external rule-pack distribution channel exists (cross-org rule
sharing, marketplace, etc.) — that's a Phase 6+ scope.

### Self-protection bar

Agent self-protection is bounded by what's actionable without
kernel modules:

| Surface | Phase 5 | Phase 6+ |
|---------|---------|----------|
| `PR_SET_DUMPABLE=0` on agent startup | ✅ | — |
| Drop unused caps post-BPF-load via `prctl(PR_CAP_AMBIENT_LOWER)` | ✅ | — |
| `/var/lib/slither` + `/etc/slither` mode 0700 root:root, agent state files immutable where supported (`chattr +i`) | ✅ | — |
| Tamper-evident logs (hash-chain over response_actions and detection findings, flushed before shutdown, verified on next boot) | ✅ | — |
| Anti-debug: refuse to run if `ptrace` attached at startup | ✅ | — |
| Kernel-keyring storage for client cert (closes §10.2) | ✅ | TPM-sealed variant |
| Boot integrity (TPM measured boot) | — | ✅ Phase 6+ |
| Agent process hidden from `ps` via `kthread`-style trickery | — | explicit non-goal — operators must always be able to see the agent |

### Resilience bar

| Surface | Spec |
|---------|------|
| Offline buffering | On-disk ringbuffer at `/var/lib/slither/buffer/`. **6 h cap** at typical fleet event rates (~1k events/s/host) → **256 MiB default**, operator-tunable. Oldest-wins drop. Bounded resume on reconnect — events older than the cap are dropped from the head to avoid backfill storms. |
| End-to-end backpressure | Two-direction signal. **Up:** when agent's `DropsOutput` > 0 over a 30 s window, raise sampling on low-priority classes (NetworkActivity for non-IOC events first; FileSystemActivity for non-rule paths second). **Down:** when server's CH writer reports subscriber drops, broadcast a `BackpressureSignal` over the control channel (additive wire bump in `slither.v1`). Agents respect the signal until cleared. |
| Replay protocol | Agent buffers Envelopes with wall-clock timestamps; on reconnect, opens a Session and streams buffered Envelopes ahead of fresh ones. Server detects via Envelope's `observed_at < (now - 1m)` and routes to a replay path that bypasses live SSE subscribers (replay clutters live-tail) but lands in CH normally. |

The 6 h cap is a deliberate compromise: longer windows force
operators to size disk per-host; shorter windows make a routine
overnight server outage drop a workday's worth of telemetry. 6 h
covers AWS region-failover-shaped outages and deliberate maintenance
windows; longer disconnections are an alerting concern not a
buffering one.

### Cert storage upgrade (closes §10.2)

Kernel keyring (`add_key(2)` + `keyctl(2)`) is the default for
agent-side client cert + key storage post-enrollment. Falls back to
`/etc/slither/` files when keyring is unavailable (containers
without `/proc/keys`, kernels < 5.4, hosts where the keyring is
namespaced unhelpfully). Rotated certs (Phase 6+ work) update both
the keyring and the file fallback; runtime always prefers keyring.

TPM-sealed storage stays Phase 6+ — TPM availability is the
gating problem, not the API surface.

### CH migration harness (closes §10.3)

Goose-style forward + down migrations with a `schema_version` table
in CH. Tooling: `slither-ch migrate-up`, `slither-ch migrate-down`,
`slither-ch status`, with a `--dry-run` flag that prints the SQL
without applying. Symmetric to the existing pg path. **Required
before any OCSF version bump** — Phase 5 ships the harness; Phase 5
does NOT bump OCSF.

### Phase 4 carry-over batched as a single early task

Four operational papercuts batched into **#88** rather than scattered
across Phase 5 numbered tasks:

1. `detect.Engine` doesn't refresh on rule change — subscribe to
   `rules_changed` NOTIFY like `control.Hub` does (re-uses #39's
   plumbing).
2. Auto-respond emits two `response_actions` rows per spawn — dedupe
   in the immediate-fire path before submitting.
3. `hosts.agent_version` not populated despite agents reporting it on
   heartbeat — server-side handler write.
4. `deploy/sysctl.d/99-slither.conf` install posture preview — the
   real fix is the package postinst (#92), but a documented manual
   install step closes the immediate gap.

### Quarantine vs hardening posture (Gap B from #86)

Decision: **bind-mount the host root as a read-write namespace for
the quarantine handler only.** The agent's main systemd unit keeps
`PrivateTmp=yes` + `ProtectSystem=strict` for defense-in-depth on
the BPF / detection paths. Quarantine moves to a separate
sub-process spawned with a relaxed namespace (no PrivateTmp,
RW-ProtectSystem) that handles only `quarantine_file` /
`unquarantine`. The sub-process is short-lived (one action), drops
all caps except `CAP_DAC_OVERRIDE` + `CAP_DAC_READ_SEARCH`, and is
audited via the existing `response_actions` chain.

This keeps the BPF + detection blast radius small while letting
quarantine do its job on `/tmp/`, `/opt/`, and `/var/spool/` — the
realistic malware drop locations.

### Threat model doc

`docs/threat-model.md` is the artefact (no separate ADR). STRIDE
per surface: ingest path, control plane, console, agent runtime,
package distribution. Captures what slither defends against
(local-root tampering with the EDR, opportunistic malware,
unauthorized response action), what it explicitly does **not**
defend against (kernel-mode rootkits, supply-chain compromise of
the build system itself, physical access to enrolled hosts), and
residual risks. Lands toward the end of Phase 5 (#102) so it
describes what shipped.

### §59 stateful cold-start hybrid: decision belongs in Phase 5

Phase 3 parked the cold-start hybrid (always-on with
`max_cold_start_lookback` cap, default ~1 h) pending production CH
query telemetry. Phase 4 produced none. Phase 5's exit-gate cloud
run gives us the data — operate the fleet for a sustained window,
sample CH `system.query_log`, decide whether the hybrid is worth
the complexity. Either ship it in Phase 5 (#101) or close as
"won't-do" with the rationale recorded.

### Action surface stays frozen

Phase 4's six-action freeze (kill_process, kill_tree, quarantine_file,
isolate_host, unisolate_host, collect_artifacts) holds through
Phase 5. New actions still need an ADR + an additive enum bump per
§2.4.

## Consequences

- **Phase 5 is end-state for distribution.** After this phase, an
  operator should be able to `apt install slither-agent` (or pull the
  OCI image) on a fresh host and have a fully functional, signed,
  capability-bounded agent reporting to a server.
- **Self-protection bar is honest.** We document what we do and don't
  defend against — including kernel rootkits and supply-chain
  attacks. No marketing claims about "tamper-proof" or "kernel-level
  trust" — neither is true at this surface.
- **Resilience is per-surface, not blanket.** 6 h offline buffering
  + class-priority-aware backpressure + replay-bypassing-live-tail
  is opinionated. Operators with longer-disconnection-tolerance
  needs will need to cap-up the buffer; operators with stricter
  always-fresh requirements can set the buffer to zero and accept
  drops on disconnect.
- **No new operator capability.** Phase 5 should feel like a quiet
  release for end-users. Internal-facing changes (packaging, signing,
  reproducible builds) are the headline features, and those land in
  release notes + threat-model doc.
- **Phase 6 unblocks naturally.** With distribution + self-protection
  shipped, Phase 6 (extensions, osquery bridge, dashboards) builds on
  a stable foundation.

## References

- ADR-0010 (kernel floor)
- ADR-0011 (transport gRPC mTLS)
- ADR-0021 (immediate-response opt-in)
- ADR-0034 (response model + auth boundary)
- IMPLEMENTATION.md §7 (Phase 5 outline) + §7.1 (task breakdown — written as part of #87)
- IMPLEMENTATION.md §10.2 / §10.3 / §10.5 (deferred technical questions)
