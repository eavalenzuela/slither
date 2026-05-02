# Slither — threat model

**Status:** v1, accurate as of Phase 5 close (Phase 5 #102).

This doc enumerates the security properties slither does and does **not**
provide. It is descriptive, not aspirational. Every claim here is
backed by code that shipped or by an explicit gap we acknowledge.

The audience is two-fold: operators evaluating whether slither fits
their threat profile, and security reviewers checking that what we
claim matches what we built. If a property below conflicts with what
the code does, the code is right and this doc is wrong — file an
issue.

## Scope

**In scope.** Linux endpoint telemetry + detection + response running
under operator-controlled hosts (bare-metal, VMs, k8s daemonsets).
Server is single-replica per ADR-0035; multi-replica HA is Phase 6+.

**Explicit non-goals.** Slither is not a kernel-rootkit detector, not
a network IPS, not a SIEM (it ships events at OCSF; downstream SIEMs
consume them), not a vulnerability scanner. The agent runs in
userspace with capability-bounded privileges; it cannot detect or
defend against attackers who already have ring-0 execution.

## Trust model overview

Three trust boundaries:

1. **Agent ↔ Server.** mTLS-pinned. Agent cert is enrolled once via a
   short-lived operator token (Phase 2 #34); server cert is pinned by
   the agent at enrollment time or via `--ca-cert`. Either side can
   refuse the other's cert at any reconnect.
2. **Server ↔ Console operator.** Argon2id password (Phase 2 #41) +
   session cookie (scs/pgxstore). Role-based: viewer / analyst / admin.
3. **Operator ↔ Build system.** Reproducible builds (Phase 5 #89) +
   cosign keyless signing (Phase 5 #91). Operators verify signatures
   before installing.

Anything inside a single boundary is trusted by anything else inside
that boundary. We don't try to defend a compromised server from
itself, nor a compromised agent from itself. The boundaries are
where attestation lives.

## Surface 1 — Ingest path (agent → server)

The agent encodes OCSF events into gRPC `Envelope`s and ships them
over a single Session stream. Server reads, stamps with the trusted
peer-cert host_id, and fans out to ClickHouse + the rule engine.

| STRIDE | Threat | Status |
|--------|--------|--------|
| **Spoofing** | Attacker forges an agent identity to inject events as a real host | **Defended.** mTLS with a per-host cert. Server reads `host_id` from the verified peer cert's CN, *overwriting* whatever the wire claimed (Phase 2 §3.2 trust model — wire host_id is advisory). |
| **Tampering** | Attacker alters in-flight events | **Defended.** TLS 1.3 only (`MinVersion: tls.VersionTLS13`). |
| **Repudiation** | Agent denies sending an event | **Partially defended.** Server records `event_id` + `collected_at` per event. Agent-side hash chain (Phase 5 #95) cross-checks rule-driven response actions. Plain telemetry events are not signed per-event — too expensive at fleet scale. |
| **Information disclosure** | Attacker reads in-flight events | **Defended.** TLS 1.3 confidentiality. |
| **Denial of service** | Attacker floods the server with bogus events | **Partially defended.** Server's CH writer has bounded subscriber drops + Phase 5 #97 backpressure broadcast. mTLS cert revocation lists aren't shipped (Phase 6+); a stolen agent cert can flood until manually revoked via console. |
| **Elevation of privilege** | Attacker uses the ingest path to take over the server | **No known vector.** Server-side decoders are protobuf + JSON; no shell-exec, no template injection. |

**Residual risks:**
- Stolen agent cert (e.g. host cloning before revocation propagates)
  can produce forged-but-cryptographically-valid events for that
  host_id until the operator revokes via `/hosts/{id}/revoke`.
  Cert rotation is post-Phase 5 work.
- Pre-shared CA on dev clusters via `--insecure-skip-verify` provides
  no defense. The flag exists for compose-stack development; it is
  documented as production-forbidden.

## Surface 2 — Control plane (server → agent)

Three control messages: `RuleSet` (Phase 2 #39), `ResponseRequest`
(Phase 4 #75), `HostPolicy` (Phase 4 #84), `BackpressureSignal`
(Phase 5 #97). All flow over the same mTLS Session as ingest.

| STRIDE | Threat | Status |
|--------|--------|--------|
| **Spoofing** | Attacker pushes fake rules / response actions to an agent | **Defended.** mTLS — only a peer with the server's cert can drive the control channel. |
| **Tampering** | Attacker modifies a rule mid-push | **Defended.** TLS 1.3. |
| **Repudiation** | Operator denies issuing a kill | **Defended.** Every operator-driven response writes to `audit_log` (Phase 4 #76) keyed on the action's `id`, with operator UUID + transitions. Phase 5 #95 mirrors the chain agent-side for tamper-evidence. |
| **Information disclosure** | Rule contents leak | **Defended.** Rules flow over mTLS only. They're not secret per se (a determined attacker can reverse-engineer detection logic from observed agent behaviour) but the server doesn't broadcast them to non-mTLS peers. |
| **Denial of service** | Operator floods rules to thrash the agent | **Partially defended.** Hub.Refresh debounces NOTIFY at 200 ms; agent's rule-replace path is bounded (drop-stale-not-block). A determined operator with admin role can still author bad rules — that's a "trusted operator misuse" scenario, not an attacker. |
| **Elevation of privilege** | Compromised server → agent code execution | **Partially defended.** Rules are Sigma YAML, parsed by `pkg/ruleast` into a typed AST. No shell-exec, no template eval. Response actions are a frozen six-class enum (ADR-0034); agent rejects unknown values. A compromised server can still issue arbitrary kills/quarantines/isolation against any agent it controls — that's by design. |

**What we explicitly accept:** a compromised server has full control
over connected agents within the per-host policy bounds. Default
detect-only baseline (ADR-0034) is the structural defence: a fresh
host enrols and acts on nothing until an admin promotes it.

**Residual risks:**
- Default-deny on freshly-enrolled hosts mitigates blast radius from
  a compromised server, but a host already promoted to
  `allow_kill_process=true` is at the server's mercy. Reduce blast
  radius by promoting narrowly + auditing `host_response_policies`
  changes in `audit_log`.
- The control channel has no per-message signing; the entire
  defence is the mTLS pipe.

## Surface 3 — Console (operator UI)

HTMX + chi router + scs session manager. Argon2id password auth.
Server-rendered templ views; no SPA, no client-side state.

| STRIDE | Threat | Status |
|--------|--------|--------|
| **Spoofing** | Attacker logs in as a known operator | **Defended.** Argon2id with OWASP-recommended parameters (Phase 2 #41). Login surface returns identical "Invalid credentials" for unknown user vs bad password — no enumeration. |
| **Tampering** | XSS, CSRF, SQL injection | **Defended.** templ auto-escapes (no `{!html!}` raw injection except for already-rendered SVGs from `graph.Cache`). pgx parameterised queries throughout `pg.Store`. Console routes are GET / POST with form-encoded bodies; CSRF coverage is via session-cookie + same-site default — no token-based CSRF middleware (acceptable for a server-rendered HTMX app on a single origin; would need adding for a future SPA). |
| **Repudiation** | Operator denies an action | **Defended.** `audit_log` keyed on user UUID for every response dispatch, policy edit, host revoke, alert transition, IOC feed change. Login outcomes (success + failure) audited too. |
| **Information disclosure** | Viewer escalates to data above their role | **Defended.** Routes wrap `RequireRole(...)` at registration, not at handler entry — direct POSTs to admin endpoints from a viewer session 403 without DB hit. Per-row authz isn't implemented (single-tenant assumption); per-host visibility for multi-tenant deploys is Phase 6+. |
| **Denial of service** | Brute-force login | **Partially defended.** No rate-limiter shipped. Argon2id is intentionally slow (~150 ms per attempt on the target host), so brute force is bounded by login latency × attacker patience. A reverse-proxy rate limit is the operator's responsibility. |
| **Elevation of privilege** | Viewer → admin escalation | **No known vector.** Role is server-authoritative (read from `users.role` per request); session cookie carries only user_id, not role claims. |

**Residual risks:**
- No CSRF token middleware. Same-site=Lax + the session-cookie default
  blocks cross-origin form posts in evergreen browsers, but a
  same-origin XSS would bypass that. Adding a chi-style CSRF
  middleware is a small Phase 6 task if multi-tenant deploys land.
- No login rate-limit. Operators behind a reverse proxy
  (nginx/Caddy) get rate-limiting for free; bare deploys don't.

## Surface 4 — Agent runtime (the binary on the host)

The agent runs as root with a bounded capability set
(CAP_BPF, CAP_PERFMON, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH,
CAP_DAC_OVERRIDE, CAP_KILL, CAP_NET_ADMIN), holds open BPF program
FDs + tracepoint perf events, reads /proc, hashes executables,
writes telemetry to ClickHouse via the server.

| STRIDE | Threat | Status |
|--------|--------|--------|
| **Spoofing** | Local-root attacker impersonates the agent to peer hosts | **Out of scope.** A local-root attacker on the agent host has the agent's cert and the agent's keyring; impersonation is by definition possible. The operator's response is to revoke + re-enrol. |
| **Tampering** | Local attacker modifies the agent's state, rules, or audit chain | **Partially defended.** State dir 0700 root:root (Phase 5 #94). PR_SET_DUMPABLE=0 blocks ptrace + core dumps + /proc/<agent-pid>/* reads from non-owner UIDs. Tamper-evident hash chain (Phase 5 #95) makes silent log edits detectable on next boot. None of this defends against a local-root attacker who can write the chain AND control the agent's outbound channel — that's the explicit non-goal. |
| **Repudiation** | Agent denies it killed a process | **Defended.** ResponseResult round-trips back to the server's `response_actions` audit row. Agent-side hash chain duplicates the record locally so an isolated agent (during a server outage) still has provable history. |
| **Information disclosure** | Side-channel readout of agent memory | **Partially defended.** PR_SET_DUMPABLE=0 + state-dir lockdown covers /proc and core dumps. Kernel keyring (Phase 5 #98) keeps the client cert + key out of disk where the file fallback isn't taken. Memory of a running process is still visible to a CAP_SYS_PTRACE-holding peer; we don't defend against another root process on the same host. |
| **Denial of service** | Attacker SIGKILLs the agent | **Out of scope.** A local-root attacker can kill any process. Detection of agent absence is the server's job (heartbeat staleness → host marked offline at /hosts). |
| **Elevation of privilege** | Compromised agent escapes to ring-0 | **No known vector via slither code.** BPF programs are kernel-verified. Capability bounding box prevents the agent from acquiring caps it didn't start with. The remaining attack surface is the kernel itself, which we explicitly don't defend against (see "what we don't defend against" below). |

**Residual risks:**
- Local-root attacker on the agent host can disable the agent. Server
  side detection (heartbeat absence + `audit_log` agent-revoke chain)
  surfaces it; agent-side prevention isn't possible without a
  separate watchdog process operating outside the unit.
- Mutual-exclusion between "agent self-protected from local root"
  and "agent operates with local root" is a real contradiction.
  Slither resolves it by accepting the operator-side promise that
  the host's local-root credential is trusted; if it isn't, the
  threat model is host-compromise, not slither-compromise.

## Surface 5 — Package distribution

Phase 5 #89 (reproducible builds) + #90 (SBOM) + #91 (cosign keyless)
+ #92 (deb/rpm) + #93 (OCI multi-arch).

| STRIDE | Threat | Status |
|--------|--------|--------|
| **Spoofing** | Attacker serves a malicious binary as if it were slither | **Defended.** Cosign-keyless signatures via GitHub OIDC. Verifier gates on `--certificate-identity-regexp` matching this repo's release workflow at a `refs/tags/v*` ref. Forks, PR builds, and re-signed-by-attacker artefacts all fail verification. |
| **Tampering** | In-transit modification | **Defended.** Same signature anchor — any modification breaks the cosign verify. |
| **Repudiation** | Slither maintainers deny shipping a release | **Defended.** Sigstore transparency log records every signing event publicly. |
| **Information disclosure** | Build process leaks secrets | **Defended.** No secrets in the build pipeline beyond GitHub's ephemeral OIDC token. SBOM (syft) makes the dependency tree auditable in both SPDX and CycloneDX formats. |
| **Denial of service** | Attacker DoSes the GitHub release surface | **Out of scope.** GitHub's responsibility. |
| **Elevation of privilege** | Compromise of the build system itself | **Acknowledged limitation.** A compromised GitHub Actions runner, a compromised workflow definition merged via a backdoored PR, or a compromised dependency post-`go mod download` can all produce a signed binary that we don't catch. Reproducible builds (verify-reproducible CI job) raise the bar — the tampered binary would need to reproduce bit-for-bit from source — but doesn't eliminate the risk. |

**Residual risks:**
- Trust still flows from GitHub's OIDC provider through Fulcio's CA.
  A compromise of either is out-of-band for slither but inside the
  trust chain consumers rely on.
- Operators who skip verification (`apt install` without
  `cosign verify-blob` first) trade trust for transport. The doc
  yells about this in `docs/install.md §1.2`.

## What slither explicitly does NOT defend against

Stated plainly so operators can decide if slither fits:

1. **Kernel-mode rootkits.** A ring-0 attacker can hide processes
   from `/proc`, intercept BPF program loads, fake tracepoint
   responses, and tamper with anything user-space-visible. Slither
   relies on the kernel telling the truth. Phase 6+ may add bpfman
   integration or a ring-0 attestation hook; today, no.
2. **Supply-chain compromise of the build system.** Reproducible
   builds raise the bar but a determined attacker who compromises
   the Go toolchain or a transitive dependency can still ship a
   tampered slither. SBOM helps post-incident triage; it doesn't
   prevent the tamper.
3. **Physical access to enrolled hosts.** Cold-boot attacks on the
   client cert (when the file fallback is taken), forensic disk
   imaging of `/var/lib/slither`, and keystone-level access to TPM
   contents are all out of scope. TPM-sealed cert storage is Phase
   6+ work.
4. **Compromise of the slither server itself.** The trust model
   pushes the boundary at the agent ↔ server mTLS pipe. A
   compromised server has full control over its agents within their
   per-host policies. The structural defence is default-detect-only
   on every fresh enrollment + narrow promotion + audit chain.
5. **Insider operator abuse.** A malicious admin can mint enrolment
   tokens, revoke hosts, edit per-host policy, dispatch responses,
   and edit IOC feeds. Every action is audited, not prevented.
   Operator due diligence is the only mitigation.
6. **Side-channels external to slither.** Spectre/Meltdown-class
   CPU attacks, RowHammer, electromagnetic emanations — all
   physics, not code.
7. **Network-level traffic analysis.** mTLS hides content, not
   metadata. An attacker observing the agent's outbound traffic
   can fingerprint slither by packet timing + size patterns even
   without breaking the tunnel.
8. **Upstream Sigma-rule logic flaws.** Operators write rules; bad
   rules produce bad detections. Slither's compiler validates
   structure (ADR-0032's two-artefact shape, ADR-0018's
   classification gate), not semantic correctness.

## Defense-in-depth posture summary

What stacks together to make the bar reasonable:

- mTLS at every agent ↔ server boundary; pinned CA at enrollment.
- Default-detect-only per-host policy; explicit promotion required
  before any response action fires (ADR-0034).
- Capability bounding on the agent unit (Phase 1 #25 + Phase 5 #94
  refinements); no privileged: true in the k8s daemonset.
- PR_SET_DUMPABLE=0 + state-dir 0700 + anti-debug refusal at agent
  startup (Phase 5 #94).
- Tamper-evident local audit chain (Phase 5 #95) + canonical
  server-side `audit_log` (Phase 4 #76).
- Offline-buffer replay-bypass (Phase 5 #96) so reconnect storms
  don't backfill `/live` with stale events.
- End-to-end backpressure (Phase 5 #97) so a slow CH writer doesn't
  cascade into the agent's collectors.
- Kernel-keyring storage for client cert (Phase 5 #98) when usable.
- Cosign-signed reproducible release artefacts (Phase 5 #89/#91)
  with operator-facing verification recipe.

## Reporting security issues

`SECURITY.md` covers the disclosure process. The threat model above
is descriptive; a real-world finding the doc didn't anticipate gets
filed there, not as a public issue.

## Document maintenance

This file is updated alongside every Phase change that affects the
security posture. Phase 6+ work that materially shifts the threat
model (TPM-sealed storage, multi-tenancy, rule-pack signing) gets
its own section + cross-references back to the relevant ADR.
