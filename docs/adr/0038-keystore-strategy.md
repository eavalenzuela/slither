# ADR-0038: Keystore strategy — `@u` user keyring + file fallback

**Status:** accepted

**Date:** 2026-05-05

## Context

Phase 5 #98 (IMPLEMENTATION.md §10.2) shipped a kernel-keyring +
file-fallback keystore for the agent's mTLS material (client.key,
client.crt, ca.crt). Phase 5 #103 V9 cloud validation surfaced **Gap
A**: the chosen keyring target was `KEY_SPEC_SESSION_KEYRING` (`@s`)
which is per-PAM-session. The `slither-agent enroll` subprocess
wrote keys into its own session ring; when the systemd-managed
`slither-agent.service` started later, it landed in a *different*
session ring with none of those keys. The keyring path was
effectively dead in production. The hot-fix made the keyring write
best-effort additive on top of the file store — durability stayed
correct, but the in-RAM-only privacy property the keyring was meant
to provide didn't hold across an enrol→service boundary.

Phase 6 #117 picks the durable strategy. ADR-0037's trade table
listed three options:

| Option | Trade |
|--------|-------|
| (a) Drop kernel-keyring entirely; files-only | Smallest code surface; loses any in-RAM-only privacy property |
| (b) `KEY_SPEC_USER_KEYRING` (`@u`) — per-uid persistent | Survives session boundary; still in RAM; matches typical EDR-ish "key in keyring" expectation. Available on every kernel ≥ 3.5. |
| (c) Systemd helper unit pre-populating keys at boot via `KeyringMode=shared` | Most operationally complex; requires a second unit + ordering dependency |

## Decision

**Option (b): use `KEY_SPEC_USER_KEYRING` (`@u`) as the keyring
target, with the file store at `/etc/slither/` as the durable
belt-and-braces.**

The `keyringID()` helper now prefers `@u` and degrades to `@s` only
when `@u` is unreachable (rare — kernel ≥ 3.5 always exposes it).
The Save path writes to whichever ring `keyringID()` returns; the
Load path reads from that same ring. AutoSelect's probe still
gates the choice — a kernel without CONFIG_KEYS, a confined
container, or a SELinux denial degrades cleanly to the File store.

## Consequences

### Why option (b)

- **Survives the enrol→service boundary.** The enroll subprocess
  and the long-lived agent service run as the same uid (root in the
  default deployment, or whatever the operator's `User=` directive
  picks); `@u` is shared across both processes by definition.
- **Smallest code change.** Flipping the preference order in
  `keyringID()` + updating the comment on `Keyring`. No new systemd
  unit, no new ordering dependency, no install-script changes.
- **Available everywhere.** `KEY_SPEC_USER_KEYRING` lands in Linux
  3.5; the project's kernel floor (ADR-0010) is 5.15.
- **Familiar shape.** Other EDR-shaped tooling (auditd-helper,
  audisp-remote) parks credentials under `@u` for the same reason.
  Operators inspecting `/proc/keys` see the keys in the place they
  expect.

### Why not (a)

A files-only keystore loses the in-RAM-only secrecy story we
inherited from Phase 5. Even though the file store is the durable
authority, the keyring write provides a non-trivial privacy
upgrade for hosts that explicitly clear the file store post-enrol
(rare but legitimate hardening pattern). Dropping the keyring path
would shrink that option without saving meaningful code (the
fallback wiring is already there for non-CONFIG_KEYS hosts).

### Why not (c)

`KeyringMode=shared` works but requires a second systemd unit
ordered before `slither-agent.service`, plus an
`ExecStartPre=` that populates the ring from the file store on
every boot. The ordering glue is fragile — a misconfigured
`After=` directive silently degrades to "no keyring", which is
exactly what Gap A taught us to avoid. (b) achieves the same
durability with strictly less moving parts.

### Cross-tenant caveat

`@u` is **per-uid**, not per-process. Any process running as the
agent's uid can read the keys via `keyctl`. The agent runs as root
in the standard deployment, so the realistic threat reduces to
"another root process on the same host" — which is already out of
scope per `docs/threat-model.md` Surface 4 ("local-root attacker
who can write to log.chain AND control the agent's signing key").
Operators wanting tighter scoping run the agent under a dedicated
uid (e.g., `User=slither` in the systemd unit) so `@u` becomes a
single-process keyring in practice.

This is the same trade `auditd-helper` and similar EDR-shaped
agents make. Documented in the threat model under Surface 4.

### File store stays primary for durability

The file store at `/etc/slither/{client.key,client.crt,ca.crt}`
remains the durable source of truth. On every boot:

1. The agent's enroll path writes to both stores (file first, then
   keyring best-effort).
2. The agent's Load path reads from whichever store AutoSelect
   chose (keyring when probe succeeds, file otherwise).
3. A keyring miss + file hit causes the loader to populate the
   keyring on the next Save. Operators who want to clear the file
   store post-enrol (in-RAM-only mode) do so manually after
   confirming the keyring is loaded; v1 does not automate this
   flow because the safety properties depend on operator-specific
   policy (e.g., immutable-rootfs hosts).

### Migration

Existing fleets running the Phase 5 #98 code path still write to
`@s`. After a Phase 6 upgrade:

- The first Save lands in `@u` (the new target).
- A stale `@s`-scoped key remains for the lifetime of whatever
  PAM session created it; operators can `keyctl clear @s`
  manually if they want hygiene, but the agent's Load path no
  longer consults `@s` so the stale key is inert. **Functionally a
  no-op upgrade** — no enroll re-issuance, no service restart
  ordering required.

## TPM-sealed variant (separate ADR pending #118)

`agent.keystore.tpm: true` opts into PCR-bound sealing (Phase 6
#118). Falls back to the strategy this ADR records when TPM is
absent. The TPM variant is a strict superset of (b); Operators
treating `@u` as insufficient for their threat model upgrade to
TPM rather than to (c).

## Validation

The test matrix for this change is the existing
`agent/internal/keystore` unit tests (which exercise both stores
without caring which keyring spec the probe used) plus manual
Phase 6 #121 cloud-VM exit validation against:

- Debian 13 6.12
- RHEL 10 6.12
- Ubuntu 24.04 6.8
- distroless-nonroot OCI image (where the probe is expected to
  fail and AutoSelect drops to file)

The keyring-vs-file choice is logged at agent boot via the
existing `keystore: <name>` slog line so operators can verify the
selected store post-enroll.

## References

- IMPLEMENTATION.md §10.2 — kernel keyring storage
- ADR-0010 — supported-kernel matrix (5.15 floor)
- ADR-0037 — Phase 6 scope (option trade table)
- `agent/internal/keystore/keyring_linux.go`
- `docs/threat-model.md` Surface 4 — Information disclosure
- `docs/phase5-validation.md` Gap A
