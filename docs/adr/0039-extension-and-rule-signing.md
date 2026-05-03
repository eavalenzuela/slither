# ADR-0039: Extension + rule-bundle signing model

**Status:** accepted

**Date:** 2026-05-03

## Context

Phase 5 #91 shipped cosign-keyless signing for slither's *release
artefacts*: the binary, the OCI image manifest, the deb / rpm
packages. Phase 6 #107 wired the agent's extension supervisor to
verify extension binaries on every spawn — but the signing pipeline
itself (the CI workflow that produces signed extension binaries +
signed rule bundles) and the rule-bundle import path still need to
exist. ADR-0035 explicitly parked rule-pack signing for Phase 6.
ADR-0037 promised both close out together.

This ADR records: (a) the trust root the agent and `slither-db`
share; (b) the keyless-vs-keyed call; (c) the verification sequence
each consumer runs; (d) the bundle format used for out-of-band rule
distribution; (e) how the in-band server-push channel intentionally
stays unsigned.

## Decision

### Single trust root, keyless-OIDC, GitHub-bound

Both consumers (agent extension supervisor, `slither-db verify-rule-bundle`,
`slither-db insert-rule --signed-bundle`) verify against the same
trust root:

- **Issuer:** `https://token.actions.githubusercontent.com`
- **Identity regexp:** `^https://github\.com/t3rmit3/slither/\.github/workflows/release\.yml@refs/tags/v.*$`
- **Sigstore log:** Rekor public transparency log (default)

No long-lived signing key in the slither repo. No KMS-backed key.
The keyless flow is the single path; alternatives are explicit
opt-outs (`signature_verification: disabled` per-extension; no
`--signed-bundle` flag on `insert-rule`). Operators with their own
fork or downstream signing pipeline override `cosign_identity_regexp`
+ `cosign_oidc_issuer` per-extension to point at their own workflow
URL, or set their own `--cosign-identity-regexp` flag on the CLI.

### Why keyless

| Trade | Choice |
|-------|--------|
| Long-lived key in CI secrets | ❌ — single point of compromise; rotation requires resigning every release |
| KMS-backed key | ❌ — adds infra + cost; no value over keyless given the GitHub Actions OIDC chain is already the trust anchor for the project |
| Keyless via GitHub OIDC | ✅ — short-lived per-workflow-run cert, Rekor log makes signing events publicly auditable, matches Phase 5 #91's existing release-artefact flow |

The trust chain runs: GitHub OIDC (workflow identity) → Fulcio
(issues short-lived cert) → cosign signature (binds the artefact's
SHA-256 to the cert) → Rekor (transparency log).

### Two artefact shapes, same verifier

| Shape | Producer | Sidecars | Consumer |
|-------|----------|----------|----------|
| Extension binary | `cosign sign-blob` in `.github/workflows/release.yml` (Phase 5 #91 step extended for `slither-ext-*`) | `<bin>.sig` + `<bin>.pem` alongside | Agent extension supervisor (Phase 6 #107) |
| Rule bundle (`*.tgz`) | `cosign sign-blob` against the tar | `<bundle>.tgz.sig` + `<bundle>.tgz.pem` alongside | `slither-db verify-rule-bundle` / `slither-db insert-rule --signed-bundle` |

Both consumers share `pkg/sigverify` — one set of cosign-shell logic,
one set of error semantics, one set of fail-closed guarantees.

### Rule bundle format

Tar.gz, conventionally named `slither-rules-<vN>.tgz`. Top-level
entries are Sigma YAML files; subdirectories permitted but ignored
for `insert-rule` (each YAML compiles independently). No metadata
file required — the bundle is "every YAML inside is a rule, signed
as a unit".

```
slither-rules-v1.tgz
├── 01-process-creation/
│   ├── reverse-shell-bash.yml
│   └── suspicious-curl.yml
├── 02-file-events/
│   └── history-clear.yml
└── 03-network/
    └── unusual-egress.yml
```

`slither-db insert-rule --signed-bundle FILE` walks every `*.yml` /
`*.yaml` entry in the tar, compiles + upserts each, and rolls back
the transaction if any rule fails to compile (atomic per-bundle import).

### What gets signed, what doesn't

| Path | Signed? | Why |
|------|---------|-----|
| Extension binary distributed via deb/rpm/OCI | ✅ cosign-keyless | Operator runs `cosign verify` before installing; agent verifies again on every spawn |
| Rule bundle pulled from a partner repo, ingested via CLI | ✅ cosign-keyless | Out-of-band path — no transport-layer trust |
| Rules pushed in-band over the control channel | ❌ unsigned | `Hub.Refresh` reads from pg, mTLS-pushes to subscribed agents; an attacker who can write to pg already has signing-key access if rules were signed (the signing would happen at insert time, by the same admin). Adding a layer here protects against nothing |
| `slither-db insert-rule --file FILE` (legacy path) | ❌ optional | Backward-compat; operators with no upstream signing pipeline still have a usable workflow. `--signed-bundle` is the recommended path |

The asymmetry is deliberate: in-band push trusts the server (mTLS +
server-side authz); out-of-band import requires a signature because
there is no transport-layer trust to lean on.

### Verification sequence (shared by both consumers)

1. Locate signature + certificate sidecars (`{artefact}.sig` /
   `{artefact}.pem`, or operator-supplied paths).
2. Resolve the cosign binary (default `cosign` on `PATH`).
3. Invoke `cosign verify-blob --certificate-identity-regexp ...
   --certificate-oidc-issuer ... --signature {sig} --certificate
   {cert} {artefact}`.
4. Map exit codes:
   - **0** → verification passes; consumer proceeds.
   - **non-zero with "no matching signatures" / "certificate-identity"
     / "issuer" in stderr** → policy mismatch (`ErrSignatureRefused`).
   - **non-zero, other text** → infrastructure failure (cosign / Rekor
     unavailable, malformed sidecar). Surface raw cosign output so
     operators can triage.

Fail-closed at every step. Missing cosign on PATH is a refusal, not a
silent skip.

### Why shell out rather than vendor sigstore/cosign/v2

`github.com/sigstore/cosign/v2` pulls ~150 transitive deps including
a chunk of the kubernetes API surface. Verification is rare (once
per extension restart cycle, once per rule-bundle import). The fork
cost of `exec.Command("cosign", ...)` is negligible compared to the
dependency footprint. If a future v1.x sub-release adds in-process
verification (e.g. for performance reasons in a hot path), the
`pkg/sigverify` interface is the swap point — implementation, not
contract, changes.

### Operator workflow

**Producer side** (project maintainer):

```bash
# .github/workflows/release.yml extends Phase 5 #91 to also sign
# slither-ext-osquery and the canonical rule bundle.
cosign sign-blob --yes ./slither-ext-osquery \
    --output-signature ./slither-ext-osquery.sig \
    --output-certificate ./slither-ext-osquery.pem
cosign sign-blob --yes ./slither-rules-v1.tgz \
    --output-signature ./slither-rules-v1.tgz.sig \
    --output-certificate ./slither-rules-v1.tgz.pem
```

**Consumer side** (operator on a target host or admin host):

```bash
# Install signed extension. Drop the binary + sidecars into
# /usr/lib/slither/extensions/, declare in agent.yaml.
sudo install -m 0755 slither-ext-osquery     /usr/lib/slither/extensions/
sudo install -m 0644 slither-ext-osquery.sig /usr/lib/slither/extensions/
sudo install -m 0644 slither-ext-osquery.pem /usr/lib/slither/extensions/

# Verify a rule bundle offline before pulling it into the running
# server.
slither-db verify-rule-bundle ./slither-rules-v1.tgz

# Import a signed bundle. Verifies first, then transactionally
# upserts every YAML rule inside.
slither-db insert-rule --signed-bundle ./slither-rules-v1.tgz
```

## Consequences

- **One trust root for everything Slither distributes.** Agent
  extensions, rule bundles, and the agent/server binaries themselves
  all chain to the same GitHub-OIDC keyless cosign cert. Operators
  audit one signing pipeline.
- **§10.5 closes.** Rule signing is no longer "deferred to Phase 6+";
  out-of-band imports require a signature, in-band server-push
  intentionally does not.
- **§10.6 closes.** Extension distribution model is operator-installed,
  signature-verified, agent.yaml-declared. Server-pushed binaries
  remain Phase 6+.
- **`pkg/sigverify` is the seam.** Both consumers share verification
  logic; a future swap to in-process cosign or to a different signing
  backend (Notary v2, SLSA-only) needs to change one package.
- **No long-lived signing keys to rotate.** Keyless OIDC cert TTL is
  ~10 minutes per signing event; compromise of any single workflow
  run can be rolled back via Rekor log audit, not key rotation.
- **Operators with downstream forks override the identity regexp.**
  Documented in `docs/install.md`; the override is per-extension in
  `agent.yaml` and per-invocation on the CLI.

## References

- ADR-0011 (transport gRPC mTLS — in-band server trust precedent)
- ADR-0035 (Phase 5 scope — parked rule-pack signing for Phase 6)
- ADR-0037 (Phase 6 scope — extension distribution + signing folded
  into one task)
- Phase 5 #91 (`.github/workflows/release.yml` cosign sign-blob loop —
  extended by this task to cover extension binaries + rule bundles)
- Phase 6 #107 (`agent/internal/extensions/verify.go` — cosign verify
  on every spawn; refactored to use `pkg/sigverify` as part of #108)
