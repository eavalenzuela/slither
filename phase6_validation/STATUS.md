# Phase 6 #121 — final captures + status

**Status:** ✅ all 13 steps captured (some with surfaced bugs flagged
Phase 7). Run completed 2026-05-05.

## Status matrix

| § | Status | Capture |
|---|--------|---------|
| V0 | ✅ | 00-preflight.txt + 00-fleet-state.txt |
| V1 | ✅ tamper-detect; ⚠ Phase 7 #1 OOM under disabled-verify | 01-extension-supervisor.txt |
| V2 | ✅ no-provider path documented | 02-live-hunt.txt |
| V3 | ✅ | 03-snapshot-no-providers.txt |
| V4 | ✅ | 04-chain-mismatch.txt |
| V5 | ✅ first-login + role rotation + IdP-down fallback | 05-oidc-sso.txt |
| V6 | ✅ explorer + policy-gated menu | 06-process-tree.txt |
| V7 | ✅ saved queries + dashboards + dangling-card placeholder | 07-queries-dashboards.txt |
| V8 | ✅ reopen-alert; ⚠ Phase 7 #6 host: hostname/UUID parser gap | 08-search-reopen.txt |
| V9 | ✅ restart cycle; ⚠ Phase 7 #3 keystore probe possession bug | 09-keystore-gap-a.txt |
| V10 | ✅ no-TPM fallback; ⚠ Phase 7 #5 NitroTPM AMI provisioning | 10-tpm-pcr-bump.txt |
| V11 | ✅ native arm64 + kind; ⚠ Phase 7 #2 arm64 BPF CO-RE | 11-multiarch-native.txt + 11-multiarch-k8s.txt |
| V12 | ⚠ steady-state only; sustained-load deferred per #103 V8 | 12-backpressure.txt |
| V13 | ✅ | 13-jsonapi.txt |

## Phase 7 follow-ups surfaced by this validation run

1. **Extension supervisor OOM under signature_verification:disabled.**
   With cosign verify disabled, the agent crashes with
   `runtime: out of memory` during the Hello-frame read on the
   socketpair fd. Stack: extsdk.readUvarint → readFrame →
   ReadExtensionToAgent → readHello. Likely interaction between
   setrlimit(RLIMIT_AS) on the extension child and the Go
   runtime's mmap-based heap growth in the parent agent. With
   cosign on PATH the path is functionally unreachable, so this
   doesn't gate Phase 6 close.

2. **arm64 BPF CO-RE relocation failure (net collector).**
   `agent/internal/bpf/src/*.o` are pre-compiled by bpf2go on
   amd64. arm64 kernel BTF rejects the net collector's
   handle_inet_csk_accept retprobe with "bad CO-RE relocation:
   invalid func unknown#195896080". Workaround: net.enabled=false
   on arm64. Fix: regenerate per-arch .o files via bpf2go in the
   build pipeline.

3. **Keystore @u probe possession-traversal bug.**
   `tryKeyringPlatform()` adds a probe key to @u then reads it
   back. The READ returns EACCES on every host shape because the
   process doesn't possess @u (its session-keyring chain doesn't
   include @u). Linking @u into @s before the read makes the probe
   succeed. Effective Phase 6 behaviour: every host falls through
   to the file store. Security posture unchanged from Phase 5 #98;
   the in-RAM-only privacy upgrade ADR-0038 promised is not
   active. Fix in tryKeyringPlatform: keyctl_link @u into @s
   before the probe read.

4. **ADR-0038 effective-behaviour gap.**
   Consequence of #3. The threat-model claim about @u as the
   primary cert store needs a docs revision until #3 ships.

5. **NitroTPM AMI provisioning gap.**
   AWS Nitro TPM 2.0 needs an AMI with `TpmSupport=v2.0` baked in.
   Canonical's stock Ubuntu 24.04 amd64 AMI ships with
   TpmSupport=None, so a stock m7a.large gets no /dev/tpm*. Phase
   6 #121 V10 only validated the no-TPM fallback path; full
   hardware seal/unseal + PCR-bump validation needs a custom
   NitroTPM-enabled AMI. Either docs the register-image recipe or
   ships a Packer template under deploy/cloud/aws/.

6. **Events query parser host: axis hostname/UUID gap.**
   `q=host:ip-172-31-26-27` writes the literal hostname into
   ParsedQuery.HostID. Downstream ch.SearchEvents calls
   uuid.Parse(filter.HostID) which rejects hostnames, so the
   page returns "search failed" instead of resolving the
   hostname. Fix: parser should either UUID-validate at parse
   time or hostname-resolve via pg.GetHostByName before the CH
   query (paralleling the JSON API's host_name handling, #120(d)).

## Phase 6 close readiness

All 13 V-steps captured + 6 Phase 7 follow-ups documented. Ready
for the close commit:

  1. Flip docs/phase6-validation.md status header to "completed"
  2. Update IMPLEMENTATION.md task #18 → ✅
  3. Append the 6 Phase 7 follow-ups to IMPLEMENTATION.md §9
  4. Update memory project_phase_status.md
  5. git push origin main

## Cleanup state (2026-05-05)

- phase6-tpm (i-076cf63cb408f5a1d) — terminated 21:30Z
- phase6-graviton (i-0e51640f2e31bcac4) — terminated 21:33Z
- Phase 5 #103 fleet (4 hosts) — running, reusable per memory
- phase6-oidc-stub.service — disabled on slither-server
- iptables OUTPUT DNAT rule — removed
- SG port 5556 ingress — revoked (operator + intra-SG)
