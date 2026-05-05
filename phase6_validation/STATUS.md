# Phase 6 #121 — captures so far + operator instructions

## Status matrix

| § | Status | Capture |
|---|--------|---------|
| V0 | ✅ | 00-preflight.txt + 00-fleet-state.txt |
| V1 | ✅ tamper-detect; ⚠ Phase 7 OOM under disabled-verify | 01-extension-supervisor.txt |
| V2 | ⏳ operator | OPERATOR_WALKTHROUGH.md |
| V3 | ✅ | 03-snapshot-no-providers.txt |
| V4 | ✅ | 04-chain-mismatch.txt |
| V5 | ⏳ operator | OPERATOR_WALKTHROUGH.md |
| V6 | ⏳ operator | OPERATOR_WALKTHROUGH.md |
| V7 | ⏳ operator | OPERATOR_WALKTHROUGH.md |
| V8 | ⏳ operator | OPERATOR_WALKTHROUGH.md |
| V9 | ✅ restart cycle; ⚠ Phase 7 keystore probe possession bug | 09-keystore-gap-a.txt |
| V10 | ✅ no-TPM fallback path; ⚠ Phase 7 NitroTPM AMI provisioning | 10-tpm-pcr-bump.txt |
| V11 | ✅ native arm64 + kind; ⚠ Phase 7 arm64 BPF CO-RE | 11-multiarch-native.txt + 11-multiarch-k8s.txt |
| V12 | ⚠ steady-state only; sustained-load deferred | 12-backpressure.txt |
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

## Phase 6 close readiness

Code-side: all 18 task implementations are on main (commit
1c192f9 + earlier). The 5 follow-ups above are real bugs surfaced
by validation, not code regressions. Phase 6 closes when:
  (a) operator captures V2 + V5 + V6 + V7 + V8 land under
      phase6_validation/
  (b) docs/phase6-validation.md status flips to "completed"
  (c) the 5 follow-ups are filed as Phase 7 task entries in
      IMPLEMENTATION.md §9
  (d) git push origin main with the closing commit

## Cleanup state (2026-05-05)

- phase6-tpm (i-076cf63cb408f5a1d) — terminated 21:30Z
- phase6-graviton (i-0e51640f2e31bcac4) — terminated 21:33Z
- Phase 5 #103 fleet (4 hosts) — running, reusable per memory
