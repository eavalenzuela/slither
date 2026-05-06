# AWS deployment helpers

Phase 6 #121 follow-up #5 — operator-facing recipes for AWS-specific
shapes that the stock distribution images don't satisfy. Single
deliverable today: a NitroTPM-capable AMI for the agent's TPM-sealed
cert variant (Phase 6 #118).

## NitroTPM-capable Ubuntu 24.04 AMI

The agent's TPM-sealed keystore (`agent.keystore.tpm: true`) seals
cert material against the boot-time value of PCR 7 (Secure Boot
policy). On AWS, that PCR is exposed only when the instance was
launched from an AMI registered with `TpmSupport=v2.0` AND the
instance type supports NitroTPM 2.0 (m7a/m7i family or newer).

**The catch:** Canonical's stock Ubuntu 24.04 amd64 AMI ships with
`TpmSupport=None`. Launching an `m7a.large` from it boots without
`/dev/tpm*`, and the agent's keystore probe silently falls back to
the keyring → file chain — no error, but the TPM-sealed property
isn't actually in force. Phase 6 #121 V10 only validated this
fallback behaviour for that reason.

`register-tpm-ami.sh` rewrites the metadata so a stock AMI's root
snapshot is re-registered with `TpmSupport=v2.0 + boot_mode=uefi`.
No EBS copy, no new disk — the same root blocks under a new AMI ID
the launch path treats as TPM-capable.

```bash
# 1. Find the latest Canonical Ubuntu 24.04 amd64 AMI in your region.
aws ec2 describe-images \
  --owners 099720109477 \
  --filters 'Name=name,Values=ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*' \
  --region us-west-2 \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text
# → ami-0abcdef1234567890

# 2. Re-register with TpmSupport=v2.0.
./register-tpm-ami.sh --source-ami ami-0abcdef1234567890 --region us-west-2
# → ami-09876543210fedcba

# 3. Launch m7a/m7i instances from the new AMI ID; /dev/tpm0 + tpmrm0
#    appear, and `slither-agent enroll --tpm` seals against PCR 7.
```

### When to use this

- AWS deployments where threat-model analysis says the keyring's
  per-uid scope is insufficient (e.g., multi-tenant root concerns,
  containerised co-residents).
- Hosts where Secure Boot is in force AND PCR 7 is stable enough
  that re-enrolment on kernel updates is acceptable.

### When to skip

- Anything that doesn't materially upgrade the threat model — the
  keyring + file stores already cover the standard surface (see
  ADR-0038 "Cross-tenant caveat").
- Fleets with frequent kernel updates: PCR 7 churns on every Secure
  Boot policy change, forcing re-enrolment.
- Instance families without NitroTPM (most pre-m7 generations).

### Provisioning into Packer

This script does the bare metadata flip. Operators with existing
Packer pipelines should lift the `register-image` invocation into a
post-processor and add their usual provisioning (slither-agent
install, signed-binary fetch, etc.). The contract — `boot_mode=uefi`
+ `tpm_support=v2.0` — is what the agent's TPM probe checks for.

## Validation

The new AMI exposes `/dev/tpm0` + `/dev/tpmrm0` to launched instances;
`slither-agent enroll --tpm` exits 0 and writes
`/var/lib/slither/tpm_sealed.bin`; `journalctl -u slither-agent`
contains `keystore: tpm` (not `keystore: kernel-keyring` /
`keystore: file`).

Full hardware seal/unseal + PCR-bump validation rides this path on
the next Phase 6 #121 fleet bring-up — the captures land under
`phase6_validation/V10/` alongside the existing no-TPM run.
