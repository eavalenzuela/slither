#!/usr/bin/env bash
# Extract the slither CA cert from the running compose `pki` volume so
# operators can copy it onto an agent VM before running
# `slither-agent enroll --ca-cert ...`. Phase 2 #46 validation step.
#
# The bootstrap container exits after first run, so we can't `docker
# compose exec bootstrap`. Instead spin up a one-shot alpine that
# mounts the same volume read-only and prints the cert.
#
# Usage:
#   ./scripts/export-compose-ca.sh > server-ca.crt
#   scp server-ca.crt agent-vm:/tmp/

set -euo pipefail

VOLUME="${SLITHER_PKI_VOLUME:-compose_pki}"

if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "error: docker volume $VOLUME not found — is the stack up?" >&2
    echo "       set SLITHER_PKI_VOLUME if your compose project name differs" >&2
    exit 1
fi

docker run --rm -v "$VOLUME:/pki:ro" alpine cat /pki/ca.crt
