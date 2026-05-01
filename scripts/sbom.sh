#!/usr/bin/env bash
# scripts/sbom.sh — emit SPDX-JSON + CycloneDX-JSON SBOMs for a target.
#
# Phase 5 #90. Wraps `syft` so the release pipeline can produce both
# formats with one call per artefact. Both formats are attached to
# the release alongside cosign signatures (#91), so consumers using
# either ecosystem (Linux Foundation SPDX, OWASP CycloneDX) get a
# verifiable bill of materials without us picking sides.
#
# Usage:
#   scripts/sbom.sh <target-path> [output-dir]
#
# Behaviour:
#   - <target-path> is anything syft accepts: a binary, a tar.gz, an
#     OCI image reference, or a directory.
#   - <output-dir> defaults to the directory containing <target-path>.
#   - Output files are named after the target's basename:
#       <basename>.spdx.json
#       <basename>.cyclonedx.json
#   - syft is expected on PATH; the release workflow installs it via
#     anchore/sbom-action/download-syft. Missing syft → exit 2.
#
# Exits non-zero on syft errors so the release job fails loud.

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <target-path> [output-dir]" >&2
    exit 2
fi

TARGET="$1"
OUTDIR="${2:-$(dirname "$TARGET")}"

if ! command -v syft >/dev/null 2>&1; then
    echo "error: syft not found on PATH. Install via anchore/sbom-action/download-syft@v0 or 'brew install syft'." >&2
    exit 2
fi

mkdir -p "$OUTDIR"

BASE="$(basename "$TARGET")"
SPDX="$OUTDIR/$BASE.spdx.json"
CYCLONE="$OUTDIR/$BASE.cyclonedx.json"

# syft scans the same target twice rather than re-using a cached scan
# across formats — the runtime cost is small (each binary is single-MB)
# and the SBOM tool stays composable. Future syft versions add
# `--select-catalogers` or similar; today the default catalog set is
# correct for stripped Go binaries (relies on Go's buildinfo, not on
# any debug section we strip via -s -w).
echo "▶ SBOM for $TARGET"
syft "$TARGET" -o "spdx-json=$SPDX" -o "cyclonedx-json=$CYCLONE" >/dev/null
echo "  ✓ $SPDX"
echo "  ✓ $CYCLONE"
