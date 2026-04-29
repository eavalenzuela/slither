#!/usr/bin/env bash
# Generates a 100,001-entry SHA-256 feed file (one over the
# MaxIOCFeedEntries cap) so the oversize-IOC server-only test path can
# be exercised. Output: ./oversize-threat-domains.txt
#
# We use ASCII domain names (phase3-test-NNNNNNN.example.org) so the
# pg.normaliseEntries domain validator accepts every line.

set -euo pipefail
out=${1:-oversize-threat-domains.txt}
count=${2:-100001}

: > "$out"
for i in $(seq 1 "$count"); do
    printf 'phase3-test-%07d.example.org\n' "$i" >> "$out"
done

wc -l "$out"
