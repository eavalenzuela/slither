#!/usr/bin/env bash
# Triggers proc-find-suid-discovery.yml — find -perm -4000 recon pattern.
# Harmless: depth-capped, errors suppressed, output discarded.
set -u
find / -xdev -maxdepth 2 -perm -4000 -type f 2>/dev/null | head -n 1 >/dev/null || true
exit 0
