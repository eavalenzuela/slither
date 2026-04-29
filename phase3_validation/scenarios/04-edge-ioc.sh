#!/usr/bin/env bash
# Drive the 2 edge IOC-driven rules.

set -uo pipefail

# net-bad-ip-egress: connect to a documentation IP that's pre-loaded
# into the bad-ips feed. The packet won't actually reach anywhere
# routable; the tcp_connect tracepoint fires before the SYN even
# leaves.
echo "▶ net-bad-ip-egress: connect to 203.0.113.5"
timeout 1 bash -c 'exec 3<>/dev/tcp/203.0.113.5/80' 2>/dev/null || true

# file-bad-hash-touch: write a file whose SHA-256 matches the first
# entry in iocs/bad-hashes.txt (sha256("phase3-validation\n")).
echo "▶ file-bad-hash-touch: write file with seeded SHA-256"
printf 'phase3-validation\n' > /tmp/phase3-bad-hash.bin
sha256sum /tmp/phase3-bad-hash.bin
sleep 1

echo "edge IOC scenarios complete"
