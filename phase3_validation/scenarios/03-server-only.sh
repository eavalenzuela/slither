#!/usr/bin/env bash
# Drive the server-only rules. These fire on the server's detection
# engine (#58), not the agent — the agent just emits the underlying
# events.
#
# Coverage:
#   near-shell-exec-then-net: bash exec immediately followed by an
#     outbound net connect (cross-stream temporal join).
#   cross-host-passwd-fanout: /etc/passwd reads on multiple hosts;
#     scenario only fires the local read — the cross-host dimension
#     requires the same scenario to run on >=4 hosts within 5m, which
#     the multi-host run handles by invoking this script on every
#     agent.
#   long-window-net-burn: 100+ outbound 443 connects per host in 1h —
#     not driven here (would need a slow background loop). Tested
#     opportunistically by the load test phase; not part of the
#     synthetic adversary scenario.
#   oversize-ioc-domain-hit: see scenarios/04-edge-ioc.sh; the same
#     rule shape but referencing the oversize-domains feed.

set -uo pipefail

# near: shell exec then net connect
echo "▶ near-shell-exec-then-net: bash + curl in tight sequence"
bash -c 'curl -sS --max-time 1 http://198.51.100.42/ -o /dev/null' 2>/dev/null || true

# cross-host-passwd-fanout: emit a passwd read; cross-host signal
# accumulates as every agent runs this scenario.
echo "▶ cross-host-passwd-fanout: passwd read"
cat /etc/passwd > /dev/null

echo "server-only scenarios complete"
