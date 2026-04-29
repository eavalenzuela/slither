#!/usr/bin/env bash
# Drive the 3 bounded-stateful edge rules. Each rule's threshold is
# crossed inside the rule's 60s timeframe so the agent fires a single
# DetectionFinding per rule per host.

set -uo pipefail

# proc-curl-burst: > 5 curls by the same user within 60s.
echo "▶ proc-curl-burst: 6 invocations of /usr/bin/curl"
for i in $(seq 1 6); do
    curl -sS --max-time 1 http://198.51.100.99/ -o /dev/null 2>/dev/null || true
done
sleep 1

# file-tmp-write-burst: > 10 file creates under /tmp by the same actor pid in 60s.
echo "▶ file-tmp-write-burst: 12 file creates by one bash"
bash -c '
    for i in $(seq 1 12); do
        : > "/tmp/phase3-burst-$i"
    done
'
sleep 1

# net-port-fanout: > 10 distinct dst IPs on a single port in 60s.
echo "▶ net-port-fanout: 12 connect attempts to TEST-NET-2 on port 53/udp"
for i in $(seq 1 12); do
    # /dev/tcp short-circuit, no socket actually opened to the world but
    # the agent's tcp_connect tracepoint sees the connect syscall.
    timeout 1 bash -c "exec 3<>/dev/tcp/198.51.100.$i/8080" 2>/dev/null || true
done

echo "stateful edge scenarios complete"
