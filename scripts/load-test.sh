#!/usr/bin/env bash
# scripts/load-test.sh — Phase 1 agent load baseline.
#
# Runs the slither-agent under stress-ng --exec and reports:
#   - events produced / dropped / detections fired (via stderr DiagReport)
#   - drop rate %
#   - peak and mean agent CPU% + peak RSS (via ps-sampling)
#
# Requires: root, kernel BTF, stress-ng, ps. No network.
#
# Usage: scripts/load-test.sh [DURATION_S] [EXEC_COUNT]
#   DURATION_S  default 30
#   EXEC_COUNT  default 100 (stress-ng --exec workers)

set -euo pipefail

DURATION="${1:-30}"
EXEC_COUNT="${2:-100}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT="${ROOT}/bin/slither-agent"

require() {
    command -v "$1" >/dev/null || {
        echo "error: $1 not found in PATH" >&2
        exit 2
    }
}

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: root required for BPF load" >&2
    exit 2
fi
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    echo "error: /sys/kernel/btf/vmlinux unavailable" >&2
    exit 2
fi
require stress-ng
require ps
require awk

# Build if missing or older than sources.
if [[ ! -x "$AGENT" ]] || [[ -n "$(find "${ROOT}/agent" -name '*.go' -newer "$AGENT" -print -quit 2>/dev/null)" ]]; then
    echo ">>> building agent"
    (cd "$ROOT" && make build-agent >/dev/null)
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "${WORK}/agent.yaml" <<EOF
agent:
  host_id_file: ${WORK}/host_id
  log_level: warn
collectors:
  process:
    enabled: true
  file:
    enabled: true
  net:
    enabled: true
rules:
  paths: []
output:
  kind: stdout
EOF

STDERR_LOG="${WORK}/agent.stderr"
CPU_LOG="${WORK}/agent.cpu"

echo ">>> starting agent"
"$AGENT" --config "${WORK}/agent.yaml" >/dev/null 2>"$STDERR_LOG" &
AGENT_PID=$!
trap 'kill -TERM "$AGENT_PID" 2>/dev/null || true; wait "$AGENT_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# Wait for tracepoints to attach. A cold agent binary sits ~300–500 ms
# before the first event lands; 1 s is comfortably past that on CI runners.
sleep 1

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "error: agent exited during startup" >&2
    cat "$STDERR_LOG" >&2
    exit 1
fi

# Sample CPU% and RSS in parallel with the workload. 1 Hz is plenty —
# the agent is measured over tens of seconds, so sampling noise is the
# dominant source of error at higher rates anyway.
(
    while kill -0 "$AGENT_PID" 2>/dev/null; do
        ps -o %cpu=,rss= -p "$AGENT_PID" 2>/dev/null || break
        sleep 1
    done
) > "$CPU_LOG" &
SAMPLER_PID=$!

echo ">>> stress-ng --exec ${EXEC_COUNT} --timeout ${DURATION}s"
stress-ng --exec "$EXEC_COUNT" --timeout "${DURATION}s" --metrics-brief >/dev/null 2>&1 || true

echo ">>> stopping agent"
kill -TERM "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true
kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true

# Parse telemetry line: `telemetry: events=N dropped=N detections=N ringbuf_overflows=N`
TELEM_LINE="$(grep -E '^telemetry:' "$STDERR_LOG" | tail -n 1 || true)"
if [[ -z "$TELEM_LINE" ]]; then
    echo "error: no telemetry line on agent stderr" >&2
    echo "--- agent stderr follows ---" >&2
    cat "$STDERR_LOG" >&2
    exit 1
fi

EVENTS="$(echo "$TELEM_LINE" | awk 'match($0,/events=[0-9]+/){print substr($0,RSTART+7,RLENGTH-7)}')"
DROPS="$(echo "$TELEM_LINE" | awk 'match($0,/dropped=[0-9]+/){print substr($0,RSTART+8,RLENGTH-8)}')"
DETECTIONS="$(echo "$TELEM_LINE" | awk 'match($0,/detections=[0-9]+/){print substr($0,RSTART+11,RLENGTH-11)}')"
OVERFLOWS="$(echo "$TELEM_LINE" | awk 'match($0,/ringbuf_overflows=[0-9]+/){print substr($0,RSTART+18,RLENGTH-18)}')"

if [[ -z "$EVENTS" ]] || [[ -z "$DROPS" ]]; then
    echo "error: could not parse telemetry line: $TELEM_LINE" >&2
    exit 1
fi

# Drop rate = dropped / (produced + dropped). Counters track what the
# agent ingested into its channels vs. what it couldn't enqueue.
TOTAL=$(( EVENTS + DROPS ))
DROP_PCT="0.00"
if [[ "$TOTAL" -gt 0 ]]; then
    DROP_PCT="$(awk -v d="$DROPS" -v t="$TOTAL" 'BEGIN{printf "%.2f", (d/t)*100}')"
fi

CPU_SUMMARY="$(awk '
    NF >= 2 {
        cpu = $1; rss = $2
        sum_cpu += cpu; n_cpu++
        if (cpu > max_cpu) max_cpu = cpu
        if (rss > max_rss) max_rss = rss
    }
    END {
        if (n_cpu == 0) { print "samples=0"; exit }
        printf "samples=%d mean_cpu=%.1f peak_cpu=%.1f peak_rss_kb=%d\n", n_cpu, sum_cpu/n_cpu, max_cpu, max_rss
    }
' "$CPU_LOG")"

cat <<EOF

================= slither-agent load baseline =================
duration_s       ${DURATION}
stress_ng_exec   ${EXEC_COUNT}
events_produced  ${EVENTS}
events_dropped   ${DROPS}
detections_fired ${DETECTIONS}
ringbuf_overflow ${OVERFLOWS}
drop_rate_pct    ${DROP_PCT}%
${CPU_SUMMARY}
===============================================================
EOF
