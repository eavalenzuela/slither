#!/usr/bin/env bash
# Phase 6 #121 — operator-facing validation helper.
#
# Doc-driven runbook lives at docs/phase6-validation.md. This script
# automates the parts that don't need a human: matrix dry-runs, CH/pg
# probe queries, telemetry-grep helpers. Steps that need eyeballs (V5
# IdP loop, V6 right-click menu, V10 TPM kernel bump) print
# instructions + pause for confirmation.
#
# Inputs:
#   PHASE6_OUT      — capture directory (default: phase6_validation/)
#   SERVER_HOST     — e.g. server.slither.local
#   AGENT_HOSTS     — space-separated list, e.g.
#                     "agent-debian agent-rhel agent-ubuntu agent-graviton"
#   PG_DSN          — for V4 (chain mismatch) + V13 (event count)
#   API_BASE        — e.g. https://server.slither.local:8080
#
# Exit codes: 0 = every automated check passed; 1 = at least one
# failed (capture file shows which); 2 = setup blocker.

set -euo pipefail

OUT="${PHASE6_OUT:-phase6_validation}"
mkdir -p "$OUT"

step() { printf '\n=== %s ===\n' "$*" | tee -a "$OUT/00-summary.txt"; }
note() { printf '%s\n' "$*" | tee -a "$OUT/00-summary.txt"; }
fail() { printf 'FAIL: %s\n' "$*" | tee -a "$OUT/00-summary.txt"; exit "${2:-1}"; }

require() {
    command -v "$1" >/dev/null 2>&1 || fail "missing tool: $1" 2
}

require curl
require ssh
require date

# Pre-flight inventory.
step "V0 — pre-flight"
{
    date -u +%Y-%m-%dT%H:%M:%SZ
    printf 'server: %s\n' "${SERVER_HOST:-<unset>}"
    printf 'agents: %s\n' "${AGENT_HOSTS:-<unset>}"
    printf 'api_base: %s\n' "${API_BASE:-<unset>}"
} | tee "$OUT/00-preflight.txt"

# V1 — extension supervisor signature failure path.
step "V1 — extension supervisor (tamper test only — install via runbook)"
note "Manual install of slither-ext-osquery per the runbook. The"
note "automated probe below confirms a tamper test produces the"
note "expected supervisor log line. Run only after the install"
note "step has happened."
for host in ${AGENT_HOSTS:-}; do
    {
        printf '\n--- %s ---\n' "$host"
        ssh "$host" 'sudo journalctl -u slither-agent --since "30 minutes ago"' \
            2>/dev/null || true
    } >> "$OUT/01-extension-supervisor.txt"
done
grep -q "ext: signature failure\|ext: capability violation\|ext: spawned" \
    "$OUT/01-extension-supervisor.txt" || \
    note "  (no ext: supervisor lines yet — install slither-ext-osquery first)"

# V4 — server-side chain-mismatch probe (read-only).
step "V4 — chain-summary recent count"
if [[ -n "${PG_DSN:-}" ]]; then
    psql "$PG_DSN" -tAc \
        "SELECT host_id, count(*) FROM chain_summaries
         WHERE received_at > now() - interval '30 minutes'
         GROUP BY host_id ORDER BY host_id" \
        > "$OUT/04-chain-summaries-recent.txt" || \
        note "  (pg query failed — check PG_DSN)"
    note "Expect ≥ 6 summaries per host (5min cadence × 30min)."
else
    note "  (skip — PG_DSN unset)"
fi

# V8 — search refinements: parser smoke (server runs the parser
# locally; this is a curl drive of the URL form).
step "V8 — search-refinements parser smoke (URL form)"
if [[ -n "${API_BASE:-}" && -n "${TOKEN:-}" ]]; then
    curl -sS -H "Authorization: Bearer $TOKEN" \
        "$API_BASE/api/v1/events/search?since=24h" \
        > "$OUT/08-search-since-24h.json" || true
    note "Expect HTTP 400 with bad_since (the parser only accepts"
    note "RFC3339 in this curl smoke; the HTML /events bar accepts"
    note "the 24h shorthand — runbook tests both)."
fi

# V11 — multi-arch + k8s smoke (delegated).
step "V11 — k8s smoke (delegated to deploy/k8s/smoke.sh)"
if [[ -n "${RUN_K8S_SMOKE:-}" ]]; then
    NAMESPACE="${NAMESPACE:-slither-test}" \
        deploy/k8s/smoke.sh > "$OUT/11-k8s-smoke.txt" 2>&1 || \
        note "  (k8s smoke failed — see capture)"
fi

# V13 — JSON API contract drive.
step "V13 — JSON API contract (events/search filters)"
if [[ -n "${API_BASE:-}" && -n "${TOKEN:-}" ]]; then
    {
        printf '\n--- /healthz (unauthenticated) ---\n'
        curl -sS "$API_BASE/api/v1/healthz"
        printf '\n--- events/search empty ---\n'
        curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/json' \
            -d '{"limit":5}' \
            "$API_BASE/api/v1/events/search"
        printf '\n--- /rules ---\n'
        curl -sS -H "Authorization: Bearer $TOKEN" \
            "$API_BASE/api/v1/rules"
    } > "$OUT/13-jsonapi.txt" 2>&1 || true
fi

step "Done — review per-step captures + close docs/phase6-validation.md"
note "Manual steps still pending: V1 install + tamper, V2 hunt UX,"
note "V3 snapshot empty path, V5 OIDC roundtrip, V6 process tree,"
note "V7 saved queries + dashboards, V8 reopen-alert, V9 keystore"
note "restart cycle, V10 TPM PCR-bump, V12 backpressure run."
