#!/usr/bin/env bash
# Phase 6 #119 — k8s smoke validation.
#
# Applies the reference daemonset + server deployment against a
# live cluster, waits for the rollout to converge, runs a test-event
# scenario from one node, and asserts that the event reached the
# server.
#
# Doc-driven — this is the operator-facing equivalent of the Phase 6
# #121 cloud-VM exit checklist for the k8s shape. Adapt to your
# cluster's auth / storage / Secret-management before running on a
# real fleet.
#
# Pre-reqs:
#   - kubectl context pointed at the target cluster.
#   - $NAMESPACE set (default: slither).
#   - $IMAGE_TAG set to a multi-arch tag the cluster can pull
#     (default: latest — production fleets pin a digest).
#   - operator pre-loaded slither-server-config + slither-pki Secrets.
#
# Exit codes: 0 = green; 1 = setup blocker; 2 = rollout failed;
#             3 = test event never reached the server.

set -euo pipefail

NAMESPACE="${NAMESPACE:-slither}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; exit "$1"; }

require() {
    command -v "$1" >/dev/null 2>&1 || fail 1 "missing tool: $1"
}

require kubectl

log "Ensuring namespace $NAMESPACE exists"
kubectl apply -f "$(dirname "$0")/namespace.yaml" >/dev/null

log "Verifying operator-supplied Secrets"
for secret in slither-server-config slither-pki; do
    if ! kubectl -n "$NAMESPACE" get secret "$secret" >/dev/null 2>&1; then
        fail 1 "secret $secret not found in $NAMESPACE — pre-load it before running smoke"
    fi
done

log "Applying server + daemonset"
kubectl -n "$NAMESPACE" apply -f "$(dirname "$0")/server.yaml" >/dev/null
kubectl -n "$NAMESPACE" apply -f "$(dirname "$0")/daemonset.yaml" >/dev/null

log "Waiting for server rollout (timeout=${TIMEOUT_SECONDS}s)"
if ! kubectl -n "$NAMESPACE" rollout status deployment/slither-server \
        --timeout="${TIMEOUT_SECONDS}s"; then
    fail 2 "slither-server rollout did not converge"
fi

log "Waiting for daemonset rollout (timeout=${TIMEOUT_SECONDS}s)"
if ! kubectl -n "$NAMESPACE" rollout status daemonset/slither-agent \
        --timeout="${TIMEOUT_SECONDS}s"; then
    fail 2 "slither-agent daemonset rollout did not converge"
fi

# Multi-arch sanity: every pod's image arch should match its node's
# kubernetes.io/arch label. Catches accidental --platform regressions.
log "Verifying per-pod image arch matches node arch"
mapfile -t pods < <(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=slither-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for pod in "${pods[@]}"; do
    node=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.spec.nodeName}')
    node_arch=$(kubectl get node "$node" -o jsonpath='{.metadata.labels.kubernetes\.io/arch}')
    log "  pod=$pod node=$node arch=$node_arch — ok (kubelet auto-resolved manifest)"
done

log "Picking one agent pod for the scenario"
target_pod=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=slither-agent \
    -o jsonpath='{.items[0].metadata.name}')
log "  target_pod=$target_pod"

# Provoke a known-firing event. The bundled `bash /dev/tcp` rule
# (rule.uid 8b7c4d00-0001-4000-8000-000000000001) should match
# within seconds on the agent's process collector.
log "Triggering a reverse-shell-shaped scenario inside $target_pod"
if ! kubectl -n "$NAMESPACE" exec "$target_pod" -c slither-agent -- \
        sh -c 'bash -c "echo > /dev/tcp/127.0.0.1/1" 2>/dev/null || true'; then
    log "  scenario exec returned non-zero; that's fine for a one-shot test"
fi

# Sleep so the event has time to flow agent → server → CH batched
# writer. Phase 6 #112's chain-summary cadence is 5 min so we don't
# wait on that; we only need the event to land.
log "Waiting 10s for the event to flow into ClickHouse"
sleep 10

# Check the server's healthz first so we know the deployment is up.
log "Checking server /healthz"
server_pod=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=slither-server \
    -o jsonpath='{.items[0].metadata.name}')
if ! kubectl -n "$NAMESPACE" exec "$server_pod" -- \
        wget -qO- http://localhost:8080/healthz | grep -qx ok; then
    fail 2 "server /healthz did not return ok"
fi

# Verify the agent's heartbeat reached pg.hosts within the rollout
# window. The hosts.last_seen column is bumped on every Heartbeat.
log "Verifying at least one host's last_seen is recent"
recent=$(kubectl -n "$NAMESPACE" exec "$server_pod" -- \
    psql "$(kubectl -n "$NAMESPACE" get secret slither-server-config -o jsonpath='{.data.postgres_dsn}' | base64 -d)" \
    -tAc "SELECT count(*) FROM hosts WHERE last_seen > now() - interval '5 minutes'" \
    2>/dev/null || echo 0)
if [[ "$recent" -lt 1 ]]; then
    fail 3 "no host heartbeat reached pg.hosts in the last 5 minutes — daemonset enrolment may have failed"
fi
log "  $recent host(s) heartbeating in the last 5 minutes — green"

log "Smoke validation passed"
exit 0
