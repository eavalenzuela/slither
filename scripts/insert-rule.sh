#!/usr/bin/env bash
# scripts/insert-rule.sh — push a Sigma rule into the running compose
# stack's rules table after compile-validating it via pkg/ruleast.
#
# Wraps `slither-db insert-rule` inside the compose bootstrap image (it
# already ships the binary + has Postgres reachability via the compose
# network) so operators don't need a Go toolchain on the host. Mounts
# the YAML read-only and runs the container with `run --rm` so each
# invocation is fresh — no state leaks between runs.
#
# Usage:
#   scripts/insert-rule.sh path/to/rule.yml [--enabled=false] [--updated-by USERNAME]
#
# Behaviour:
#   - YAML must compile via pkg/ruleast.CompileSigma; the rule's `id`
#     becomes the row uid.
#   - The row is upserted: re-running with the same uid edits in place.
#   - --updated-by defaults to "admin" (matches bootstrap-admin's seed).
#
# Exits non-zero on compile failure, missing user, or DB error so CI
# wrapping is straightforward.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <yaml-path> [--enabled=false] [--updated-by USERNAME]" >&2
    exit 2
fi

YAML="$1"
shift
if [[ ! -f "$YAML" ]]; then
    echo "error: $YAML is not a regular file" >&2
    exit 2
fi
YAML_ABS="$(realpath "$YAML")"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deploy/compose/docker-compose.yml"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found in PATH" >&2
    exit 2
fi
if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "error: $COMPOSE_FILE not found" >&2
    exit 2
fi

# Forward any remaining flags (--enabled, --updated-by, ...) verbatim
# to the slither-db subcommand. The container sees the YAML at /rule.yml.
exec docker compose -f "$COMPOSE_FILE" run --rm \
    --no-deps \
    --entrypoint slither-db \
    -v "$YAML_ABS:/rule.yml:ro" \
    bootstrap insert-rule --file /rule.yml "$@"
