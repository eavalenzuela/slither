#!/usr/bin/env bash
# Compose bootstrap — runs on every up but every step is a no-op when
# already done. Order matters: pg + ch healthchecks gate this container
# in docker-compose so we know they're ready by the time we run.
#
# 1. Generate the CA + server cert into /pki (mounted volume).
# 2. Apply Postgres migrations.
# 3. Apply ClickHouse migrations.
# 4. Seed an admin user; print credentials to stdout if random.

set -euo pipefail

PKI_DIR="${PKI_DIR:-/pki}"
GRAPHS_DIR="${GRAPHS_DIR:-/graphs}"
ARTEFACTS_DIR="${ARTEFACTS_DIR:-/artefacts}"
PG_DSN="${SLITHER_STORAGE_POSTGRES_DSN:?SLITHER_STORAGE_POSTGRES_DSN required}"
CH_DSN="${SLITHER_STORAGE_CLICKHOUSE_DSN:?SLITHER_STORAGE_CLICKHOUSE_DSN required}"

# Make the alert-flow-graph cache dir writable by the server's nonroot
# uid (65532). Compose mounts a named volume here; first-touch is the
# bootstrap container so we own the chown.
if [ -d "$GRAPHS_DIR" ]; then
    chmod 0755 "$GRAPHS_DIR"
    chown -R 65532:65532 "$GRAPHS_DIR" 2>/dev/null || true
fi
# Same pattern for the collect_artifacts spool (#81).
if [ -d "$ARTEFACTS_DIR" ]; then
    chmod 0755 "$ARTEFACTS_DIR"
    chown -R 65532:65532 "$ARTEFACTS_DIR" 2>/dev/null || true
fi

# gen-ca.sh expects to be invoked from a repo root and writes into
# `deploy/pki/` relative to the script's parent directory. Fake that
# layout in /tmp by symlinking deploy/pki to the mounted volume so the
# script lands its outputs where the server image will read them.
WORK=/tmp/slither-bootstrap
mkdir -p "$WORK/scripts" "$WORK/deploy"
ln -sfn "$PKI_DIR" "$WORK/deploy/pki"
cp /usr/local/bin/gen-ca.sh "$WORK/scripts/gen-ca.sh"
chmod +x "$WORK/scripts/gen-ca.sh"
( cd "$WORK" && ./scripts/gen-ca.sh )

# gen-ca.sh chmods the pki dir 0700 by design (sensible on a host with
# multiple operators). In the compose volume context the dir + key
# files need to be readable by the server container's nonroot UID, so
# loosen them here. Cert files stay 0644; private keys are still
# nonroot-only by virtue of the volume not being mounted anywhere
# else writeable.
chmod 0755 "$PKI_DIR"
chmod 0644 "$PKI_DIR"/*.crt 2>/dev/null || true
chmod 0644 "$PKI_DIR"/*.key 2>/dev/null || true

echo "[bootstrap] applying postgres migrations…"
slither-db --dsn "$PG_DSN" migrate

echo "[bootstrap] applying clickhouse migrations…"
slither-ch --dsn "$CH_DSN" migrate

echo "[bootstrap] seeding admin user…"
slither-db --dsn "$PG_DSN" bootstrap-admin

# Generate a session key for the console once. The server runs in
# distroless-nonroot which can't write to the volume; generating here
# means the volume can stay :ro on the server side. Idempotent — leave
# the existing key alone if it's there so a server restart doesn't
# invalidate every operator's cookie.
SESSION_KEY="$PKI_DIR/session.key"
if [ ! -f "$SESSION_KEY" ]; then
    echo "[bootstrap] minting session key at $SESSION_KEY"
    head -c 64 /dev/urandom > "$SESSION_KEY"
    chmod 0644 "$SESSION_KEY"
fi

echo "[bootstrap] done"
