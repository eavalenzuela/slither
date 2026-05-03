#!/usr/bin/env bash
# Regression check for Phase 5 #103 V1 cosmetic gap (b): /var/log/slither
# came back at 0755 not 0700 after apt reinstall on Debian. Fix applied
# in postinstall.sh §4 — per-dir chmod with explicit ordering.
#
# Strategy: run postinstall.sh against a sandboxed root via the
# SLITHER_STATE_ROOT env-var seam, with sysctl + systemctl stripped from
# PATH so the early branches no-op, and assert the dir-mode block lands
# /var/log/slither at 0700 even when the dir pre-exists at 0755.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POSTINSTALL="${SCRIPT_DIR}/postinstall.sh"

if [ ! -x "$POSTINSTALL" ] && [ ! -f "$POSTINSTALL" ]; then
    echo "FAIL: postinstall.sh not found at $POSTINSTALL" >&2
    exit 1
fi

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/var/lib/slither"
mkdir -p "$ROOT/var/log/slither"
mkdir -p "$ROOT/etc/slither"
chmod 0755 "$ROOT/var/log/slither"
chmod 0755 "$ROOT/var/lib/slither"

# Run with PATH that excludes sysctl + systemctl so section 1-3
# short-circuit cleanly. /usr/bin must stay so chmod/chown/mkdir/stat
# resolve; we only need to hide the host-management binaries.
SANDBOX_PATH=$(mktemp -d)
trap 'rm -rf "$ROOT" "$SANDBOX_PATH"' EXIT
for b in chmod chown mkdir stat ln cat; do
    if command -v "$b" >/dev/null 2>&1; then
        ln -sf "$(command -v "$b")" "$SANDBOX_PATH/$b"
    fi
done
SLITHER_STATE_ROOT="$ROOT" PATH="$SANDBOX_PATH" /bin/bash "$POSTINSTALL" >/dev/null 2>&1 || true

mode_log=$(stat -c '%a' "$ROOT/var/log/slither")
mode_lib=$(stat -c '%a' "$ROOT/var/lib/slither")
mode_etc=$(stat -c '%a' "$ROOT/etc/slither")

fail=0
if [ "$mode_log" != "700" ]; then
    echo "FAIL: /var/log/slither mode = $mode_log, want 700"
    fail=1
fi
if [ "$mode_lib" != "700" ]; then
    echo "FAIL: /var/lib/slither mode = $mode_lib, want 700"
    fail=1
fi
if [ "$mode_etc" != "755" ]; then
    echo "FAIL: /etc/slither mode = $mode_etc, want 755"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: postinstall.sh §4 lands all three dir modes correctly."
fi
exit "$fail"
