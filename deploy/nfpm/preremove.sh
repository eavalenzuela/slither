#!/usr/bin/env bash
# Phase 5 #92 — preremove hook. Runs before the package payload is
# removed. Stop the service cleanly if running so the binary isn't
# yanked out from under the live agent.

set -euo pipefail

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active slither-agent.service >/dev/null 2>&1; then
        systemctl stop slither-agent.service >/dev/null 2>&1 || true
    fi
    systemctl disable slither-agent.service >/dev/null 2>&1 || true
fi
