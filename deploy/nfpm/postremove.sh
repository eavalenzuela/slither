#!/usr/bin/env bash
# Phase 5 #92 — postremove hook. Runs after the package payload is
# removed. Cleans up sysctl drop-in + reloads systemd, but PRESERVES
# operator data:
#
#   /var/lib/slither/quarantine/  — quarantined files (operator must
#                                    decide whether to restore/discard)
#   /var/lib/slither/buffer/      — Phase 5 #96 offline event buffer
#   /etc/slither/agent.yaml       — operator's hand-edited config
#   /etc/slither/                 — the cert + key directory
#
# These survive uninstall so re-installing the package (or migrating
# to a new version via `apt install`) doesn't lose audit history or
# force a re-enrollment. The deb's `purge` action is the explicit way
# to wipe everything; we don't intercept that path here.

set -euo pipefail

# Re-apply sysctl defaults — removing /etc/sysctl.d/99-slither.conf
# means perf_event_paranoid reverts to the kernel default on next
# `sysctl --system` (or boot). Run it now so the change is visible
# immediately, matching the install-time symmetry.
if command -v sysctl >/dev/null 2>&1; then
    sysctl --system >/dev/null 2>&1 || true
fi

# Reload systemd so the unit file removal is reflected in
# `systemctl list-units`.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
