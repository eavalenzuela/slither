#!/usr/bin/env bash
# Phase 5 #92 — postinst hook for the slither-agent deb/rpm package.
#
# Runs after the package contents are unpacked. Idempotent across
# upgrades and re-installs. Does NOT auto-start the service — the
# operator must run `slither-agent enroll` first to obtain a client
# cert before the agent can talk to a server.

set -euo pipefail

# 1. Apply the sysctl drop-in immediately so the agent doesn't trip on
#    Debian's perf_event_paranoid=3 default at first start.
#    /etc/sysctl.d/99-slither.conf was placed by the package payload.
if command -v sysctl >/dev/null 2>&1; then
    if [ -f /etc/sysctl.d/99-slither.conf ]; then
        sysctl --system >/dev/null 2>&1 || true
    fi
fi

# 2. Reload systemd so the new (or changed) unit file is visible.
#    daemon-reload is cheap; running it on every install/upgrade is
#    the defensive default packaging convention.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true

    # 3. Enable the unit so it starts automatically on next boot, but
    #    DO NOT start it now. The agent needs a client cert before it
    #    can reach a server; the operator runs `slither-agent enroll`
    #    next, which provisions the cert + writes /etc/slither/agent.yaml.
    #    After that, `systemctl start slither-agent` brings it up.
    systemctl enable slither-agent.service >/dev/null 2>&1 || true

    # On upgrade where the unit was already running, restart so the
    # operator picks up the new binary. `try-restart` is a no-op if
    # the unit isn't currently active, which matches the "fresh
    # install never auto-starts" rule above.
    systemctl try-restart slither-agent.service >/dev/null 2>&1 || true
fi

# 4. Tighten state-dir permissions. systemd's StateDirectory= would
#    create /var/lib/slither at first activation with mode 0700, but
#    the package owns the directory now so we set the mode explicitly.
#    Existing data is preserved.
chown root:root /var/lib/slither /var/log/slither /etc/slither 2>/dev/null || true
chmod 0700      /var/lib/slither /var/log/slither            2>/dev/null || true
chmod 0755      /etc/slither                                  2>/dev/null || true

cat <<'EOF'

slither-agent installed.

Next steps:

  1. Mint an enrolment token on the server:
       slither-server enroll mint --ttl=1h

  2. Run enrolment on this host (provisions client cert + writes config):
       sudo slither-agent enroll \
           --server-addr=YOUR-SERVER:9444 \
           --token=THE-TOKEN \
           --ca-cert=/path/to/ca.crt

  3. Start the service:
       sudo systemctl start slither-agent

The unit is already enabled — it will auto-start on next boot once
configured.

EOF
