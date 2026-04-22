#!/usr/bin/env bash
# Triggers proc-bash-reverse-shell.yml — bash invoked with /dev/tcp.
# Harmless: targets 127.0.0.1 on an unused high port, 1s timeout.
set -u
exec bash -c 'exec 3<>/dev/tcp/127.0.0.1/1 || true' &
pid=$!
( sleep 1; kill -9 "$pid" 2>/dev/null || true ) &
wait "$pid" 2>/dev/null || true
exit 0
