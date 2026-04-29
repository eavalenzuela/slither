#!/usr/bin/env bash
# Drive the 5 stateless edge rules in one pass. Each rule fires a
# DetectionFinding; the validation step is to grep the agent journal +
# /alerts page for matching rule_uids.
#
# Run on any agent host. Safe — every action targets a temp file or a
# documentation IP.

set -uo pipefail

run() {
    local label=$1; shift
    echo "▶ $label: $*"
    "$@" || true
    sleep 1
}

# 1. Bash reverse shell pattern: any /bin/bash with /dev/tcp in argv
#    fires proc-bash-reverse-shell. We don't actually open the socket;
#    process_creation triggers on the exec.
run "bash-reverse-shell"        bash -c 'true /dev/tcp/198.51.100.5/4444'

# 2. /etc/passwd read by an interactive process: file-event
run "passwd-read"               cat /etc/passwd

# 3. base64 decode into sandbox dir
run "base64-sandbox"            sh -c 'echo cGhhc2UzCg== | base64 -d > /tmp/phase3-b64.out'

# 4. chmod world-writable on a file under /tmp
run "chmod-world-writable"      sh -c 'touch /tmp/phase3-ww && chmod 0777 /tmp/phase3-ww'

# 5. /etc/shadow access (will fail without root; the open syscall fires
#    the file-event rule regardless of the failed perms.)
run "shadow-access"             sh -c 'cat /etc/shadow > /dev/null 2>&1 || true'

echo "stateless edge scenarios complete"
