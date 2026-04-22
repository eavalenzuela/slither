#!/usr/bin/env bash
# Triggers file-authorized-keys-write.yml — any process writing a path
# containing `/.ssh/authorized_keys`. Harmless: writes under $1 (a tempdir).
set -u
dir="${1:?usage: $0 WORKDIR}"
mkdir -p "$dir/.ssh"
printf 'ssh-ed25519 AAAA-slither-scenario-test\n' > "$dir/.ssh/authorized_keys"
exit 0
