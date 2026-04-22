# Installing the Slither agent

Phase 1 install is intentionally unpackaged — copy a binary, write a
config, drop in the systemd unit. `.deb` / `.rpm` land in Phase 5.

## Prerequisites

- Linux kernel ≥ 5.10 with BTF exposed at `/sys/kernel/btf/vmlinux`.
  Verify with `ls /sys/kernel/btf/vmlinux`. Kernels without BTF are
  unsupported (see IMPLEMENTATION.md §3.10).
- systemd ≥ 245 (for `CAP_BPF` / `CAP_PERFMON` in `CapabilityBoundingSet`).
- root on the host being installed.

## 1. Build (or copy) the binary

From a dev host:

```bash
make build-agent          # produces bin/slither-agent
```

Then copy onto the target:

```bash
sudo install -Dm0755 bin/slither-agent /usr/local/bin/slither-agent
```

## 2. Write the config

```bash
sudo install -d -m0755 /etc/slither /etc/slither/rules
sudo install -m0644 deploy/config/agent.yaml.sample /etc/slither/agent.yaml
sudo install -d -m0750 /var/lib/slither /var/log/slither
```

Edit `/etc/slither/agent.yaml` to taste. Schema lives at
IMPLEMENTATION.md §3.7; validation errors are actionable (unknown keys
yield "did you mean?" hints).

Drop Sigma rules under `/etc/slither/rules/` matching the glob in the
config. An empty rules set is valid — the agent runs without detections.

### Environment variable overrides

The config loader honours a small set of `SLITHER_*` env vars as
late-binding overrides (see `agent/internal/config/config.go`):

| Env var                              | Overrides                          |
| ------------------------------------ | ---------------------------------- |
| `SLITHER_AGENT_LOG_LEVEL`            | `agent.log_level`                  |
| `SLITHER_AGENT_HOST_ID_FILE`         | `agent.host_id_file`               |
| `SLITHER_OUTPUT_KIND`                | `output.kind`                      |
| `SLITHER_COLLECTORS_PROCESS_ENABLED` | `collectors.process.enabled`       |
| `SLITHER_COLLECTORS_FILE_ENABLED`    | `collectors.file.enabled`          |
| `SLITHER_COLLECTORS_NET_ENABLED`     | `collectors.net.enabled`           |
| `SLITHER_RULES_PATHS`                | `rules.paths` (comma-separated)    |

Set them in a systemd drop-in (`/etc/systemd/system/slither-agent.service.d/override.conf`):

```ini
[Service]
Environment=SLITHER_AGENT_LOG_LEVEL=debug
```

## 3. Install the systemd unit

```bash
sudo install -m0644 deploy/systemd/slither-agent.service \
    /etc/systemd/system/slither-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now slither-agent.service
```

Verify:

```bash
systemctl status slither-agent.service
journalctl -u slither-agent.service -f
```

With `output.kind: stdout`, OCSF events land in the journal. Swap to
`grpc` in Phase 2 once the server handshake exists.

## 4. Reloading rules and file filters

The agent handles `SIGHUP` as a hot reload for **rules + file-collector
include/exclude paths**. Everything else (collectors, hashing pool,
device identity) is startup-fixed and requires a full restart.

```bash
sudo systemctl reload slither-agent.service    # sends SIGHUP
# or
sudo kill -HUP "$(systemctl show --property MainPID --value slither-agent.service)"
```

If the reloaded config fails to parse or compile, the agent logs the
error to stderr and keeps running with the previous config — it does not
replace the live config on error.

## 5. Uninstall

```bash
sudo systemctl disable --now slither-agent.service
sudo rm /etc/systemd/system/slither-agent.service
sudo systemctl daemon-reload
sudo rm /usr/local/bin/slither-agent
sudo rm -rf /etc/slither /var/lib/slither /var/log/slither
```

## Why the unit runs as root with `NoNewPrivileges=no`

Both are deliberate. See the comments in
`deploy/systemd/slither-agent.service`:

- **Root + `CapabilityBoundingSet`** caps what the agent can ever acquire
  (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`),
  which is meaningfully tighter than full root without buying the
  complexity of a dedicated service user that still needs the same caps.
- **`NoNewPrivileges=no`** stays off because some 5.x kernels (notably
  RHEL 9 / 5.14) reject `bpf(BPF_PROG_LOAD)` with `no_new_privs` set
  when the program type requires `CAP_PERFMON`. Until we drop support
  for those kernels this flag must remain off for the loader to
  succeed. Other hardening (`ProtectSystem`, `ProtectHome`,
  `ProtectKernelLogs`, `RestrictSUIDSGID`, `LockPersonality`, ...) still
  applies independently.

## Troubleshooting

**`failed to load BPF program: operation not permitted`** — verify
`CapabilityBoundingSet` is set on the running process
(`cat /proc/$(pidof slither-agent)/status | grep CapBnd`) and that BTF
is present. On a container host, check `docker info | grep -i btf` and
whether the container has `CAP_BPF`/`CAP_PERFMON`.

**`config: invalid: unknown key "collecor" — did you mean "collectors"?`** —
fix the typo; the loader is strict. Full key list in §3.7.

**Reload silently did nothing** — check stderr / journal for a parse or
rule-compile error. Hot reload only swaps rules + file filters; changes
to `collectors.*.enabled`, `output`, or `agent.*` require a restart.
