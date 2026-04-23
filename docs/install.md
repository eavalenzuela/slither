# Installing the Slither agent

Phase 1 install is intentionally unpackaged — copy a binary, write a
config, drop in the systemd unit. `.deb` / `.rpm` land in Phase 5.

## Prerequisites

### Runtime (target host)

- Linux kernel ≥ 5.10 with BTF exposed at `/sys/kernel/btf/vmlinux`.
  Verify with `ls /sys/kernel/btf/vmlinux`. Kernels without BTF are
  unsupported (see IMPLEMENTATION.md §3.10).
- systemd ≥ 245 (for `CAP_BPF` / `CAP_PERFMON` in `CapabilityBoundingSet`).
- root on the host being installed.
- `stress-ng` — only if you plan to run `make load-test` on the target
  (Phase 1 exit criterion #3). Debian/Ubuntu: `apt-get install stress-ng`;
  RHEL/Rocky: `dnf install stress-ng` (EPEL).
- On **Debian** (11/12/13): lower `kernel.perf_event_paranoid` to 2 —
  Debian defaults it to 3, at which level tracepoint `perf_event_open`
  demands `CAP_SYS_ADMIN` and `CAP_PERFMON` is rejected. RHEL and
  Ubuntu already default to 2. Use the shipped drop-in:

  ```bash
  sudo install -m0644 deploy/sysctl.d/99-slither.conf /etc/sysctl.d/99-slither.conf
  sudo sysctl --system
  ```

The shipped agent binary is a statically linked Go binary with the BPF
object embedded via `bpf2go` — no libbpf, no kernel headers, no runtime
Go toolchain required on the target.

### Build (dev host, only if you build from source)

- Go 1.24+ (`go version`). RHEL 9 ships Go 1.21; use the
  [official tarball](https://go.dev/dl/) if the distro lags.
- clang 16+ and llvm (`clang --version`) — required for `make gen-bpf`
  to regenerate bpf2go outputs. Not needed if you build from a clean
  checkout that already has the generated files committed.
- `make`, `git`.
- Distro packages:
  - Debian 13 / Ubuntu 22.04+: `apt-get install -y golang-1.24 clang llvm libbpf-dev linux-headers-$(uname -r)`
  - RHEL 9 / Rocky 9: `dnf install -y golang git clang llvm libbpf-devel kernel-devel`

See `docs/dev-setup.md` for the full dev-host bootstrap.

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

The repo ships a starter rule pack under `rules/linux/`. Copy it to the
install path referenced by `agent.yaml`:

```bash
sudo install -m0644 rules/linux/*.yml /etc/slither/rules/
```

The bundled pack covers reverse-shell patterns, SUID discovery, sensitive
file writes (`authorized_keys`, cron persistence, rc-file persistence,
`/etc/shadow` access), and IMDS/cloud-metadata egress. An empty rules set
is also valid — the agent runs without detections.

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

**`attach sched/sched_process_exec: opening tracepoint perf event: permission denied`** —
`kernel.perf_event_paranoid` is > 2. Debian ships this at 3 by default;
the CAP_PERFMON the unit grants is not enough at that level. Check with
`cat /proc/sys/kernel/perf_event_paranoid`, then apply the shipped
sysctl drop-in (`deploy/sysctl.d/99-slither.conf`) or one-shot
`sudo sysctl -w kernel.perf_event_paranoid=2` and restart the service.

**`config: invalid: unknown key "collecor" — did you mean "collectors"?`** —
fix the typo; the loader is strict. Full key list in §3.7.

**Reload silently did nothing** — check stderr / journal for a parse or
rule-compile error. Hot reload only swaps rules + file filters; changes
to `collectors.*.enabled`, `output`, or `agent.*` require a restart.
