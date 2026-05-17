# Detection Theorycrafting

Working document for mapping out new Sigma rules to add to `rules/linux/`.
Not committed-to-ship — entries here graduate to YAML once they've been
sanity-checked for signal, noise, and data feasibility.

## Ground rules for this doc

1. **Every proposed rule names the conjunction that makes it fire.** A field
   selection on its own (`Image|endswith /python`) is hunting, not detection.
   The "what makes this not noisy" line is mandatory.
2. **Every proposed rule names the data dependency.** If the rule needs a
   field or collector we don't ship today, mark it **BLOCKED** and link to
   the IMPLEMENTATION.md task that unblocks it.
3. **Severity discipline.** `high`/`critical` rules pop on the dashboard and
   train the operator. Reserve them for findings that justify response.
   Default to `medium`. `low`/`informational` is reserved for the future
   hunt tier (Phase 3+) — do not ship a low-sev rule today.

## What we have today (data plane)

OCSF classes the agent currently emits (Phase 1 complete):

| Class | Class UID | Source | Fields the rule engine binds today |
|---|---|---|---|
| `process_activity` | 1007 | `process.bpf.c` | `Image`, `CommandLine`, `User`, `ProcessId`, `ParentImage`, `ParentCommandLine`, `ParentProcessId` |
| `file_activity` | 1001 | `file.bpf.c` | `Image`, `CommandLine`, `User` (actor) + path/op (matched via filter, not Sigma fields yet) |
| `network_activity` | 4001 | `net.bpf.c` | `Image`, `CommandLine`, `User` (actor) + dst port/IP (filter only, not Sigma fields yet) |
| `detection_finding` | 2004 | rule engine | (not a detection source — it's the output) |

**Open data gaps that limit detection design:**

- ~~`file_activity` rules can't match the target path in Sigma syntax.~~
  **Corrected 2026-05-17:** this gap does not exist. `pkg/ruleeval/fields.go`
  already maps `TargetFilename` (plus `Filename` / `Path` aliases) onto the
  file event's path, and eight shipped `file-*` rules use it
  (`TargetFilename|startswith: /etc/cron.d/` etc.). Backlog #5/#9/#10 were
  marked BLOCKED on a field that already existed — they shipped with no
  engine work.
- No `User` resolution beyond UID/name as captured at enrich time. No group
  membership, no `setuid`/`setgid` flagging on the exec event itself. T1548
  (Abuse Elevation) detection is hampered.
- No DNS payload (we get TCP/UDP 5-tuples but not the queried name). T1071.004
  detection is limited to "egress to known sus port" + "process is dig/host/
  resolv-style binary" via cmdline. No real DGA or tunnel detection.
- No process tree beyond immediate parent (`ParentImage`, `ParentCommandLine`).
  No grandparent chain. Limits living-off-the-land rules where the smoking
  gun is "shell ⇒ shell ⇒ shell" depth.
- No persistent state across events (Phase 3 deliverable). Eliminates
  threshold/sequence/correlation rules: brute-force, scan-and-exploit,
  recon-burst, beaconing-cadence.

## Coverage map (current pack vs ATT&CK)

Tactic-by-tactic snapshot of what's in `rules/linux/` right now (51 rules).

### Initial Access
- **None directly.** Initial access is mostly network-edge, which is out of
  scope for an endpoint sensor. Closest is `proc-curl-pipe-shell` (T1059 +
  T1105 hybrid).

### Execution (T1059)
- ✅ `proc-bash-reverse-shell` (T1059.004)
- ✅ `proc-nc-reverse-shell` (T1059.004)
- ✅ `proc-curl-pipe-shell` (T1059.004 + T1105)
- ✅ `proc-python-inline-script` (T1059.006, tightened with payload tokens)
- ✅ `proc-exec-from-world-writable` (T1059.004, tightened with parent excl.)
- **Gaps:** perl/ruby one-liners (analogous to python), `awk system()`,
  `gawk @load`, busybox unusual subcommand misuse, `osascript`-style binary
  abuse (no Linux equivalent), in-memory loaders via `memfd_create` (needs
  syscall trace).

### Persistence (T1053, T1136, T1543, T1546)
- ✅ `file-cron-persistence` (T1053.003 cron)
- ✅ `file-rc-persistence` (T1037 boot/login init)
- ✅ `file-authorized-keys-write` (T1098.004 ssh keys)
- ✅ `proc-at-job-schedule` (T1053.001 at, parallel) — verify
- ✅ `file-systemd-user-unit-write` (T1543.002 user systemd, parallel) — verify
- ✅ `file-motd-script-drop` (T1037.004 motd, parallel) — verify
- ✅ `file-systemd-system-unit-write` (T1543.002 system unit)
- ✅ `file-ld-preload-write` (T1574.006 dynamic-linker hijack)
- **Gaps:** `update-alternatives` link manipulation, `/etc/profile.d/*`
  script drop, kernel module install (T1547.006). The dotfile `LD_PRELOAD=`
  variant is unreachable — file events carry no content (see backlog #9).

### Privilege Escalation (T1548, T1068)
- ✅ `proc-chmod-world-writable` (T1222.002 perms manipulation)
- ✅ `proc-find-suid-discovery` (T1083 + recon for SUID escalation)
- ✅ `proc-sudo-rights-probe` (T1548.003, parallel) — verify
- **Gaps:** `setcap` invocation (capability escalation), `pkexec` abuse
  (CVE-2021-4034 family), `unshare`/`nsenter` unusual invocation, `dirtypipe`
  artefact patterns. Most of T1068 is exploit-specific and best caught by
  collector-level signals (e.g. `bpf_probe_read_kernel` from non-root) which
  we don't have.

### Defence Evasion (T1027, T1070, T1140, T1562)
- ✅ `proc-base64-decode-to-sandbox` (T1140 + T1027)
- ✅ `proc-log-truncate` (T1070.002)
- ✅ `proc-security-tool-disable` (T1562.001 disable security units)
- ✅ `proc-firewall-flush` (T1562.004 firewall flush)
- ✅ `proc-history-disable` (T1070.003 clear command history)
- **Gaps:** `auditctl -D` / `auditctl -e 0` (T1562.001 disable audit
  ruleset specifically), `chattr +i` on log files, `wipe` / `shred`
  against logs.

### Credential Access (T1003, T1552, T1555)
- ✅ `file-etc-shadow-access` (T1003.008 /etc/shadow read)
- ✅ `proc-passwd-file-read` (T1003.008 /etc/passwd read, parallel) — verify
- ✅ `file-aws-credentials-read` (T1552.001, parallel) — verify
- ✅ `proc-keyring-secret-tool` (T1555 keyring abuse, parallel) — verify
- ✅ `proc-procfs-environ-scrape` (T1552.001 env-from-/proc, parallel) — verify
- ✅ `proc-history-cred-grep` (T1552.003 shell history, parallel) — verify
- ✅ `proc-ssh-private-key-access` (T1552.004, parallel) — verify
- ✅ `file-pam-module-drop` (T1556.003 malicious PAM module)
- **Gaps:** GCP/Azure cloud cred files (analogue to AWS), kubeconfig
  read by non-kubectl process, docker config.json read, gnome-keyring DB
  files, browser cookie/login DB files, `gpg --export-secret-keys`,
  `pass`/`gopass` invocation by non-interactive parent.

### Discovery (T1018, T1057, T1082, T1083, T1087)
- ✅ `proc-find-suid-discovery` (T1083)
- ✅ `proc-host-recon-hostnamectl` (T1082, parallel) — verify
- ✅ `proc-network-listen-enum` (T1049, parallel) — verify
- ✅ `proc-process-enum-to-file` (T1057, parallel) — verify
- ✅ `proc-recon-burst` (T1033/T1082/T1087 — stateful identity-recon burst)
- **Gaps:** `/etc/passwd`/`/etc/group` enumeration via `cut`/`awk`, `getent`,
  `ldapsearch` against AD, `arp -a`/`ip neigh` lateral discovery,
  cloud-metadata via DNS (`metadata.google.internal`).

### Lateral Movement
- **None.** Mostly needs network correlation across hosts (Phase 3+).
  Single-host signals: `ssh -o StrictHostKeyChecking=no` (proxying),
  `socat TCP-LISTEN`, `chisel client`/`server`, `frp`, `gost`.

### Collection (T1005, T1056, T1113)
- **None directly.** Mostly file-read patterns that overlap with cred-access.
  Candidates: `tcpdump`/`tshark` invocation by non-root or in user shells,
  `/dev/snd/*` open by non-pulseaudio (mic capture), `xinput` / `xev`
  on `:0` (keylogger).

### Command & Control (T1071, T1090, T1102, T1573)
- ✅ `net-cloud-metadata-egress` (cloud IMDS abuse)
- ✅ `net-tor-port-egress` (T1090.003 multi-hop, parallel) — verify
- ✅ `proc-curl-custom-user-agent` (T1071.001, parallel) — verify
- ✅ `proc-dns-suspicious-query` (T1071.004, parallel) — verify
- ✅ `proc-dns-tunnel-marker` (T1071.004, parallel) — verify
- ✅ `proc-nc-listener` (T1571 non-standard port C2)
- ✅ `net-webhook-beacon` (T1102 / T1567 chat-webhook C2 + exfil)
- **Gaps:** pastebin egress
  (raw.githubusercontent.com from shell, ix.io, transfer.sh), domain-fronted
  CDN POSTs (hard without TLS SNI capture). Beacon-cadence detection is
  Phase 3+.

### Exfiltration (T1041, T1048, T1567)
- **None.** Most exfil patterns require either DNS payload (T1048.003) or
  byte-counting per flow (out of scope for Phase 1 net collector). Single-event
  candidates: `curl -T` / `curl --upload-file`, `scp` to non-bastion host,
  `aws s3 cp` to non-org-bucket, `rclone copy` invocation.

### Impact (T1485, T1486, T1490, T1496)
- ✅ `proc-crypto-miner` (T1496 resource hijacking)
- ✅ `proc-disk-wipe-dd` (T1485 / T1561 — `dd` against block devices)
- ✅ `file-ransomware-marker` (T1486 — ransom-extension file markers)
- **Gaps:** `cryptsetup luksFormat` against a mounted device, `wipefs`,
  mass-rename ransomware thresholding (needs Phase 3 — see below).

## Backlog: proposed rules (next batch)

Ranked roughly by signal/effort. Each entry: **what fires**, **the
disambiguating conjunction**, **severity**, **data dependency**, **noise risk**.

### 1. `proc-security-tool-disable` — high — ✅ SHIPPED (id …036)
- **Fires when:** `systemctl` (or `service`) invoked with `stop|disable|mask|kill`
  AND the unit name is in {`auditd`, `slither-agent`, `osqueryd`,
  `falcon-sensor`, `crowdstrike-falcon`, `falcon-kernel`, `wazuh-agent`,
  `clamav-daemon`, `clamav-freshclam`, `sysmon`}.
- **Why not noisy:** the service-name allowlist is the conjunction — admins
  do `systemctl stop nginx` constantly; nobody benign stops these specific
  units in normal ops.
- **Data:** existing fields. Ship-ready.
- **Shipped 2026-05-17.** Substring match on the unit name carries `.service`
  suffix for free (`auditd` matches `auditd.service`).

### 2. `proc-history-disable` — medium — ✅ SHIPPED (id …037)
- **Fires when:** `Image` is `bash`/`sh`/`zsh` (i.e. interactive shell exec
  via `-c`) AND `CommandLine|contains` any of `history -c`, `HISTFILE=`,
  `HISTSIZE=0`, `unset HISTFILE`, `>~/.bash_history`, `>/dev/null 2>&1; history -c`.
- **Why not noisy:** these idioms are deliberately uncommon. Power users
  occasionally `unset HISTFILE` for sensitive sessions, but it's worth flagging.
- **Data:** existing fields. Ship-ready.
- **Risk:** `.bashrc`/`.zshrc` files that legitimately set `HISTSIZE=0` may
  show up in shell-init exec — verify in testing.
- **Shipped 2026-05-17** as T1070.003. Gated on a `-c` shell invocation, so
  dotfile-sourced `HISTSIZE=0` does not trigger it (no separate exec event).

### 3. `proc-firewall-flush` — high — ✅ SHIPPED (id …038)
- **Fires when:** `iptables -F`, `iptables -X`, `nft flush ruleset`,
  `nft delete table`, `ufw disable`, `ufw reset`, `firewall-cmd --panic-off`
  (panic-off is the inverse but interesting), or `systemctl stop firewalld|nftables|ufw`.
- **Why not noisy:** firewall flush is rare in steady-state ops. Might fire
  during initial provisioning — exclude `ParentImage|endswith` in
  `/cloud-init`/`/ansible-playbook` if it shows.
- **Data:** existing fields. Ship-ready.
- **Shipped 2026-05-17** as T1562.004. Two-branch condition: firewall CLI
  tool + flush flag, OR systemctl/service `stop|disable|mask` against a
  `firewalld`/`nftables`/`ufw` unit. No provisioning-parent exclusion
  shipped yet — add in production if cloud-init noise shows.

### 4. `proc-pkexec-suspicious-env` — high — partially blocked
- **Fires when:** `Image|endswith /pkexec` AND `CommandLine|contains` indicators
  of CVE-2021-4034-style abuse (suspicious env or null-argv patterns).
- **Why not noisy:** pkexec invocations are rare and almost always interactive.
- **Data:** **BLOCKED** on env-vector capture in process_activity. Today we
  only get `Cmdline`. Need `EnvVars` (or at least `LD_*` env vars) bound to
  the rule field. Cost: medium — process.bpf.c would need to read `/proc/[pid]/environ`
  on exec or capture from `bprm->envp`.

### 5. `file-systemd-system-unit-write` — high — ✅ SHIPPED (id …03b)
- **Fires when:** a process writes a `.service`/`.timer`/`.socket` file under
  a systemd system-unit directory AND the writing process is not in
  {dpkg, rpm, systemctl, systemd, systemd-sysv-generator, apt, dnf, yum,
  snapd, unattended-upgrade}.
- **Why not noisy:** writer allowlist excludes the entire legitimate path.
- **Data:** `TargetFilename` already exists (see corrected data-gap note
  above) — no engine work. **Shipped 2026-05-17** as T1543.002. Broadened
  to `.timer`/`.socket` beyond the doc's original `.service`-only scope;
  both are equally valid persistence units.

### 6. `net-webhook-beacon` — medium — ✅ SHIPPED (id …039)
- **Fires when:** process is `curl`/`wget` AND cmdline contains any of
  `discord.com/api/webhooks/`, `api.telegram.org/bot`, `hooks.slack.com/services/`,
  `webhook.site/`, `pipedream.com/`. Excludes parents in CI runners.
- **Why not noisy:** these endpoints aren't called from production shell
  scripts as a rule. CI exclusion handles dev workflows.
- **Data:** existing process_activity fields suffice for the cmdline match.
  A real-net-side rule would need TLS SNI which we don't have (Phase 3?).
- **Shipped 2026-05-17.** Endpoint list resolved to the middle option from
  the open question below: Discord / Telegram / Slack + `webhook.site` +
  Pipedream. CI-runner parent allowlist excludes notification POSTs. ngrok
  staging endpoints deliberately left out — too broad for `medium`.

### 7. `proc-recon-burst` — high — ✅ SHIPPED (id …03e)
- **Fires when:** ≥3 identity/host-recon command executions
  (whoami, id, groups, hostname, uname, w, who, last, lastlog,
  lsb_release, hostnamectl, arch, uptime) sharing one parent shell
  (`count() by ParentProcessId > 2`) within 30s.
- **Why not noisy:** the burst is the signal; any one of these in isolation
  is normal admin behaviour.
- **Data:** ~~BLOCKED on Phase 3 stateful detection.~~ **Unblocked —
  Phase 3 closed 2026-04-29.** The bounded-stateful runtime (#56) and
  `| count() [by F] OP N` + `timeframe` are shipped. **Shipped 2026-05-17**
  as the pack's first stateful rule: 30s window → classifies `edge_only`
  (well under the 300s bounded-stateful cap), fires without a server
  round-trip. Grouping key is `ParentProcessId` — the parent shell PID is
  the available proxy for "same session" (no session-id field today).
  `cat /etc/passwd|os-release` from the doc's original set are *not* in
  the tool list: matching `cat` would dominate the count and swamp the
  signal. /etc/passwd reads are already covered by `proc-passwd-file-read`.

### 8. `proc-crypto-miner` — medium — ✅ SHIPPED (id …03a)
- **Fires when:** `Image|endswith` any of `/xmrig`, `/t-rex`, `/phoenixminer`,
  `/lolminer`, `/teamredminer`, `/nbminer`, `/ethminer`, `/cgminer`, OR
  `CommandLine|contains` `--coin monero`, `--algo cryptonight`, `stratum+tcp://`.
- **Why not noisy:** these binary names and pool URIs are unmistakable.
- **Data:** existing fields. Ship-ready.
- **Caveat:** legitimate mining setups exist; consider ship-default-disabled
  or hosts-with-GPU exclusion later.
- **Shipped 2026-05-17** as T1496. `miner_binary OR miner_cmdline` — either
  a known miner image name or a `stratum+tcp://`-class pool URI / algo flag.
  Ships `status: experimental` like the rest of the pack; default-enabled
  vs -disabled is a server-side `rules.enabled` decision, still open below.

### 9. `file-ld-preload-write` — high — ✅ SHIPPED (id …03c) — partial
- **Fires when:** any process writes to `/etc/ld.so.preload`, excluding
  dpkg/rpm.
- **Data:** `TargetFilename` already exists — no engine work.
  **Shipped 2026-05-17** as T1574.006, severity raised medium→high (a
  global-preload SO is loaded into *every* process — that warrants
  response). The dotfile half of the original idea (a `LD_PRELOAD=` line
  appearing inside `~/.bashrc`) is **not shippable**: file events carry
  the path and writer, not file *content* — there's no collector that
  inspects written bytes. That clause is dropped, not parked.

### 10. `file-pam-module-drop` — high — ✅ SHIPPED (id …03d)
- **Fires when:** a `.so` is written into a PAM module directory
  (`/lib*/security/`, `/usr/lib*/security/`, the multiarch
  `*-linux-gnu/security/` paths) by a process not in
  {dpkg, rpm, apt, apt-get, dnf, yum}.
- **Why not noisy:** PAM module install is exclusively a package-manager
  operation in normal ops.
- **Data:** `TargetFilename` already exists — no engine work.
  **Shipped 2026-05-17** as T1556.003. The doc's "non-root" criterion was
  dropped: a root-level attacker dropping a PAM module is precisely the
  threat, so excluding root would be a hole. Package-manager exclusion
  alone carries the rule.

## Stateful / correlation candidates

Patterns that need the stateful runtime. **Phase 3 closed 2026-04-29** —
the bounded-stateful engine, `count()`/`timeframe`, and edge eligibility
all shipped, so a `count()`-shaped rule with a ≤300s window is now
writeable directly (see `proc-recon-burst`, the first one shipped). The
entries below still need a missing *data source* or a server-side
evaluator, which is why they are not yet rules.

- **Beaconing cadence**: same `(host, dst_ip, dst_port, process)` tuple
  emitting connections at near-constant intervals over ≥10 min. Needs a
  cadence/variance aggregator beyond `count()` — not just a threshold.
- **Failed-then-successful auth**: SSH/sudo failure burst followed by success
  on same `User`. Needs auth event source we don't ship yet.
- **Process-tree depth anomaly**: shell ⇒ shell ⇒ shell ≥ depth-3 from
  non-shell entry (nginx, postgres, sshd). Needs grandparent chain.
- ✅ **Recon burst** (#7 above) — shipped 2026-05-17 as `proc-recon-burst`.
- **Mass-rename ransomware**: ≥N file rename events with new extension
  matching `.crypt|.locked|.encrypted|...` within window. Writeable as a
  stateful file_event rule once a `TargetFilename`-suffix `count()` is
  confirmed to compile — candidate for the next batch.
- **Lateral SSH spread**: same `User` SSH-ing to ≥N internal IPs in window.
  Cross-host correlation; needs the server-side stateful evaluator.

## Decisions / open questions

(captured as we discuss; convert to ADRs if they affect architecture)

- _Should crypto-miner detection ship default-enabled or default-disabled?_
  Still open — rule ships `experimental`; the enable/disable call is the
  server-side `rules.enabled` flag, not the YAML.
- ✅ _Webhook-beacon list — start narrow or wide?_ **Resolved 2026-05-17:**
  shipped the middle option — Discord + Telegram + Slack + `webhook.site`
  + Pipedream. ngrok-style staging endpoints left out as too broad for a
  `medium` rule; revisit if a real incident motivates it.
- _Severity convention: when does a discovery rule justify `high` vs
  `medium`? Current pack is inconsistent — `proc-find-suid-discovery` is
  high, others are medium. Worth a short consistency pass._
- _Operator UX: does flagging a "verify" parallel-process rule above mean
  we re-review them as a batch, or trust the parallel author and audit
  spot-checks only?_
