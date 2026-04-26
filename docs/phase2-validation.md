# Phase 2 exit validation

This is the operator-execution checkpoint that closes Phase 2.
Mirrors the [Phase 1 #29 manual validation](../debian_13_phase1_validation)
pattern: doc-backed runbook, raw outputs captured under
`phase2_validation/` at the repo root. The AI cannot perform this
validation — it requires real agent VMs, real network connectivity
to the compose stack, and real stress-ng workloads.

Per IMPLEMENTATION.md §4.1 task #46:

> bring up `make compose-up`, enroll a fresh agent VM, generate
> process/file/net events, confirm they land in ClickHouse via
> `/events`, confirm a server-pushed rule fires on edge and the
> resulting `DetectionFinding` is also searchable. Also load-test the
> server path: 3 agents × the Phase 1 stress-ng workload (~36k
> events/s aggregate) with `drop_rate_pct` reported at both agent and
> server-subscriber level.

When every step below passes, Phase 2 is closed and Phase 3 (edge
eligibility, stateful detection, hunt) opens per ADR-0019.

## Status (2026-04-26): partial pass, multi-host load test deferred

Steps 1-11 (single-host smoke against 127.0.0.1-bound listeners)
passed end-to-end on 2026-04-25 — every event class lands in
`/events`, server-pushed Sigma rule fires + disable cleanly drops
to 0 active rules. Diagnostic surfaces caught during that pass have
since been closed by §4.2 follow-ups #47-#52 (commit `f6b7bd3`).

Steps 12-14 (3-agent stress-ng load test, drop_rate <1 % on agent +
server) **remain unfinished** and **cannot be marked complete on a
single host**. Single-host runs share CPU between agents and the
compose stack, so the drop-rate numbers are not comparable to Phase
1's per-host baselines and would be misleading if captured.

Phase 2 cannot close without a live load-test pass across separated
hosts — cloud VMs are the recommended path (~$5-20 per run, picks
up the RHEL 10 / Debian 13 kernel matrix in passing). A second
physical machine on the dev LAN is acceptable. Phase 3 prototyping
(edge eligibility, stateful detection seams) may proceed in
parallel; only the formal §4.1 #46 ✅ flip is gated on the load
test.

`§4.1 #46` stays unchecked in `IMPLEMENTATION.md` until those
captures land in `phase2_validation/05-load-test.txt`.

## 0. Prerequisites

**Server host (where compose runs):**

- Linux + Docker 24+ + the `docker compose` plugin.
- 8 GB RAM, 4 vCPUs is plenty for the validation; the load test
  pushes ClickHouse but no individual component is RAM-hungry.

**Agent VMs (≥ 1, three for the load test):**

- Linux 5.15+ kernel with BTF (`/sys/kernel/btf/vmlinux`). The agent
  has been validated on Debian 13 / RHEL 10 — see
  [Phase 1 validation](../debian_13_phase1_validation).
- Network reachability to the server's `9443` (Session) and `9444`
  (Enroll) ports.
- For the load test: `stress-ng` installed.
- For network-event generation: `curl` / `nc` (any TCP-capable tool).

**Operator workstation:**

- A copy of the slither repo, recent enough that `make compose-up`
  is the #40 build and `slither-agent enroll` is the #36 subcommand.

## 1. Bring up the stack

```bash
make compose-up
docker compose -f deploy/compose/docker-compose.yml ps
```

Expect all four containers reporting `healthy` (or `Exited (0)` for
`slither-bootstrap` — that's the one-shot first-run helper):

```
NAME                 STATUS
slither-bootstrap    Exited (0)
slither-clickhouse   Up (healthy)
slither-postgres     Up (healthy)
slither-server       Up (healthy)
```

The bootstrap admin password is fixed at `slither-admin-dev` for the
compose default — see `deploy/compose/docker-compose.yml`.
**Capture** `docker compose ps` output and the bootstrap admin
credential string into `phase2_validation/00-stack-up.txt`.

## 2. Export the CA cert for the agent

```bash
./scripts/export-compose-ca.sh > /tmp/server-ca.crt
scp /tmp/server-ca.crt agent-vm-1:/tmp/server-ca.crt
```

(Repeat for each agent VM.)

## 3. Mint an enrolment token

```
http://localhost:8080 → admin / slither-admin-dev → Enrolment
```

Mint a token with `hostname_hint=agent-vm-1` and `ttl=1h`. Copy the
plaintext exactly once (the page warns you), then run on the agent:

```bash
sudo install -d -m0750 /var/lib/slither
sudo install -m0644 /tmp/server-ca.crt /var/lib/slither/server-ca.crt
sudo slither-agent enroll \
    --server <server>:9444 \
    --token  <PASTED-TOKEN> \
    --ca-cert /var/lib/slither/server-ca.crt \
    --state-dir /var/lib/slither
```

Expected stderr from the agent:

```
enrolled host <UUID>
  key:     /var/lib/slither/client.key
  cert:    /var/lib/slither/client.crt
  ca:      /var/lib/slither/ca.crt
  host_id: /var/lib/slither/host_id
```

**Capture** that block + the resulting host_id into
`phase2_validation/01-enroll.txt`.

## 4. Switch the agent to gRPC output and start it

Edit `/etc/slither/agent.yaml` (use the sample) so `output:` reads:

```yaml
output:
  kind: grpc
  grpc:
    server_addr: <server>:9443
    ca_path:   /var/lib/slither/ca.crt
    cert_path: /var/lib/slither/client.crt
    key_path:  /var/lib/slither/client.key
    host_id_path: /var/lib/slither/host_id
    heartbeat_interval: 30s
    buffer_size: 4096
```

Then enable the systemd unit (per `docs/install.md`):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now slither-agent.service
journalctl -u slither-agent.service -f
```

Expect the journal to log `output_reconnects=0` increasing and no
`output_drop` accumulation under idle load.

## 5. Confirm the agent in `/hosts`

Within ~5 seconds of `slither-agent.service` becoming active, the
console's `/hosts` page should show the host with status **online**
(green badge). After a clean shutdown the badge turns **stale**
within 90 s and **offline** beyond that — verify by `systemctl stop`
and waiting.

**Capture** screenshots or `curl -b … /hosts` HTML into
`phase2_validation/02-hosts.txt`.

## 6. Generate observable events on the agent

On the agent VM, drive each collector class:

```bash
# Process activity (class 1007)
/bin/true

# File-system activity (class 1001)
sudo touch /etc/slither-test-touch && sudo rm /etc/slither-test-touch

# Network activity (class 4001) — connect anywhere reachable
curl -fsS http://example.com >/dev/null
```

In the console, `/events` filtered by `host_id=<UUID>` should now
list rows for each. Open one row of each class — the detail view
should render the OCSF JSON with the trigger pid/path/dst_ip
prefilled.

**Capture** `/events` filtered HTML + one detail page per class
into `phase2_validation/03-events.txt`.

## 7. Server-pushed rule fires on the edge

This proves the #39 rule-distribution path end-to-end. Push the rule
through `scripts/insert-rule.sh`, which compiles it via `pkg/ruleast`
before upserting — bypasses both terminal autoindent (which silently
produces tab-indented YAML the Sigma compiler rejects) and SQL
escape-quoting hazards. Save this YAML to `phase2-rule.yml` first:

```yaml
title: Phase 2 validation
id: 8b7c4d00-0001-4000-8000-000000000099
description: bash launch on validation host
level: medium
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /bin/bash
  condition: selection
```

Then push it:

```bash
scripts/insert-rule.sh phase2-rule.yml
```

The script forwards through the bootstrap container's `slither-db
insert-rule` subcommand, which validates the YAML, looks up the
admin user (override with `--updated-by USERNAME`), and upserts the
row keyed by Sigma `id`. Re-running on the same file edits in place.

Within ~1 second the agent's stderr should log a structured info
line from the server-push code path:

```
level=INFO msg="ruleset apply: rule count changed" rule_count=N skipped_count=0 ruleset_version=… source=server-push previous_count=N-1
```

(For the operator: this is from `applyRuleSetTo` in
`agent/internal/app/app.go`, which fires at info on every rule-count
transition. Steady-state pushes log at debug; raise the agent's
`log_level` if you want to see the no-op pushes too.) The local
SIGHUP-driven reload path emits a different `reload: applied N rules
source=sighup` line — it does *not* fire on server-push.

Trigger the rule on the agent:

```bash
bash -c 'echo phase2'
```

The console's `/events` filtered by `class_uid=2004` should show a
new `DetectionFinding` whose `rule.uid` matches
`8b7c4d00-0001-4000-8000-000000000099`. Disable the rule:

```bash
docker compose exec postgres psql -U slither slither -c \
  "UPDATE rules SET enabled = false WHERE uid = '8b7c4d00-0001-4000-8000-000000000099';"
```

Trigger again — no new finding should fire (within ~1 s of the
disable taking effect through NOTIFY+debounce+push).

**Capture** the helper output, agent journal lines showing the
ruleset apply transition, and the resulting `DetectionFinding`
detail into `phase2_validation/04-rule-push.txt`.

## 8. Load test — 3 agents × stress-ng

Run the Phase 1 load-test workload concurrently from three agent
VMs against the same compose stack:

```bash
# On each agent VM, in parallel:
make build-agent                      # if not already built
sudo bash scripts/load-test.sh 60 100 # 60 s, --exec 100
```

Then capture:

- Each agent's final `telemetry: events=N dropped=N (collector=… dispatch=… enricher=… engine=… output=…) detections=… ringbuf_overflows=… output_reconnects=… heartbeats_sent=…` line from journalctl. Compute `drop_rate_pct` per agent.
- Server-side telemetry from `docker compose logs server | grep telemetry:` after the run completes (the server's snapshot prints on shutdown). Restart the server (`docker compose restart server`) once the agents are done so the snapshot fires:

  ```
  telemetry: events_received=N dropped=N (ingest=… subscriber=…) batches_flushed=… rulesets_pushed=… enroll=N/N sessions_active=N sessions_closed=N heartbeats=… authn_failures=…
  ```

  `subscriber` drops are the ClickHouse-writer-fell-behind counter;
  `ingest` drops are the Session-handler-couldn't-fan-out counter.
  Both should be zero at the Phase 1 baseline rate; non-zero
  numbers identify which subsystem is the bottleneck.

Phase 2 exit bar (mirrors Phase 1 §3.10 #3 scaled by 3 agents):

- Per-agent drop rate < 1 % at the 100-stressor / 60 s workload.
- Server `subscriber` drops ≤ 1 % of total received events.

**Capture** per-agent telemetry lines + the server telemetry line +
your per-agent drop-rate calculation into
`phase2_validation/05-load-test.txt`.

## 9. Tear down

```bash
sudo systemctl disable --now slither-agent.service       # on each agent
make compose-down                                        # operator host
```

## 10. Sign-off

Update `IMPLEMENTATION.md §4.1 #46` to ✅ with a one-line summary of
the run (host kernel versions, drop-rate numbers, anything notable).
That commit closes Phase 2.

## Troubleshooting

- **`enroll: rpc: rpc error: code = FailedPrecondition desc = enrollment token already used`** — minted token has been claimed by a previous attempt. Mint a fresh one.
- **Agent journal: `dial tcp <server>:9443: connect: connection refused`** — the slither-server container's mTLS listener bound to a non-public interface. Re-check the docker-compose `ports:` mapping or rebuild with `--build` after editing.
- **Agent journal: `tls: failed to verify certificate: x509: certificate signed by unknown authority`** — `--ca-cert` doesn't match the live CA (e.g. you re-ran `make compose-up` with `down -v` between the export step and the enroll step, which wiped the volume and minted a fresh CA). Re-export.
- **Console `/hosts` shows the agent as `unknown`** — agent enrolled but Session is not connecting. Agent journal will show output_reconnects climbing.
- **Console `/events` is empty after generating events** — check `docker compose logs server | grep "ch flush"` for ClickHouse insert errors. Most common cause is the bootstrap container's CH migration step failing on a stale volume.
