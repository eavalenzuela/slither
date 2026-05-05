# Phase 6 exit validation (§8.1 #121)

**Status:** ✅ completed 2026-05-05. Operator-driven cloud-fleet
run is captured under `phase6_validation/` at repo root; six
follow-ups carried to Phase 7 §9. This doc remains the runbook for
re-running the matrix on a future fleet.

Phase 6's surface is wider than any earlier phase — extension
supervisor, hunts, snapshots, server-side chain check, OIDC SSO, the
process-tree explorer, saved queries + dashboards, search
refinements, the keystore Gap A resolution, the TPM-sealed variant,
multi-arch + k8s, and the read-only JSON API. The matrix below maps
each task to a concrete capture so the closing PR has unambiguous
green flags.

## Fleet

Phase 5 #103's fleet (4 stopped EC2s — see
`memory/project_aws_phase3_fleet.md`) plus one **Graviton** instance
for arm64 coverage from #119. Bring up via `aws ec2 start-instances`
matching the per-instance IDs the memory file records.

| Role | Distro | Kernel | Arch | Instance |
|------|--------|--------|------|----------|
| server | Debian 13 (trixie) | 6.12 | amd64 | c7i.2xlarge (Phase 5 fleet) |
| agent-debian | Debian 13 (trixie) | 6.12 | amd64 | c7i.xlarge (Phase 5 fleet) |
| agent-rhel | RHEL 10 | 6.12 | amd64 | c7i.xlarge (Phase 5 fleet) |
| agent-ubuntu | Ubuntu 24.04 | 6.8/6.17 | amd64 | c7i.xlarge (Phase 5 fleet) |
| agent-graviton | Ubuntu 24.04 | 6.8 | arm64 | c7g.xlarge — **new** |

The Graviton instance gets the multi-arch agent OCI image pulled
straight from `ghcr.io/<org>/slither/agent:vX` — the kubelet (or
podman, on bare-metal) auto-resolves arm64 from the manifest list.

Server compose port bindings stay at `127.0.0.1` for production;
operators following this runbook either tunnel via an SSM session or
flip the bindings to `0.0.0.0` behind a tight security group, same
as the #103 capture noted.

## Pre-flight

```bash
# Operator's local machine.
cd ~/gits/slither

# Bring back the fleet.
aws ec2 start-instances --instance-ids \
    i-04a784fe98ecdb974 \
    i-03b468e20e802f163 \
    i-0fddb743cda81e679 \
    i-0338aaeebcbd42433
# Allocate one Graviton instance separately:
# aws ec2 run-instances --image-id <ubuntu-24.04-arm64> --instance-type c7g.xlarge ...

mkdir -p phase6_validation
```

Build + push the v-tag to ghcr.io that drives this run; the
`release.yml` workflow's first multi-arch tag run also serves as
`V11`'s capture.

## Step matrix

Captures land under `phase6_validation/`; each row's "Capture"
column is the file name the operator records command output into.

| § | Criterion | Capture | Result |
|---|-----------|---------|--------|
| V1 | Extension supervisor — install slither-ext-osquery via signed-bundle path on Debian 13 + RHEL 10 + Ubuntu 24.04; tampered binary refuses cleanly; OCSF events from osquery land in CH with `metadata.product.name="osquery (extension)"` | `01-extension-supervisor.txt` | ✅ |
| V2 | Live-query hunt — dispatch `SELECT name, port, address FROM listening_ports` against the 3-host fleet; all three respond within 60s; `/hunt/{id}` aggregates with per-host attribution; per-host row cap enforced | `02-live-query-hunt.txt` | ✅ |
| V3 | Snapshot-on-alert wire — fire a rule with `slither.snapshot: true`; alert detail surfaces "(no snapshot extensions configured)" since Phase 6 ships no provider; telemetry counter `ext_snapshots_requested=0` (no fanout target) and `ext_snapshots_failed=0` | `03-snapshot-no-providers.txt` | ✅ |
| V4 | Server-side tamper-chain cross-check — happy path emits clean ChainSummaries every 5 min for 30 min; intentional `UPDATE response_actions SET status='done' WHERE id=…` (one tampered row) fires `chain.mismatch` audit row within 5 min; `/hosts/{id}/chain-status` shows the row in red | `04-chain-mismatch.txt` | ✅ |
| V5 | Console SSO — Dex (or any operator-shaped OIDC IdP) integration roundtrip; first-login user creation; role mapping from `groups` claim picks `analyst` correctly; IdP-down fallback to local-user login still works | `05-oidc-sso.txt` | ✅ |
| V6 | Live process-tree explorer — opens on a real alert; expand-on-click walks the tree one hop per click; right-click response actions hidden when host policy denies | `06-process-tree-explorer.txt` | ✅ |
| V7 | Saved queries + dashboards — operator saves filters from `/events`, `/alerts`, `/hunt`; assembles a dashboard with two cards; refresh persists; deleting a saved query renders "(query deleted)" placeholder on the dashboard card | `07-queries-dashboards.txt` | ✅ |
| V8 | Search refinements — `host:foo class:1007 since:24h` parses on `/events` query bar; `/events/history` lists last-50 with click-to-rerun; closed→in_progress reopen-alert transition works + writes `alert.reopened` audit | `08-search-reopen.txt` | ✅ |
| V9 | Keystore Gap A resolution — `@u`-keyring strategy survives the enroll → restart → second-boot lookup cycle on every host shape (Debian 13, RHEL 10, Ubuntu 24.04, Graviton) | `09-keystore-gap-a.txt` | ✅ |
| V10 | TPM-sealed cert variant — opt-in path via `slither-agent enroll --tpm` on the TPM-equipped instance; sealed blob lands at `/var/lib/slither/tpm_sealed.bin`; PCR-bump (kernel update) → next boot logs `tpm: PCR 7 mismatch (kernel/Secure-Boot change?)` and falls back; re-enroll re-seals | `10-tpm-pcr-bump.txt` | ✅ |
| V11 | Multi-arch + live k8s — daemonset on k3s reports events; arm64 host (Graviton EC2) runs the agent natively without qemu-user; `deploy/k8s/smoke.sh` exits 0 | `11-k8s-multiarch.txt` | ✅ |
| V12 | Sustained-load backpressure e2e (deferred from Phase 5 #103 V8) — `make load-test` against the fleet under pinned slow CH writer; agents observably raise NetworkActivity sampling within 30s; recovery within 30s of writer unpin | `12-backpressure-e2e.txt` | ⚠ |
| V13 | eyeexam JSON API contract (#120 / ADR-0040) — mint API key via `/api/keys`; fire a known Atomic test on a fleet host; `eyeexam exec --pack ...` against live `slither-server` scores the expectation `caught` with `raw_json` populated; host_name + sigma_id + tag filters all narrow as advertised; revoked key returns 401 with JSON body | `13-jsonapi-eyeexam.txt` | ✅ |

## Per-step detail

The order below tracks the matrix above; each step lists the
operator-facing commands + the green-criterion the capture must
record. Steps **may** run in parallel where independent (V5–V8 have
no shared state); V9/V10/V12 are restart-bound and serialise.

### V1 — extension supervisor

```bash
# Per host: install the signed bundle.
sudo /usr/local/bin/slither-db verify-rule-bundle \
    /tmp/slither-ext-osquery.tgz   # static check passes
sudo install -m0755 ./slither-ext-osquery /usr/lib/slither/extensions/

# Tamper test.
cp /usr/lib/slither/extensions/slither-ext-osquery /tmp/tampered.bin
echo "evil" >> /tmp/tampered.bin
sudo install -m0755 /tmp/tampered.bin /usr/lib/slither/extensions/slither-ext-osquery
sudo systemctl restart slither-agent
journalctl -u slither-agent --since "1 minute ago" | grep "ext: signature failure"
# Restore the good binary before continuing.

# OCSF event flow check (server side).
psql … -c "SELECT count(*) FROM ocsf_process_activity_1007
    WHERE host_id=:h AND product_name='osquery (extension)'
    AND observed_at > now() - interval '5 minutes'"
# Expect ≥ 1.
```

Capture: install output, tamper failure log line, post-restore
event count.

### V2 — live-query hunt

Console: `/hunt` → dispatch
`SELECT name, port, address FROM listening_ports` with
`max_rows_per_host: 100`. Wait ≤ 60s. Capture the
`/hunt/{id}` page screenshot or HTML dump showing
`completed_host_count = 3`, per-host result counts, and one row
truncated at the cap on a noisy host (use a host with > 100 ports
listening — `nc -l` a few extras to force the truncation if needed).

### V3 — snapshot-on-alert empty path

Insert a rule with `slither.snapshot: true` via
`slither-db insert-rule --file rules/test-snapshot.yml`. Trigger
the rule with the bundled scenario script. On the alert detail
page, capture the `Forensic snapshots` block rendering
`(no snapshot extensions configured)`. Confirm
`telemetry: ext_snapshots_requested=0 ext_snapshots_completed=0
ext_snapshots_failed=0` in the agent's stderr DiagReport.

### V4 — server-side chain mismatch

Wait 30 minutes for clean summaries on each host (5 min cadence × 6
intervals). Capture `/hosts/{id}/chain-status` showing all OK rows.
Then:

```sql
-- pg side, one tampered row.
UPDATE response_actions
   SET status = 'done', detail = 'tampered'
 WHERE id = '<known-pending-id>'
   AND host_id = '<target>';
```

Wait ≤ 5 min for the next ChainSummary. Capture
`/hosts/{id}/chain-status` showing one mismatch row in red + the
corresponding `audit_log` row with action=`chain.mismatch`,
severity 4.

### V5 — console SSO

Run a Dex container locally bound to the fleet's reachable network
(or an existing operator IdP). Configure Dex with two groups:
`slither-admin` and `slither-analyst`. Set
`agent.yaml`-equivalent `console.oidc` block on the server. Verify:

- First sign-in via SSO creates a `users` row with
  `oidc_subject = <Dex subject>`, role = `analyst`.
- Re-bind the same Dex user into `slither-admin`, sign in again →
  `users.role` rotates to `admin` (covered by
  `UpdateUserRole`).
- Stop Dex, restart server, sign in as the bootstrap admin via the
  password form — local fallback still works.

### V6 — process-tree explorer

Open a real alert on `/alerts/{id}`. Capture the SVG explorer
rendering the BFS-grid layout. Click an inner node → page fetches a
deeper subtree. Right-click on any node and confirm the action menu
items are gated by `pg.HostPolicy`: `kill_process` is hidden when
`allow_kill_process=false`.

### V7 — saved queries + dashboards

On `/events`, apply two filters and click Save (e.g.
"high-severity-process" with class_uid=1007 + severity_id=5). Open
`/queries`, click the saved name, confirm the URL params re-encoded
correctly. Create `/dashboards/<id>` with two cards from saved
queries. Delete one of the saved queries; refresh the dashboard;
capture the "(query deleted)" placeholder.

### V8 — search refinements

On `/events`, type `host:agent-debian class:1007 since:24h` into
the query bar; capture the result count + URL re-encoding. Open
`/events/history`, click the recent entry, confirm it re-runs.

Close any alert in the in-progress state. Then on the closed
alert's detail page, click Reopen → status flips to in_progress;
audit_log gets `alert.reopened`.

### V9 — keystore Gap A

```bash
# Per host:
sudo systemctl stop slither-agent
sudo cat /var/lib/slither/client.key | sha256sum  # capture
sudo keyctl list @u | grep slither.agent          # capture (3 keys)
sudo systemctl start slither-agent
sleep 10
sudo systemctl restart slither-agent              # second boot
sleep 10
sudo journalctl -u slither-agent | grep "keystore: kernel-keyring"
# Expect at least 2 lines (initial + post-restart) — both pick the
# keyring store, not file fallback, on every host.
```

### V10 — TPM-sealed variant

Provision one TPM-equipped instance (AWS Nitro TPM, m6a or m7a
with `EnableNitroEnclave=false` + Nitro TPM enabled). Re-enroll
with `--tpm`, then:

```bash
sudo cat /var/lib/slither/tpm_sealed.bin | wc -c    # > 0
sudo systemctl restart slither-agent                 # unseals OK
# Bump kernel:
sudo apt -y install linux-image-generic-hwe-24.04
sudo reboot
# After reboot:
sudo journalctl -u slither-agent | grep "tpm: PCR 7 mismatch"
sudo /usr/local/bin/slither-agent enroll --tpm --token ... # re-seal
```

### V11 — multi-arch + k8s

```bash
NAMESPACE=slither-test IMAGE_TAG=vX.Y.Z deploy/k8s/smoke.sh
```

Exit 0 → green. The script verifies per-pod arch matches the
node's `kubernetes.io/arch` label.

### V12 — sustained-load backpressure

Pin the CH writer to a slow rate by scaling its container down or
adding a `tc` netem delay. Run `make load-test` from one agent host
for 5 minutes. Capture:

- Server's CH writer's drop_rate_pct rising above the
  CRITICAL threshold (Phase 5 #97 default).
- Agent's NetworkActivity sample rate falling within 30s of the
  signal arriving.
- Unpin → drop_rate_pct returns to baseline within 30s; agent
  resumes 100% sampling.

### V13 — eyeexam JSON API

Mint a key on `/api/keys`. Run
`eyeexam exec --pack atomic-t1059.001 --target slither-server` per
the eyeexam README. Capture the eyeexam scoring output; confirm
the expectation marks `caught: true` with `raw_json` populated.
Verify host_name + sigma_id + tag filters narrow as advertised:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
    "$API_BASE/api/v1/events/search?host_name=agent-debian&tag=T1059.001" \
    | jq '.hits | length'   # Expect ≥ 1
```

Revoke the key on `/api/keys`; same curl returns 401 with JSON
`{"error":"invalid_token"}`.

## Closing

Once every row above flips to ✅, this doc's status header changes
to **completed YYYY-MM-DD**, all captures commit under
`phase6_validation/`, and Phase 6 closes. Phase 7 (platform
expansion — macOS / Windows agents per ADR-0001) opens or stays
parked pending demand per ADR-0037.
