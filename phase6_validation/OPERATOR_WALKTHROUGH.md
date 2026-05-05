# Phase 6 #121 — Operator Walkthrough (Phase D + V10)

Server URL: http://50.112.66.184:8080  (your IP 98.37.95.245 already
allow-listed in the SG)
Login: admin / phase6-validate
SSH key path on this box: /home/t3rmit3/gits/slither/eevnio_debatabase_ssh_key.pem
SSH config: /tmp/phase6_ssh_config (host aliases: slither-server,
slither-agent-{debian,rhel,ubuntu,graviton}, slither-tpm)

────────────────────────────────────────────────────────────────────
## V2 — Live-query hunt (~10 min)
────────────────────────────────────────────────────────────────────

Pre-req: needs at least one agent host with a working extension that
declares CAPABILITY_LIVE_QUERY_RESPOND. **Phase 6 ships no such
extension that's runtime-stable in this environment** (V1 surfaced
the supervisor OOM under signature_verification:disabled, and cosign-
required mode refuses the unsigned binary). The osquery bridge would
provide the capability if installed, signed, and cosign-on-PATH.

Recommended capture: open /hunt, observe the dispatch UI shape,
fill in:
  backend: osquery
  query:   SELECT name, port, address FROM listening_ports
  host_filter: (leave blank for all)
  timeout_secs: 60
  max_rows_per_host: 100

Click Dispatch. Capture screenshot of the resulting /hunt/{id} page.
Expected: dispatch lands but every host's HuntResultComplete carries
error="no extension declares live_query_respond" (Phase 6 #110's
documented no-provider behaviour).

Operator notes for capture file phase6_validation/02-live-hunt.txt:
  - hunt id from URL
  - dispatched_by user (admin)
  - timeout_secs / max_rows / status (timed_out or completed)
  - completed_host_count and target_host_count
  - per-host error string

────────────────────────────────────────────────────────────────────
## V5 — Console SSO via OIDC (~30 min)
────────────────────────────────────────────────────────────────────

Operator path (no Dex pre-installed; allocate as needed):

1. Spin up Dex on slither-server (docker container, port 5556 on
   127.0.0.1). Operator-supplied YAML — sample below.
2. Configure two static groups:
     slither-admin → maps to admin role
     slither-analyst → maps to analyst role
3. Add console.oidc block to /etc/slither/server.yaml:
     console:
       oidc:
         issuer_url: http://slither-server:5556/dex
         client_id: slither
         client_secret: <random>
         redirect_url: http://50.112.66.184:8080/oidc/callback
         scopes: [openid, email, profile, groups]
         role_claim: groups
         role_mappings:
           slither-admin: admin
           slither-analyst: analyst
         username_claim: email
4. systemctl restart slither-server.
5. Hit http://50.112.66.184:8080/login → confirm "Sign in with SSO"
   button renders.
6. Click SSO → redirect to Dex → authenticate as a user in
   slither-admin group → redirect back → dashboard.
7. psql check: SELECT id, username, oidc_subject, role FROM users
   WHERE oidc_subject IS NOT NULL → confirm new row.
8. Re-bind the same Dex user into slither-analyst, sign in again →
   confirm users.role rotated to analyst.
9. Stop Dex, hit /login as admin/phase6-validate → confirm local
   fallback works.

Capture under phase6_validation/05-oidc-sso.txt:
  - Dex YAML
  - users row before / after first SSO sign-in
  - users.role after group rotation
  - audit_log rows for auth.oidc.success and auth.oidc.failure
  - screenshot of /login showing both forms

Sample Dex compose snippet:
  docker run -d --name dex -p 5556:5556 \
    -v $PWD/dex.yaml:/etc/dex/config.yaml \
    ghcr.io/dexidp/dex:v2.40.0 dex serve /etc/dex/config.yaml

────────────────────────────────────────────────────────────────────
## V6 — Live process-tree explorer (~15 min)
────────────────────────────────────────────────────────────────────

Trigger an alert on agent-debian (the V3 rule is still active):
  ssh -F /tmp/phase6_ssh_config slither-agent-debian 'ls /tmp'

Then in the console:
  1. Open /alerts, click the most recent V3 alert.
  2. Scroll to the "Process tree" section. Capture screenshot of the
     SVG explorer rendering.
  3. Click any inner node → confirm the page re-fetches a deeper
     subtree (visible by node count change).
  4. Right-click on a node:
     a. Default host policy is detect-only → expect NO menu items
        appear (gating).
     b. Toggle host policy: insert allow_kill_process via psql:
        INSERT INTO host_response_policies
          (host_id, allow_kill_process, allow_kill_tree, allow_quarantine, allow_isolate, allow_collect)
        VALUES
          ('ba4ac61d-664c-4438-930e-6b479492c4d5', true, false, false, false, false)
        ON CONFLICT (host_id) DO UPDATE SET allow_kill_process = true;
     c. Refresh the alert detail page; right-click again → expect
        "Kill process (pid …)" menu item now appears.

Capture under phase6_validation/06-process-tree.txt:
  - alert id used
  - screenshot of explorer (with at least one expanded subtree)
  - confirmation that menu is hidden / shown based on policy

────────────────────────────────────────────────────────────────────
## V7 — Saved queries + dashboards (~15 min)
────────────────────────────────────────────────────────────────────

1. Open /events, apply filter (host_id = ip-172-31-26-27, class_uid =
   1007). Click Save → name "test-process-events". Confirm flash
   "Saved query …".
2. Open /alerts, apply filter (status = new, severity = 3). Click
   Save → name "new-medium". Confirm.
3. Open /hunt, save current state as "hunt-history".
4. Open /queries → confirm 3 rows visible.
5. Click "test-process-events" → confirm it re-runs on /events with
   filter applied.
6. Open /dashboards → click Create → name "ops". Open the new
   dashboard. Add one card via the picker pointing at
   "test-process-events". Click Refresh → confirm card visible.
7. Add a second card pointing at "new-medium". Confirm both visible.
8. Open /queries → click Delete on "test-process-events".
9. Re-open the "ops" dashboard. Confirm the deleted card now renders
   "(query deleted)" placeholder.

Capture under phase6_validation/07-queries-dashboards.txt:
  - psql SELECT id, name, surface, params FROM saved_queries
  - psql SELECT id, name, layout FROM dashboards
  - screenshot of /dashboards/<id> with the (query deleted) tile

────────────────────────────────────────────────────────────────────
## V8 — Search refinements + reopen-alert (~15 min)
────────────────────────────────────────────────────────────────────

1. Open /events, type into search bar:
     host:ip-172-31-26-27 class:1007 since:24h
   Click Search. Confirm result count and that URL re-encodes to
   /events?q=host%3Aip-172-31-26-27+class%3A1007+since%3A24h.
2. Open /events/history → confirm the saved query lands as recent
   entry. Click → confirm rerun.
3. Open /alerts, find a closed alert. If none, manually close one
   from /alerts/{id} via Transition → "Close (skip ack)".
4. On the now-closed alert's detail page, click the Reopen button.
   Confirm status flips to in_progress.
5. psql check:
     SELECT action, detail FROM audit_log WHERE action='alert.reopened'
     ORDER BY created_at DESC LIMIT 1;
   Expect 1 row matching your test alert.

Capture under phase6_validation/08-search-reopen.txt.

────────────────────────────────────────────────────────────────────
## V10 — TPM-sealed cert variant (operator-only, ~30 min)
────────────────────────────────────────────────────────────────────

The TPM instance i-076cf63cb408f5a1d (slither-tpm) is up. SSH:
  ssh -F /tmp/phase6_ssh_config slither-tpm

Step-by-step:

1. Confirm /dev/tpmrm0 is present:
     ssh -F /tmp/phase6_ssh_config slither-tpm 'ls -la /dev/tpmrm0'

2. Push the agent binary + slither-ext-osquery + ca.crt:
     scp -F /tmp/phase6_ssh_config \
       /home/t3rmit3/gits/slither/dist/phase6/slither-agent-amd64 \
       slither-tpm:/tmp/slither-agent
     ssh -F /tmp/phase6_ssh_config slither-tpm \
       'sudo install -d -m0755 /etc/slither /var/lib/slither;
        sudo install -m0755 /tmp/slither-agent /usr/local/bin/slither-agent;
        echo "172.31.24.48 slither-server" | sudo tee -a /etc/hosts'
     scp -F /tmp/phase6_ssh_config /tmp/ca.crt slither-tpm:/tmp/ca.crt
     ssh -F /tmp/phase6_ssh_config slither-tpm \
       'sudo cp /tmp/ca.crt /etc/slither/ca.crt'

3. Mint enrol token via psql + enrol with --tpm:
     ssh -F /tmp/phase6_ssh_config slither-server "
       sudo docker exec slither-postgres psql -U slither slither -tAc \"
         INSERT INTO enrollment_tokens (token_hash, expires_at, created_by)
         SELECT digest('phase6-tpm-token','sha256'), now()+interval '1 hour',
                id FROM users WHERE role='admin' LIMIT 1
       \""
     ssh -F /tmp/phase6_ssh_config slither-tpm '
       sudo /usr/local/bin/slither-agent enroll \
         --server slither-server:9444 \
         --token phase6-tpm-token \
         --insecure-skip-verify \
         --state-dir /var/lib/slither \
         --tpm
     '
   EXPECT: enrolled host UUID printed; capture stderr.

4. Confirm sealed blob landed:
     ssh -F /tmp/phase6_ssh_config slither-tpm \
       'sudo ls -la /var/lib/slither/tpm_sealed.bin'
   EXPECT: file exists, > 0 bytes.

5. Write minimal agent.yaml + systemd unit on slither-tpm using the
   same shape as the Graviton (process collector only, server_addr
   slither-server:9443, keystore_dir + keystore.tpm: true).

6. systemctl enable + start; sleep 5; check journal for
   "keystore: tpm" log line. Capture telemetry line.

7. **Bump the kernel to trigger PCR 7 mismatch:**
     ssh -F /tmp/phase6_ssh_config slither-tpm \
       'sudo apt-get update && sudo apt-get install -y linux-image-generic-hwe-24.04 && sudo reboot'

   Wait ~3 min for reboot. SSH back in:
     until ssh -F /tmp/phase6_ssh_config slither-tpm 'true' 2>/dev/null; do sleep 10; done

8. Check journal for the PCR-mismatch log:
     ssh -F /tmp/phase6_ssh_config slither-tpm \
       'sudo journalctl -u slither-agent --no-pager 2>&1 | grep -i "PCR 7 mismatch\|tpm: " | tail'
   EXPECT: a "tpm: PCR 7 mismatch (kernel/Secure-Boot change?)"
   line, agent falling back to keyring/file.

9. Re-enrol with --tpm to re-seal against new PCR state:
     # Mint a fresh token (same psql block as step 3)
     ssh -F /tmp/phase6_ssh_config slither-tpm '
       sudo systemctl stop slither-agent
       sudo /usr/local/bin/slither-agent enroll --tpm \
         --server slither-server:9444 \
         --token <new-token> \
         --insecure-skip-verify \
         --state-dir /var/lib/slither
       sudo systemctl start slither-agent
     '
   EXPECT: clean re-enrol, sealed blob refreshed against new PCR.

Capture under phase6_validation/10-tpm-pcr-bump.txt:
  - /dev/tpmrm0 ls
  - tpm_sealed.bin pre + post bump
  - journal "tpm: PCR 7 mismatch" line
  - re-enrol stderr

────────────────────────────────────────────────────────────────────
## After all captures land
────────────────────────────────────────────────────────────────────

1. cd /home/t3rmit3/gits/slither
2. ls phase6_validation/  (expect 13 files: 00-pre-flight, 01-13)
3. Edit docs/phase6-validation.md status header to "completed YYYY-MM-DD"
4. Flip every ⏳ in the matrix to ✅ (or ⚠ for V1 sub-finding,
   V11 sub-finding, V9 sub-finding, V12 deferral).
5. Update IMPLEMENTATION.md task #18 to ✅.
6. Update memory project_phase_status.md.
7. git add phase6_validation/ docs/phase6-validation.md IMPLEMENTATION.md
8. git commit -s -m "phase6: close — cloud-VM exit validation green (#121)"
9. git push origin main

────────────────────────────────────────────────────────────────────
