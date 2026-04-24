//go:build linux && integration

// Scenario tests boot the real slither-agent binary against the shipped
// rules/linux/ pack, run one of the bash scripts under testdata/scenarios/,
// scrape the agent's JSON-lines stdout, and assert the expected detection
// finding fires within a deadline.
//
// Like the collector integration tests, these require root + kernel BTF
// (see IMPLEMENTATION.md §3.9 + §3.11 item 12). The harness skips cleanly
// otherwise so it's safe to run on a dev laptop.

package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// Rule UIDs come from the `id:` field of rules/linux/*.yml.
	ruleBashReverseShell = "8b7c4d00-0001-4000-8000-000000000001"
	ruleFindSUID         = "8b7c4d00-0001-4000-8000-000000000005"
	ruleAuthorizedKeys   = "8b7c4d00-0001-4000-8000-00000000000b"
)

// scenarioCase binds a shell script to the rule UID that should fire when
// the script runs against an agent loaded with rules/linux/.
type scenarioCase struct {
	name      string
	script    string
	needsWork bool // if true, the script takes a workdir as its first arg
	ruleUID   string
}

func TestScenarios(t *testing.T) {
	requirePrivilegedScenario(t)

	root := repoRoot(t)
	rulesDir := filepath.Join(root, "rules", "linux")
	scenariosDir := filepath.Join(root, "testdata", "scenarios")

	// Build the agent binary once per test invocation; each subtest
	// re-launches it so scenarios don't bleed state across cases.
	agentBin := buildAgentBinary(t, root)

	cases := []scenarioCase{
		{"bash-reverse-shell", "proc-bash-reverse-shell.sh", false, ruleBashReverseShell},
		{"find-suid", "proc-find-suid-discovery.sh", false, ruleFindSUID},
		{"authorized-keys", "file-authorized-keys-write.sh", true, ruleAuthorizedKeys},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			cfgPath := writeScenarioConfig(t, work, rulesDir)

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, agentBin, "--config", cfgPath)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatalf("stdout pipe: %v", err)
			}
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatalf("start agent: %v", err)
			}
			defer func() {
				cancel()
				_ = cmd.Wait()
			}()

			findings := make(chan map[string]any, 32)
			var scanErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				scanErr = scanJSONL(ctx, stdout, findings)
			}()

			// Collectors need time to attach tracepoints before the
			// scenario runs, otherwise we race the exec.
			time.Sleep(800 * time.Millisecond)

			scriptPath := filepath.Join(scenariosDir, tc.script)
			scriptArgs := []string{}
			if tc.needsWork {
				scriptArgs = append(scriptArgs, work)
			}
			sc := exec.Command("bash", append([]string{scriptPath}, scriptArgs...)...)
			sc.Stdout = io.Discard
			sc.Stderr = io.Discard
			if err := sc.Run(); err != nil {
				t.Fatalf("run scenario %s: %v", tc.script, err)
			}

			if !waitForFinding(findings, tc.ruleUID, 10*time.Second) {
				t.Fatalf("no detection_finding for rule %s seen within 10s (scenario=%s)",
					tc.ruleUID, tc.script)
			}

			cancel()
			wg.Wait()
			// context.Canceled is the intended exit path now that scanJSONL
			// respects ctx on send; io.EOF and "file already closed" cover
			// the "agent exited first" races.
			if scanErr != nil && !errors.Is(scanErr, context.Canceled) &&
				scanErr != io.EOF && !strings.Contains(scanErr.Error(), "file already closed") {
				t.Errorf("stdout scan: %v", scanErr)
			}
		})
	}
}

// requirePrivilegedScenario mirrors the collector helper but is kept local
// to avoid cross-package build-tag coupling.
func requirePrivilegedScenario(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("scenario: requires root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("scenario: requires kernel BTF: %v", err)
	}
}

// repoRoot walks upwards from this file until it finds go.work, so tests run
// correctly whether invoked via `go test ./...` from the module root or from
// the agent/ module.
func repoRoot(t *testing.T) string {
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
	t.Fatalf("repoRoot: could not find go.work starting from %s", filepath.Dir(here))
	return ""
}

// buildAgentBinary compiles ./cmd/slither-agent into a tempfile. The binary
// is shared across subtests to keep each scenario under a couple of seconds.
func buildAgentBinary(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "slither-agent")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/slither-agent")
	cmd.Dir = filepath.Join(root, "agent")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build slither-agent: %v", err)
	}
	return bin
}

// writeScenarioConfig drops an agent.yaml in work pointing at rulesDir. We
// enable all collectors so a single rule-pack can cover process/file/net
// scenarios without per-test config edits.
func writeScenarioConfig(t *testing.T, work, rulesDir string) string {
	t.Helper()
	cfg := `agent:
  host_id_file: ` + filepath.Join(work, "host_id") + `
  log_level: info
collectors:
  process:
    enabled: true
  file:
    enabled: true
  net:
    enabled: true
rules:
  paths:
    - ` + filepath.Join(rulesDir, "*.yml") + `
output:
  kind: stdout
`
	path := filepath.Join(work, "agent.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// scanJSONL reads newline-delimited JSON from r and forwards decoded objects
// on out. Stops when r closes or ctx is cancelled. ctx is needed because the
// subtest stops draining `out` once waitForFinding succeeds; without a
// cancellable send the scanner blocks on a full buffered channel and the
// wg.Wait() in the subtest's teardown never returns.
func scanJSONL(ctx context.Context, r io.Reader, out chan<- map[string]any) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var v map[string]any
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			// Non-JSON lines are unexpected on stdout; skip rather than
			// fail so a stray log line doesn't mask the actual finding.
			continue
		}
		select {
		case out <- v:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return sc.Err()
}

// waitForFinding drains findings until it sees a DetectionFinding whose
// rule.uid matches want, or the deadline expires.
func waitForFinding(findings <-chan map[string]any, want string, within time.Duration) bool {
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	for {
		select {
		case ev := <-findings:
			if !isDetectionFinding(ev) {
				continue
			}
			rule, _ := ev["rule"].(map[string]any)
			if rule == nil {
				continue
			}
			if uid, _ := rule["uid"].(string); uid == want {
				return true
			}
		case <-deadline.C:
			return false
		}
	}
}

func isDetectionFinding(ev map[string]any) bool {
	// OCSF ClassDetectionFinding = 2004.
	switch v := ev["class_uid"].(type) {
	case float64:
		return int(v) == 2004
	case int:
		return v == 2004
	}
	return false
}
