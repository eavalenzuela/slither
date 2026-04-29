//go:build linux

package respond

import (
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// mustSpawnSleep runs `sleep <duration>` as a child of the test
// process. The caller is the parent so Wait reaps cleanly + signals
// land on a process the test owns. t.Cleanup ensures the child is
// killed if the test forgets to wait.
func mustSpawnSleep(t *testing.T, duration string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sleep", duration)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	return cmd
}

// mustSpawnSh runs `sh -c <body>` as a child of the test process.
// Used to set up multi-level fork trees for kill_tree coverage.
func mustSpawnSh(t *testing.T, body string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", "-c", body)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sh: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	return cmd
}

// mustReap kills + waits the cmd. Idempotent — used in defers where
// the test path may have already reaped via cmd.Wait().
func mustReap(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.ProcessState != nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

// waitForChild blocks until /proc/<parent>/task/.../children lists
// at least one pid, or the deadline expires. Sleep + sh take a few
// ms after Start() to register the child; tests that fire kill
// before that race the parent's clone() syscall.
func waitForChild(t *testing.T, parent int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tree, err := collectDescendants(parent, 64)
		if err == nil && len(tree) > 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child of pid %d did not register within 2s", parent)
}

// itoa wraps strconv.Itoa for the test-side wire-target encoding.
// Kept package-local so the kill handler's parser is the only
// strconv consumer in production code.
func itoa(n int) string { return strconv.Itoa(n) }
