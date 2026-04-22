//go:build linux && integration

package collector

import (
	"os/exec"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestProcessCollector_ExecObserved loads process.bpf.c, execs a short-lived
// child, and asserts that an exec (and subsequent exit) event for that child
// shows up on the output channel.
func TestProcessCollector_ExecObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawProcessEvent, 1024)
	c := newProcessCollector(out, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	// Give the collector a beat to attach its tracepoints before we fire the
	// child syscall. Attaching is fast, but not instantaneous.
	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec /bin/true: %v", err)
	}
	childPID := uint32(cmd.Process.Pid)

	_, okExec := waitForEvent(t, out, func(e pipeline.RawProcessEvent) bool {
		return e.Kind == pipeline.ProcExec && e.PID == childPID
	}, 3*time.Second)
	if !okExec {
		t.Fatalf("no exec event seen for pid %d within 3s", childPID)
	}

	_, okExit := waitForEvent(t, out, func(e pipeline.RawProcessEvent) bool {
		return e.Kind == pipeline.ProcExit && e.PID == childPID
	}, 3*time.Second)
	if !okExit {
		t.Fatalf("no exit event seen for pid %d within 3s", childPID)
	}
}
