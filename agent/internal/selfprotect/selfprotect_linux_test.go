//go:build linux

package selfprotect

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCheckNotTraced_NoTracer asserts that a process running outside
// a debugger has TracerPid=0 and CheckNotTraced returns nil. CI
// runners and dev machines both fit this profile; running under
// `dlv test` or `gdb go test` would fail this test, but that's the
// correct behaviour we're testing.
func TestCheckNotTraced_NoTracer(t *testing.T) {
	if err := CheckNotTraced(); err != nil {
		t.Errorf("CheckNotTraced under no-tracer = %v, want nil; "+
			"are you running this test under a debugger?", err)
	}
}

func TestCheckNotTraced_ErrorWraps(t *testing.T) {
	// Construct the wrapped form CheckNotTraced returns and assert
	// it errors.Is-matches the sentinel.
	wrapped := wrapTracerErr(42)
	if !errors.Is(wrapped, ErrTracerAttached) {
		t.Error("wrapped error doesn't errors.Is(ErrTracerAttached)")
	}
}

// TestSetDumpable_TogglesProcDumpable asserts that PR_SET_DUMPABLE
// flips the kernel-visible dumpable flag. We read it back via
// PR_GET_DUMPABLE, then restore the original value so we don't
// affect sibling tests in the same `go test` process.
//
// IMPORTANT: this test mutates global process state. Cannot be
// t.Parallel() with anything else that touches dumpable.
func TestSetDumpable_TogglesProcDumpable(t *testing.T) {
	prev, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 {
		t.Skipf("PR_GET_DUMPABLE not supported: %v", errno)
	}

	if err := SetDumpable(); err != nil {
		t.Fatalf("SetDumpable: %v", err)
	}

	got, _, errno2 := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno2 != 0 {
		t.Fatalf("PR_GET_DUMPABLE post-set: %v", errno2)
	}
	if got != 0 {
		t.Errorf("PR_GET_DUMPABLE = %d, want 0 after SetDumpable", got)
	}

	// Restore so sibling tests (and the test runner) aren't surprised
	// by an undumpable child.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, prev, 0, 0, 0)
}

// TestDropAmbientPostInit_NoErrorOnUnprivilegedRunner asserts that
// the function exits without surfacing ENOSYS / EINVAL as fatal.
// Running outside the systemd unit's AmbientCapabilities= context,
// the agent's ambient set is empty, so PR_CAP_AMBIENT_LOWER returns
// EINVAL — DropAmbientPostInit treats that as a benign no-op.
func TestDropAmbientPostInit_NoErrorOnUnprivilegedRunner(t *testing.T) {
	if err := DropAmbientPostInit(); err != nil {
		t.Errorf("DropAmbientPostInit on unprivileged process = %v, want nil", err)
	}
}

// wrapTracerErr produces the same fmt.Errorf shape CheckNotTraced
// uses internally so tests can assert errors.Is wrapping without
// depending on a real tracer.
func wrapTracerErr(pid int) error {
	return fmt.Errorf("%w: TracerPid=%d", ErrTracerAttached, pid)
}
