//go:build linux && integration

// Integration tests in this package each load a single eBPF program into a
// real kernel, drive it with a syscall from the test process, and assert the
// decoded record shows up on the collector's output channel.
//
// They are gated by `//go:build integration` and require:
//   - root (for bpf(2) + tracepoint/kprobe attach),
//   - BTF at /sys/kernel/btf/vmlinux (no CO-RE fallback in Phase 1),
//   - the agent's bpf2go-generated objects compiled in (no separate step —
//     the package already go:generate's them).
//
// See IMPLEMENTATION.md §3.9/§3.11 item 11.

package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
)

// requirePrivileged skips the test unless we can plausibly load BPF. Both
// conditions (root + BTF) are kept fatal-in-CI via the privileged workflow
// checking them up front, but on a developer laptop we'd rather skip than
// fail loudly.
func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration: requires root")
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		t.Skipf("integration: requires kernel BTF (/sys/kernel/btf/vmlinux): %v", err)
	}
}

// startCollector runs c in a background goroutine and returns a stop func
// that cancels the context and waits for Run to exit. Any error from Run is
// reported via t.Errorf on stop (context.Canceled is treated as clean exit).
func startCollector(t *testing.T, c Collector) (ctx context.Context, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	return ctx, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Errorf("%s.Run: %v", c.Name(), err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s.Run did not exit within 2s of cancel", c.Name())
		}
	}
}

// waitForEvent drains ch until match returns true or the deadline expires.
// The per-try timeout is short so the test can log partial progress if the
// expected event never arrives.
func waitForEvent[T any](t *testing.T, ch <-chan T, match func(T) bool, within time.Duration) (T, bool) {
	t.Helper()
	var zero T
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	for {
		select {
		case ev := <-ch:
			if match(ev) {
				return ev, true
			}
		case <-deadline.C:
			return zero, false
		}
	}
}

// newTestGroupMembers returns the concrete collector under test plus a freshly
// allocated counters pointer. Kept here so individual tests don't duplicate
// the NewCounters() boilerplate.
func newCounters() *telemetry.Counters { return telemetry.NewCounters() }
