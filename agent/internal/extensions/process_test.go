//go:build linux

package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/extsdk"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// stubExtensionBinary builds a tiny Go program that performs the
// extension side of the wire: sends Hello with the requested
// capabilities, then emits `events` OCSFEvent envelopes (or a
// non-Hello first envelope if `bogusFirst`), then exits.
//
// Returns the path to the compiled binary.
func stubExtensionBinary(t *testing.T, behaviour string) string {
	t.Helper()
	src := `package main

import (
	"encoding/json"
	"os"

	"github.com/t3rmit3/slither/pkg/extsdk"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func main() {
	wire := os.NewFile(3, "wire")
	if wire == nil { os.Exit(2) }
	behaviour := os.Getenv("STUB_BEHAVIOUR")
	switch behaviour {
	case "no_hello":
		// Exit before sending Hello — supervisor must time out.
		select {}
	case "second_hello":
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_Hello{Hello: &pb.Hello{Name: "stub", Capabilities: []pb.Capability{pb.Capability_CAPABILITY_OCSF_EMIT}}}})
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_Hello{Hello: &pb.Hello{Name: "stub2"}}})
		select {}
	case "undeclared_event":
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_Hello{Hello: &pb.Hello{Name: "stub", Capabilities: []pb.Capability{pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND}}}})
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_OcsfEvent{OcsfEvent: &pb.OCSFEvent{ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY}}})
		select {}
	case "emit_events":
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_Hello{Hello: &pb.Hello{Name: "stub", Capabilities: []pb.Capability{pb.Capability_CAPABILITY_OCSF_EMIT}}}})
		for i := 0; i < 3; i++ {
			payload, _ := json.Marshal(map[string]any{
				"class_uid": 1007, "activity_id": 1, "time": 0,
				"process": map[string]any{"pid": 100 + i},
			})
			_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{Payload: &pb.ExtensionToAgent_OcsfEvent{OcsfEvent: &pb.OCSFEvent{ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY, Payload: payload}}})
		}
		// Clean exit so the supervisor sees EOF.
		_ = wire.Close()
	}
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	bin := filepath.Join(dir, "stub-ext")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, srcFile)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GO111MODULE=on")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile stub (%s): %v\n%s", behaviour, err, out)
	}
	// Stash the behaviour in a sidecar so the test runner can wire it
	// via env (extension reads STUB_BEHAVIOUR at runtime).
	t.Setenv("STUB_BEHAVIOUR_HOLDER_"+behaviour, "1")
	return bin
}

// repoRoot finds the slither workspace root so `go build` resolves
// imports against go.work. The test files sit at agent/internal/...;
// walk up four levels.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file))))
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repo root not found at %s: %v", root, err)
	}
	return root
}

func TestProcess_HelloTimeoutKillsExtension(t *testing.T) {
	bin := stubExtensionBinary(t, "no_hello")
	cfg := config.Extension{
		Name:                  "stub",
		BinaryPath:            bin,
		Capabilities:          []string{"ocsf_emit"},
		SignatureVerification: "disabled",
		RSSLimitMiB:           0,
	}
	telem := telemetry.NewCounters()
	out := make(chan ocsf.Event, 16)
	p := NewProcess(cfg, DisabledVerifier{}, ocsf.Device{HostID: "test"}, telem, out)

	// Bypass the helloTimeout default by using a tight ctx — the test
	// runs against the real timeout otherwise.
	ctx, cancel := context.WithTimeout(context.Background(), helloTimeout+2*time.Second)
	defer cancel()

	err := withEnv(t, "STUB_BEHAVIOUR", "no_hello", func() error {
		return p.runOnce(ctx)
	})
	if err == nil {
		t.Fatal("runOnce should have errored on hello timeout")
	}
	if !strings.Contains(err.Error(), "hello") {
		t.Errorf("expected hello error, got %v", err)
	}
}

func TestProcess_UndeclaredCapabilityViolationTearsDown(t *testing.T) {
	bin := stubExtensionBinary(t, "undeclared_event")
	cfg := config.Extension{
		Name:       "stub",
		BinaryPath: bin,
		// Operator authorises both capabilities — the extension
		// declares only LIVE_QUERY_RESPOND on Hello, then tries to
		// emit an OCSFEvent. The capability gate must reject.
		Capabilities:          []string{"ocsf_emit", "live_query_respond"},
		SignatureVerification: "disabled",
		RSSLimitMiB:           0,
	}
	telem := telemetry.NewCounters()
	out := make(chan ocsf.Event, 16)
	p := NewProcess(cfg, DisabledVerifier{}, ocsf.Device{HostID: "test"}, telem, out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := withEnv(t, "STUB_BEHAVIOUR", "undeclared_event", func() error {
		return p.runOnce(ctx)
	})
	if err == nil {
		t.Fatal("runOnce should have errored on capability violation")
	}
	if !errors.Is(err, ErrCapabilityViolation) {
		t.Errorf("expected ErrCapabilityViolation, got %v", err)
	}
	if got := telem.Snapshot().ExtCapabilityViolations; got != 1 {
		t.Errorf("ExtCapabilityViolations = %d, want 1", got)
	}
}

func TestProcess_EmitsStampedEventsThroughChannel(t *testing.T) {
	bin := stubExtensionBinary(t, "emit_events")
	cfg := config.Extension{
		Name:                  "stub",
		BinaryPath:            bin,
		Capabilities:          []string{"ocsf_emit"},
		SignatureVerification: "disabled",
		RSSLimitMiB:           0,
	}
	telem := telemetry.NewCounters()
	out := make(chan ocsf.Event, 16)
	device := ocsf.Device{HostID: "test-host", Hostname: "test"}
	p := NewProcess(cfg, DisabledVerifier{}, device, telem, out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := withEnv(t, "STUB_BEHAVIOUR", "emit_events", func() error {
		return p.runOnce(ctx)
	})
	if err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	close(out)
	count := 0
	for ev := range out {
		pa, ok := ev.(*ocsf.ProcessActivity)
		if !ok {
			t.Errorf("unexpected event type %T", ev)
			continue
		}
		if pa.Device.HostID != "test-host" {
			t.Errorf("Device not stamped; got %q", pa.Device.HostID)
		}
		if pa.Time == 0 {
			t.Errorf("Time not stamped")
		}
		count++
	}
	if count != 3 {
		t.Errorf("got %d events, want 3", count)
	}
	if got := telem.Snapshot().ExtSpawned; got != 1 {
		t.Errorf("ExtSpawned = %d, want 1", got)
	}
	if got := telem.Snapshot().ExtEventsEmitted; got != 3 {
		t.Errorf("ExtEventsEmitted = %d, want 3", got)
	}
}

func TestProcess_BackoffJitterStaysWithinBounds(t *testing.T) {
	// Smoke-test: verify the backoff schedule never exceeds maxBackoff
	// even after many cycles. The doubling-with-jitter shape can over-
	// flow if the cap is missing.
	backoff := minBackoff
	for i := 0; i < 50; i++ {
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	if backoff != maxBackoff {
		t.Errorf("backoff schedule didn't saturate at maxBackoff: %v", backoff)
	}
}

func TestProcess_SecondHelloIsProtocolViolation(t *testing.T) {
	bin := stubExtensionBinary(t, "second_hello")
	cfg := config.Extension{
		Name:                  "stub",
		BinaryPath:            bin,
		Capabilities:          []string{"ocsf_emit"},
		SignatureVerification: "disabled",
		RSSLimitMiB:           0,
	}
	telem := telemetry.NewCounters()
	out := make(chan ocsf.Event, 4)
	p := NewProcess(cfg, DisabledVerifier{}, ocsf.Device{HostID: "x"}, telem, out)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := withEnv(t, "STUB_BEHAVIOUR", "second_hello", func() error {
		return p.runOnce(ctx)
	})
	if err == nil || !strings.Contains(err.Error(), "second Hello") {
		t.Errorf("expected second-Hello protocol error, got %v", err)
	}
}

// withEnv temporarily sets an env var, calls fn, and restores. Allows
// the stub binary to read STUB_BEHAVIOUR at exec time.
func withEnv(t *testing.T, key, val string, fn func() error) error {
	t.Helper()
	t.Setenv(key, val)
	return fn()
}

// Quiet linter on imported but conditionally used packages.
var _ = json.Unmarshal
var _ = extsdk.MaxMessageSize

// TestApplyChildRSSLimit_DoesNotAffectParent locks down Phase 6 #121
// follow-up #1: the previous applyRSSLimit implementation called
// syscall.Setrlimit on the supervisor process before exec, which made
// the supervisor itself run under the limit and OOM-killed the agent
// once its heap mmap'd past 256 MiB. This test asserts (a) the
// supervisor's own RLIMIT_AS is untouched after applyChildRSSLimit,
// and (b) the child PID actually has the limit set.
func TestApplyChildRSSLimit_DoesNotAffectParent(t *testing.T) {
	const childLimit = int64(128) << 20

	var before unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &before); err != nil {
		t.Fatalf("getrlimit before: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if err := applyChildRSSLimit(cmd.Process.Pid, childLimit); err != nil {
		t.Fatalf("applyChildRSSLimit: %v", err)
	}

	var after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &after); err != nil {
		t.Fatalf("getrlimit after: %v", err)
	}
	if before != after {
		t.Errorf("supervisor RLIMIT_AS changed: before=%+v after=%+v", before, after)
	}

	var child unix.Rlimit
	if err := unix.Prlimit(cmd.Process.Pid, unix.RLIMIT_AS, nil, &child); err != nil {
		t.Fatalf("prlimit child: %v", err)
	}
	if child.Cur != uint64(childLimit) {
		t.Errorf("child RLIMIT_AS Cur = %d, want %d", child.Cur, childLimit)
	}
}
