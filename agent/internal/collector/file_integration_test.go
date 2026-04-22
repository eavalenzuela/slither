//go:build linux && integration

package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestFileCollector_OpenatObserved loads file.bpf.c, opens a temp file with
// O_CREAT|O_WRONLY, and asserts the corresponding openat tracepoint record
// is decoded onto the channel.
func TestFileCollector_OpenatObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawFileEvent, 1024)
	cfg := config.FileCollector{Enabled: true}
	c := newFileCollector(out, cfg, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	dir := t.TempDir()
	target := filepath.Join(dir, "slither-it-openat")

	fd, err := unix.Openat(unix.AT_FDCWD, target,
		unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("openat %s: %v", target, err)
	}
	_ = unix.Close(fd)
	defer os.Remove(target)

	_, ok := waitForEvent(t, out, func(e pipeline.RawFileEvent) bool {
		// The collector doesn't yet filter in-kernel, so any FileOpen* against
		// our unique tempfile path is enough. Kind is either OpenCreate or
		// OpenWrite depending on the SL_FILE_* classification in the program.
		return (e.Kind == pipeline.FileOpenCreate || e.Kind == pipeline.FileOpenWrite) &&
			e.Path == target
	}, 3*time.Second)
	if !ok {
		t.Fatalf("no openat event seen for %s within 3s", target)
	}
}

// TestFileCollector_UnlinkatObserved drives sys_enter_unlinkat and asserts a
// matching FileUnlink event.
func TestFileCollector_UnlinkatObserved(t *testing.T) {
	requirePrivileged(t)

	out := make(chan pipeline.RawFileEvent, 1024)
	cfg := config.FileCollector{Enabled: true}
	c := newFileCollector(out, cfg, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	dir := t.TempDir()
	target := filepath.Join(dir, "slither-it-unlink")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := unix.Unlinkat(unix.AT_FDCWD, target, 0); err != nil {
		t.Fatalf("unlinkat %s: %v", target, err)
	}

	_, ok := waitForEvent(t, out, func(e pipeline.RawFileEvent) bool {
		return e.Kind == pipeline.FileUnlink && e.Path == target
	}, 3*time.Second)
	if !ok {
		t.Fatalf("no unlink event seen for %s within 3s", target)
	}
}
