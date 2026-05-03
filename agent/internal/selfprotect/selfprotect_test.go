package selfprotect

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLockdownStateDirs_ChmodsExistingDirs(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a")
	b := filepath.Join(tmp, "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	if err := LockdownStateDirs(a, b); err != nil {
		t.Fatalf("LockdownStateDirs: %v", err)
	}

	for _, d := range []string{a, b} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if got := fi.Mode().Perm(); got != 0o700 {
			t.Errorf("%s mode = %v, want 0700", d, got)
		}
	}
}

func TestLockdownStateDirs_SkipsMissingPaths(t *testing.T) {
	t.Parallel()
	if err := LockdownStateDirs("/nonexistent/path/should/silently/skip"); err != nil {
		t.Errorf("missing path returned error: %v", err)
	}
}

func TestLockdownStateDirs_SkipsRegularFiles(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	f := filepath.Join(tmp, "regular")
	if err := os.WriteFile(f, []byte("not a dir"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := LockdownStateDirs(f); err != nil {
		t.Errorf("regular file returned error: %v", err)
	}
	// File mode untouched.
	fi, _ := os.Stat(f)
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("regular file got chmodded to %v; want 0644", got)
	}
}

func TestLockdownStateDirs_EmptyPaths(t *testing.T) {
	t.Parallel()
	// Empty + zero variadic both legal.
	if err := LockdownStateDirs(); err != nil {
		t.Errorf("zero paths returned error: %v", err)
	}
	if err := LockdownStateDirs(""); err != nil {
		t.Errorf("empty path returned error: %v", err)
	}
}

func TestLockdownStateDirs_AlreadyLockedDownNoOp(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	d := filepath.Join(tmp, "already-700")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := LockdownStateDirs(d); err != nil {
		t.Fatalf("LockdownStateDirs: %v", err)
	}
	fi, _ := os.Stat(d)
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("mode = %v, want 0700", got)
	}
}

func TestLockdownStateDirs_ROFSIsSkipped(t *testing.T) {
	// Phase 5 #103 V1 captured the production surface: chmod against
	// /etc/slither under ProtectSystem=strict returns EROFS;
	// selfprotect must not bubble that as a WARN. Inject the errno
	// via the chmodFn seam rather than constructing a real read-only
	// mount (would need root + bind-mount privileges in CI).
	tmp := t.TempDir()
	d := filepath.Join(tmp, "ro")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	prev := chmodFn
	chmodFn = func(string, os.FileMode) error { return &os.PathError{Op: "chmod", Path: d, Err: syscall.EROFS} }
	defer func() { chmodFn = prev }()
	if err := LockdownStateDirs(d); err != nil {
		t.Errorf("EROFS should be skipped silently; got %v", err)
	}
}

func TestLockdownStateDirs_NonROFSChmodFails(t *testing.T) {
	// EPERM and friends still surface — only EROFS is the read-only-
	// mount carve-out.
	tmp := t.TempDir()
	d := filepath.Join(tmp, "eperm")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	prev := chmodFn
	chmodFn = func(string, os.FileMode) error { return &os.PathError{Op: "chmod", Path: d, Err: syscall.EPERM} }
	defer func() { chmodFn = prev }()
	if err := LockdownStateDirs(d); err == nil {
		t.Error("EPERM should bubble as error; got nil")
	}
}

func TestErrTracerAttached_IsErrorsIs(t *testing.T) {
	// Sanity check: ErrTracerAttached wraps cleanly so callers can
	// gate on errors.Is().
	wrapped := errors.New("selfprotect: ptrace tracer attached at startup: TracerPid=42")
	if errors.Is(wrapped, ErrTracerAttached) {
		t.Error("string-equal isn't errors.Is — sentinel needs %w wrap")
	}
}
