//go:build linux

package extensions

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketpair allocates a connected AF_UNIX SOCK_STREAM pair. The
// agent end is returned as *os.File (the supervisor reads/writes via
// its Read/Write — syscall semantics map to socket(2) directly). The
// extension end is returned as *os.File so it can be passed via
// cmd.ExtraFiles, where it lands at FD 3 in the child.
func socketpair() (agent, ext *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	agent = os.NewFile(uintptr(fds[0]), "ext-supervisor")
	ext = os.NewFile(uintptr(fds[1]), "ext-child")
	if agent == nil || ext == nil {
		// os.NewFile returns nil only on a negative fd, which
		// Socketpair shouldn't produce — defend against an unlikely
		// regression rather than panic later.
		return nil, nil, fmt.Errorf("socketpair: nil *os.File from fds %v", fds)
	}
	return agent, ext, nil
}

// applyChildRSSLimit sets RLIMIT_AS on a freshly-spawned child via
// prlimit(2). RLIMIT_AS bounds total virtual address-space — exceeding
// it triggers the kernel's OOM path against the offender, which on
// modern Linux is a clean SIGKILL the supervisor's restart loop
// observes via the abnormal exit (ext_restarts ticks).
//
// The previous implementation called setrlimit on the supervisor
// process itself before exec, on the assumption that exec inherited
// rlimits. That was both true and catastrophic: the supervisor *did*
// inherit the limit (correct), but it also ran under it for the rest
// of its lifetime — once the supervisor's own heap mmap'd past 256
// MiB it OOM-killed the agent during the next ext.Hello read. Phase 6
// #121 V1 caught this under signature_verification: disabled, where
// the cosign verify-blob path that normally allocates ahead of the
// frame read isn't taken; production paths that load cosign happened
// to clear the limit before the read so the bug stayed hidden.
//
// prlimit(pid, ...) sets the rlimit on the named pid only. Kernel
// allows this when the caller's uid/gid + capabilities permit
// CAP_SYS_RESOURCE on the target — agent runs as root in the standard
// deployment so the call always succeeds; non-root edge cases (a
// rootless dev shell) get a noisy log but no fatal: the extension
// still runs, just unbounded.
//
// Bytes <= 0 is a no-op.
func applyChildRSSLimit(pid int, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	rl := unix.Rlimit{Cur: uint64(bytes), Max: uint64(bytes)}
	if err := unix.Prlimit(pid, unix.RLIMIT_AS, &rl, nil); err != nil {
		return fmt.Errorf("prlimit RLIMIT_AS pid=%d bytes=%d: %w", pid, bytes, err)
	}
	return nil
}
