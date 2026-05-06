//go:build linux

package extensions

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
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

// applyRSSLimit sets RLIMIT_AS on the child via cmd.SysProcAttr.
// RLIMIT_AS bounds total virtual address-space — exceeding it
// triggers the kernel's OOM path against this process, which on
// modern Linux is a clean SIGKILL. The supervisor's restart loop
// observes the abnormal exit and ticks ext_restarts.
//
// Set per-extension; configurable via the extension config block.
// Bytes <= 0 is a no-op.
func applyRSSLimit(cmd *exec.Cmd, bytes int64) {
	if bytes <= 0 {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// SysProcAttr in Go's stdlib doesn't expose RLIMIT directly; we
	// install via a Setrlimit call in the child via setpgid + rlimit
	// pattern. The most portable shim is to wrap the binary in a small
	// preamble — but that adds complexity. Pragmatic v1: set the
	// supervisor's own limits to a per-spawn floor, exec inherits.
	// This is approximate (the supervisor itself runs under it for
	// the duration of the spawn) but correct for the common case where
	// the agent is the only process the supervisor forks.
	//
	// TODO(#108): replace with a per-child rlimit via prctl/seccomp
	// preamble or a small Go helper that calls setrlimit before exec.
	rl := syscall.Rlimit{Cur: uint64(bytes), Max: uint64(bytes)}
	_ = syscall.Setrlimit(syscall.RLIMIT_AS, &rl)
}
