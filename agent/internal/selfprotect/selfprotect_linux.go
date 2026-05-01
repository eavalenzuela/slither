//go:build linux

package selfprotect

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// SetDumpable sets PR_SET_DUMPABLE=0 on the current process. Effects:
//   - blocks ptrace(PTRACE_ATTACH) from non-CAP_SYS_PTRACE callers;
//   - suppresses core dumps (no agent memory image on segfault);
//   - flips /proc/<pid>/* to root-only readability for non-owner UIDs,
//     so siblings on the same host can't grep maps/environ/etc.
//
// PR_SET_DUMPABLE=0 is reset back to 1 across exec(2) by the kernel,
// so this only protects the running agent process, not anything it
// forks via collect_artifacts subprocess pattern (#100). Forked
// subprocesses must call this themselves at their entry point.
func SetDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("selfprotect: PR_SET_DUMPABLE: %w", err)
	}
	return nil
}

// CheckNotTraced returns ErrTracerAttached when /proc/self/status
// reports a non-zero TracerPid line. The kernel writes this field
// based on the current ptracer-tracee link; PR_SET_DUMPABLE=0 prevents
// new attaches but doesn't unhook a tracer that was attached before
// the agent's startup. So this check runs first.
//
// We accept the small TOCTOU window between this check and the
// subsequent SetDumpable call; an attacker with attach capability
// who races into that window has CAP_SYS_PTRACE and the security
// model is already compromised.
func CheckNotTraced() error {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return fmt.Errorf("selfprotect: open /proc/self/status: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("selfprotect: parse TracerPid %q: %w", fields[1], err)
		}
		if pid != 0 {
			return fmt.Errorf("%w: TracerPid=%d", ErrTracerAttached, pid)
		}
		return nil
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("selfprotect: read /proc/self/status: %w", err)
	}
	// No TracerPid line at all on this kernel — older kernels (< 3.5)
	// might omit it. Treat as "no tracer" rather than failing closed.
	return nil
}

// DropAmbientPostInit lowers CAP_BPF and CAP_PERFMON from the ambient
// set. After this call:
//   - any process the agent fork+execs no longer inherits those caps
//     (the bounding set retains them, so a deliberate explicit
//     re-elevation via setuid-shaped tooling would still work);
//   - the agent's existing BPF program FDs and tracepoint perf
//     events keep working — those are FD-based access, not cap-checked
//     on every syscall.
//
// CAP_KILL, CAP_NET_ADMIN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, and
// CAP_SYS_PTRACE all stay in ambient because the agent's response
// handlers (#78–#81) and enricher hot paths exercise them
// continuously. Phase 5 #100's quarantine subprocess inherits the
// reduced ambient set + adds back DAC_* via its own setup path —
// that's the right place to re-narrow caps per task.
//
// Best-effort: unsupported kernels (< 4.3, where ambient caps don't
// exist) report ENOSYS and we return nil so older container hosts
// don't fail boot.
func DropAmbientPostInit() error {
	for _, cap := range []uintptr{unix.CAP_BPF, unix.CAP_PERFMON} {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_LOWER, cap, 0, 0); err != nil {
			// ENOSYS = ambient caps not supported on this kernel.
			// EINVAL = the cap isn't in the inheritable set anyway,
			// which means there was nothing to drop (e.g. a build
			// that didn't ship CAP_BPF in the unit's AmbientCapabilities=).
			// Either way, not fatal.
			if err == unix.ENOSYS || err == unix.EINVAL {
				continue
			}
			return fmt.Errorf("selfprotect: PR_CAP_AMBIENT_LOWER cap=%d: %w", cap, err)
		}
	}
	return nil
}
