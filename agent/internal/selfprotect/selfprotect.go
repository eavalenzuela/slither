// Package selfprotect implements the Phase 5 #94 agent
// self-protection bar: PR_SET_DUMPABLE=0, anti-debug refusal,
// state-dir lockdown, and post-init capability ambient-drop.
//
// The bar is bounded by what's actionable without kernel modules.
// Specifically out of scope (per ADR-0035):
//   - Boot integrity / TPM measured boot (Phase 6+).
//   - Hiding the agent from ps (explicit non-goal — operators must
//     always be able to see slither-agent in their process list).
//   - Anti-rootkit (kernel-mode attackers can defeat any user-space
//     protection; documented in docs/threat-model.md when #102 lands).
//
// Every function in this package is best-effort: errors are returned
// to the caller for logging, not for tearing down the agent. A
// kernel that rejects PR_SET_DUMPABLE (extremely rare) shouldn't
// stop telemetry from flowing.
package selfprotect

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ErrTracerAttached is returned by CheckNotTraced when /proc/self/status
// reports a non-zero TracerPid. The agent's main entry point treats
// this as fatal — a process that boots while ptrace-attached is, by
// definition, already compromised in the way this package's other
// hardenings try to prevent.
var ErrTracerAttached = errors.New("selfprotect: ptrace tracer attached at startup")

// chmodFn is the indirection point for tests that want to inject an
// EROFS-shaped error without a real read-only mount.
var chmodFn = os.Chmod

// LockdownStateDirs sets mode 0700 on the agent's state, log, and
// config directories. systemd's StateDirectory=/LogsDirectory= already
// does this on supported distros; this is belt-and-braces for the
// container path (where StateDirectory= is irrelevant) and for hosts
// running the binary directly without the unit.
//
// Best-effort: directories that don't exist are silently skipped.
// Read-only mounts (e.g. /etc/slither under systemd's
// ProtectSystem=strict) are silently skipped — the parent unit's
// hardening already covers the dir, and chmod against a read-only
// FS is a self-inflicted WARN, not a real failure. Permission errors
// otherwise are returned (a user that can't chmod the dir also
// probably can't fix the security posture).
func LockdownStateDirs(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("selfprotect: stat %s: %w", p, err)
		}
		if !fi.IsDir() {
			// Not a directory — caller passed a stray path. Skip
			// silently rather than chmod a regular file to 0700.
			continue
		}
		if fi.Mode().Perm() == 0o700 {
			// Already locked down — nothing to do.
			continue
		}
		if err := chmodFn(p, 0o700); err != nil {
			if errors.Is(err, syscall.EROFS) {
				continue
			}
			return fmt.Errorf("selfprotect: chmod %s: %w", p, err)
		}
	}
	return nil
}
