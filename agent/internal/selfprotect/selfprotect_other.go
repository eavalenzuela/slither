//go:build !linux

package selfprotect

// Non-Linux stubs. The agent only ships for Linux today (agent
// binaries published in Phase 5 #93 are linux/amd64 + linux/arm64),
// but tests and lint runs on dev machines must compile cleanly. Each
// stub is a no-op + returns nil so a hypothetical macOS dev build
// boots through the same self-protect block without crashing.

// SetDumpable is a no-op on non-Linux. macOS / Windows have their
// own ptrace-equivalent stories; Phase 7 (platform expansion) is
// where they get implemented.
func SetDumpable() error { return nil }

// CheckNotTraced is a no-op on non-Linux. /proc/self/status is a
// linuxism.
func CheckNotTraced() error { return nil }

// DropAmbientPostInit is a no-op on non-Linux. Linux capabilities
// don't exist on macOS / Windows.
func DropAmbientPostInit() error { return nil }
