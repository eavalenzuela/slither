//go:build !linux

package respond

// WireKillHandlers is a no-op on non-Linux platforms. The default
// not-implemented handlers stay in place so a server-pushed
// KILL_PROCESS lands a clean FAILED + audit row instead of being
// silently dropped. Linux is the v1 platform per ADR-0001;
// macOS / Windows ports (Phase 7) ship their own kill_<os>.go.
func WireKillHandlers(*Executor) {}
