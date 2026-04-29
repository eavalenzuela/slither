//go:build !linux

package respond

// WireIsolationHandlers is a no-op on non-Linux platforms. Phase 7
// macOS / Windows ports ship their own isolate_<os>.go (Windows
// Firewall, pf on macOS).
func WireIsolationHandlers(*Executor) {}
