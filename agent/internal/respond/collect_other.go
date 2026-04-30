//go:build !linux

package respond

// WireCollectHandlers is a no-op on non-Linux platforms. Phase 7
// macOS / Windows ports ship their own collect_<os>.go.
func WireCollectHandlers(*Executor) {}
