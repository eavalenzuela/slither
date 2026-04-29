//go:build !linux

package respond

// WireQuarantineHandlers is a no-op on non-Linux platforms. Default
// not-implemented handler stays in place so server-pushed
// QUARANTINE_FILE lands a clean FAILED + audit row. Phase 7 ports
// (macOS / Windows) ship their own quarantine_<os>.go.
func WireQuarantineHandlers(*Executor) {}
