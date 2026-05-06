//go:build !linux

package keystore

import "errors"

// errUnsupported is the canonical "this platform doesn't have a
// kernel keyring" sentinel. Callers don't usually inspect it —
// AutoSelect short-circuits on any error — but tests find it
// useful for assertions. Lives only in non-Linux builds because the
// Linux path always succeeds or reports a real syscall error.
var errUnsupported = errors.New("keystore: kernel keyring unsupported on this platform")

// tryKeyringPlatform on non-Linux always reports "unsupported" so
// AutoSelect falls back to the File store. The agent doesn't ship
// for non-Linux today (Phase 7 platform expansion is gated on
// demand), but tests + lint run on dev macOS / Windows machines and
// must compile cleanly.
func tryKeyringPlatform() (Store, error) { return nil, errUnsupported }
