//go:build !linux

package keystore

// tryKeyringPlatform on non-Linux always reports "unsupported" so
// AutoSelect falls back to the File store. The agent doesn't ship
// for non-Linux today (Phase 7 platform expansion is gated on
// demand), but tests + lint run on dev macOS / Windows machines and
// must compile cleanly.
func tryKeyringPlatform() (Store, error) { return nil, errUnsupported }
