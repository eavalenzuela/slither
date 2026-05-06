//go:build !linux

package extensions

import (
	"errors"
	"os"
)

// socketpair on non-Linux returns an error — the supervisor is
// Linux-only in v1 (matches the agent's own platform target per
// PROJECT.md §3.7). macOS / Windows agents are Phase 7+.
func socketpair() (agent *os.File, ext *os.File, err error) {
	return nil, nil, errors.New("extensions: supervisor is Linux-only")
}

func applyChildRSSLimit(_ int, _ int64) error { return nil }
