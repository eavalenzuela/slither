package console

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// LoadOrCreateSessionKey reads a 64-byte secret from path. Generates +
// writes a fresh one (mode 0600) when the file is absent. Returns the
// raw bytes — the console package treats the file content as the
// canonical session-cookie HMAC key.
//
// path == "" generates an ephemeral in-memory key and is intended for
// tests only; production must always be backed by a persistent file
// so a server restart doesn't invalidate every operator's session.
func LoadOrCreateSessionKey(path string) ([]byte, error) {
	if path == "" {
		buf := make([]byte, 64)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		return buf, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err == nil {
		if len(data) < 32 {
			return nil, fmt.Errorf("console: session key file %q too short (%d bytes, need 32+)", path, len(data))
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("console: read session key %q: %w", path, err)
	}

	// First boot — generate + persist.
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("console: generate session key: %w", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("console: write session key %q: %w", path, err)
	}
	return buf, nil
}
