package keystore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// File is the Phase 2 #36 storage shape, factored behind the Store
// interface so the rest of the agent can talk to "the keystore"
// instead of the file path triplet directly. Mode bits match the
// Phase 4 #94 self-protection contract: client.key 0600, the rest
// 0644. The state dir itself is locked down to 0700 by selfprotect's
// LockdownStateDirs call earlier in app.Run.
type File struct {
	stateDir string
}

// NewFile returns a File store rooted at stateDir. The directory
// must already exist (matches systemd's StateDirectory= contract;
// the Phase 5 #92 deb/rpm postinst creates it).
func NewFile(stateDir string) *File { return &File{stateDir: stateDir} }

// Name implements Store.
func (f *File) Name() string { return "file" }

// Save writes the three PEM blobs atomically. Each blob is written
// to a sibling .tmp file then renamed into place — same crash-safety
// pattern Phase 2 #36 used.
func (f *File) Save(m Material) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := writeAtomic(f.path("client.key"), m.ClientKey, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(f.path("client.crt"), m.ClientCert, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(f.path("ca.crt"), m.CACert, 0o644); err != nil {
		return err
	}
	return nil
}

// Load reads the three PEM blobs. ErrNotFound when client.key is
// missing; the assumption is the trio is written together so a
// missing key implies the whole bundle is missing.
func (f *File) Load() (Material, error) {
	key, err := os.ReadFile(f.path("client.key"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Material{}, ErrNotFound
		}
		return Material{}, fmt.Errorf("keystore.File.Load: client.key: %w", err)
	}
	cert, err := os.ReadFile(f.path("client.crt"))
	if err != nil {
		return Material{}, fmt.Errorf("keystore.File.Load: client.crt: %w", err)
	}
	ca, err := os.ReadFile(f.path("ca.crt"))
	if err != nil {
		return Material{}, fmt.Errorf("keystore.File.Load: ca.crt: %w", err)
	}
	return Material{ClientKey: key, ClientCert: cert, CACert: ca}, nil
}

func (f *File) path(name string) string {
	return filepath.Join(f.stateDir, name)
}

// writeAtomic writes data to path via an os.Rename of a sibling
// .tmp file. Mirrors the helper in agent/internal/enroll so a future
// keystore-only refactor can drop one of the two duplicates.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	// #nosec G306 -- mode is caller-controlled (0600 for keys, 0644 for certs)
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("keystore.File: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("keystore.File: rename %s: %w", path, err)
	}
	return nil
}
