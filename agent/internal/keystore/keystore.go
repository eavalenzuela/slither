// Package keystore is the agent-side persistence surface for the
// client cert + key + CA cert. Phase 5 #98 closes IMPLEMENTATION.md
// §10.2 — kernel keyring storage with file fallback.
//
// Two implementations live behind the Store interface:
//
//   - Keyring (linux, user-keyring): client.key + client.cert +
//     ca.cert live as "user"-type keys under @u. Survive reboot
//     only if the operator's session keyring persists; for the
//     systemd-managed agent unit this is process-lifetime, so the
//     usual flow is `slither-agent enroll` → keys land in keyring
//     for the rest of the boot, then a fresh enroll on next boot.
//     For systems where that's painful (long-uptime fleets), the
//     File implementation is the right answer — the operator's
//     install policy picks one.
//
//   - File: writes PEM blobs to /etc/slither/{client.key,client.cert,
//     ca.cert} with mode 0600 / 0644. Same shape Phase 2 #36 shipped;
//     this is the durable path that survives reboot.
//
// host_id stays as a plain file (/etc/slither/host_id or
// $StateDir/host_id) under both stores — it's a stable identifier,
// not a secret.
//
// AutoSelect picks Keyring when add_key(2) succeeds, File otherwise.
// Operators who want determinism set the choice explicitly via the
// agent.output.grpc.keystore config key (Phase 5+ knob; not committed
// in this changeset to avoid scope creep — AutoSelect is the v1
// answer).

package keystore

import (
	"errors"
	"fmt"
)

// Material is the bundle of PEM blobs the agent persists post-enroll.
type Material struct {
	ClientKey  []byte
	ClientCert []byte
	CACert     []byte
}

// Validate sanity-checks all three blobs are non-empty. Callers
// invoke before Save to fail fast on a malformed enroll response.
func (m Material) Validate() error {
	if len(m.ClientKey) == 0 {
		return errors.New("keystore: client key empty")
	}
	if len(m.ClientCert) == 0 {
		return errors.New("keystore: client cert empty")
	}
	if len(m.CACert) == 0 {
		return errors.New("keystore: ca cert empty")
	}
	return nil
}

// Store is the Save/Load surface for cert material. Implementations
// MUST be safe for one writer + many readers; the agent enrols once
// and reads on every reconnect.
type Store interface {
	// Save persists m. Existing material is replaced atomically from
	// the reader's perspective: a concurrent Load either sees the
	// previous Material or the new one, never a mix.
	Save(m Material) error

	// Load returns the persisted material. ErrNotFound means no
	// previous Save has happened on this Store.
	Load() (Material, error)

	// Name identifies the implementation for diagnostics
	// ("kernel-keyring" or "file").
	Name() string
}

// ErrNotFound signals "no material has been persisted via this Store
// yet". Distinct from a permission/IO error so the caller can
// dispatch to enrollment instead of bubbling up an opaque failure.
var ErrNotFound = errors.New("keystore: not found")

// AutoSelect returns the preferred store for this host. On Linux it
// probes the kernel user keyring; on systems where the probe fails
// (containers without /proc/keys, kernels < 3.5 without
// KEYCTL_GET_KEYRING_ID, sandbox profiles dropping CAP_SYSADMIN
// from CRIU/seccomp) it falls back to File at stateDir.
func AutoSelect(stateDir string) Store {
	if k, err := tryKeyring(); err == nil && k != nil {
		return k
	}
	return NewFile(stateDir)
}

// tryKeyring is implemented per-OS. Non-Linux always returns
// (nil, errUnsupported) to force AutoSelect onto the File path.
// Linux returns a Keyring instance after a successful add_key probe.
func tryKeyring() (Store, error) { return tryKeyringPlatform() }

// errUnsupported is the canonical "this platform doesn't have a
// kernel keyring" sentinel. Callers don't usually inspect it —
// AutoSelect short-circuits on any error — but tests find it
// useful for assertions.
var errUnsupported = errors.New("keystore: kernel keyring unsupported on this platform")

// formatProbeError annotates errors from the keyring probe with the
// store name so log lines stay greppable.
func formatProbeError(err error) error {
	return fmt.Errorf("keystore.AutoSelect: keyring probe: %w", err)
}
