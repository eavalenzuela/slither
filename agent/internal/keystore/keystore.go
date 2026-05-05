// Package keystore is the agent-side persistence surface for the
// client cert + key + CA cert. Phase 5 #98 shipped the original
// keyring + file split closing IMPLEMENTATION.md §10.2; Phase 6 #117
// resolved Gap A (ADR-0038) by moving the keyring target from `@s`
// (per-PAM-session — reaped at the enroll subprocess boundary) to
// `@u` (per-uid persistent — survives into the long-lived agent
// unit's lifetime).
//
// Two implementations live behind the Store interface:
//
//   - Keyring (linux, user-keyring `@u`): client.key + client.cert +
//     ca.cert live as "user"-type keys under the per-uid keyring.
//     Phase 6 #117 / ADR-0038. Loses the keys at reboot — that's
//     deliberate; the file store under /etc/slither/ stays
//     populated as the durable belt-and-braces so a fresh boot
//     reads from disk and the keyring rebuilds on the first
//     successful Save. The keyring's value is in-RAM-only secrecy
//     for hosts that explicitly cleared the file store; operators
//     wanting tighter scoping use the TPM-sealed variant
//     (Phase 6 #118).
//
//   - File: writes PEM blobs to /etc/slither/{client.key,client.cert,
//     ca.cert} with mode 0600 / 0644. Same shape Phase 2 #36 shipped;
//     this is the durable path that survives reboot.
//
// host_id stays as a plain file (/etc/slither/host_id or
// $StateDir/host_id) under both stores — it's a stable identifier,
// not a secret.
//
// AutoSelect picks Keyring when add_key(2) succeeds against `@u`,
// File otherwise. Operators who want determinism set the choice
// explicitly via the agent.output.grpc.keystore config key (Phase
// 5+ knob; not committed in this changeset to avoid scope creep —
// AutoSelect is the v1 answer).

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
//
// AutoSelect remains a single-arg shim for backward compat. Phase 6
// #118 callers wanting the TPM opt-in use AutoSelectWithOptions.
func AutoSelect(stateDir string) Store {
	return AutoSelectWithOptions(stateDir, AutoSelectOptions{})
}

// AutoSelectOptions tunes the auto-select chain. Phase 6 #118 added
// the TPM opt-in; future Phase 7+ knobs (e.g. force-file, force-
// keyring) land here without re-shaping the call sites.
type AutoSelectOptions struct {
	// TPM, when true, attempts the Phase 6 #118 PCR-bound store
	// before the keyring → file fallback chain. False (the default)
	// preserves the Phase 6 #117 chain: keyring → file.
	TPM bool
}

// AutoSelectWithOptions is the configurable form. Resolution order:
//
//  1. TPM (when opts.TPM is true and the platform satisfies the probe)
//  2. Keyring (when add_key against `@u` succeeds — Phase 6 #117)
//  3. File at stateDir (always succeeds)
//
// Each fallback is silent at the package level — the agent's
// startup path logs the picked store name once via the existing
// `keystore: <Name>` slog line so operators can verify the
// effective store post-enrol without inspecting probe internals.
func AutoSelectWithOptions(stateDir string, opts AutoSelectOptions) Store {
	if opts.TPM {
		if t, err := tryTPM(stateDir); err == nil && t != nil {
			return t
		}
	}
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
