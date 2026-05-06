//go:build linux

package keystore

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// keyringDescriptionPrefix scopes our keys under a unique
// description namespace so a host running multiple agents (dev +
// prod side-by-side) keeps them isolated. Phase 5 #98.
const keyringDescriptionPrefix = "slither.agent."

// Keyring stores cert material as "user"-typed keys under the
// per-uid user keyring (@u) — survives the enroll subprocess →
// agent-service session boundary. Phase 6 #117 / ADR-0038 picked
// this strategy after Phase 5 #103 V9 exposed Gap A: the original
// @s (session keyring) target is per-PAM-session, so keys written
// by `slither-agent enroll` were reaped before the systemd-managed
// agent unit's first read.
//
// @u trade-offs:
//
//   - Survives session boundary: every process running as the
//     agent's uid sees the same keyring, so the enroll subprocess
//     and the long-lived service share one ring without a helper
//     unit (ADR-0038 option c) or files-only (option a).
//   - Available on every kernel ≥ 3.5 — well below the project's
//     5.15 floor (ADR-0010).
//   - Cross-tenant caveat: any process running as the same uid can
//     read the keys. The agent runs as root in the standard
//     deployment, so co-resident-process risk reduces to "another
//     root process on the same host", which is already out of
//     scope per docs/threat-model.md Surface 4. Production
//     deployments wanting tighter scoping run the agent under a
//     dedicated uid.
//
// Files at /etc/slither/ stay populated as a durability + recovery
// belt-and-braces (ADR-0038 §"why both"); the keyring write is
// best-effort on top so a kernel without CONFIG_KEYS, a confined
// container, or a SELinux denial degrades cleanly to the file
// store. Operators wanting in-RAM-only secrets use the TPM-sealed
// variant (Phase 6 #118).
type Keyring struct {
	ringID int
}

// tryKeyringPlatform is the linux probe used by AutoSelect. Returns
// (nil, errUnsupported) when add_key fails — typically because
// the kernel was built without CONFIG_KEYS, the cgroup confinement
// dropped CAP_SYSADMIN, or /proc/keys is unreadable from the agent
// namespace.
func tryKeyringPlatform() (Store, error) {
	ringID, err := keyringID()
	if err != nil {
		return nil, formatProbeError(err)
	}
	// Link @u into @s so this process possesses keys in @u. KEYCTL_READ
	// is possession-checked: without the link, the default session-
	// keyring chain doesn't include @u, so reading a freshly-added @u
	// key returns EACCES even when the user-perm bits would grant it.
	// Phase 6 #121 follow-up #3 — without this every host silently fell
	// through to the file store, leaving ADR-0038's @u claim
	// aspirational. Best-effort: when keyringID fell back to @s the
	// link is a no-op error we ignore; if it fails for any other reason
	// the probe READ below fails cleanly and AutoSelect drops to file.
	_, _ = unix.KeyctlInt(unix.KEYCTL_LINK, ringID, unix.KEY_SPEC_SESSION_KEYRING, 0, 0)

	// Probe: write + read + unlink a marker key. If any step fails,
	// the keyring isn't reliably usable on this host.
	probeDesc := keyringDescriptionPrefix + "probe"
	id, err := unix.AddKey("user", probeDesc, []byte("ok"), ringID)
	if err != nil {
		return nil, formatProbeError(err)
	}
	defer func() {
		// Best-effort unlink so the probe key doesn't linger.
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, ringID, 0, 0)
	}()
	if _, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0); err != nil {
		return nil, formatProbeError(err)
	}
	return &Keyring{ringID: ringID}, nil
}

// keyringID returns the per-uid user keyring's ID (@u). Phase 6 #117 /
// ADR-0038 made @u the durable target so keys written by the enroll
// subprocess survive into the long-lived agent unit's lifetime.
//
// Falls back to the session keyring (@s) when @u is unavailable —
// rare in practice (would require a kernel without per-uid keyrings,
// which Linux ≥ 3.5 always has), but kept as a defensive degradation
// path so a misconfigured container shape still has *some* keyring
// option before AutoSelect drops to the file store.
func keyringID() (int, error) {
	if id, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true); err == nil {
		return id, nil
	}
	if id, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true); err == nil {
		return id, nil
	}
	return 0, errors.New("keystore: no keyring available")
}

// Name implements Store.
func (k *Keyring) Name() string { return "kernel-keyring" }

// Save adds (or replaces) the three "user" keys under the agent's
// keyring. add_key replaces an existing key with the same description
// in the same keyring atomically — no manual unlink needed.
func (k *Keyring) Save(m Material) error {
	if err := m.Validate(); err != nil {
		return err
	}
	for _, kv := range []struct {
		desc string
		val  []byte
	}{
		{keyringDescriptionPrefix + "client.key", m.ClientKey},
		{keyringDescriptionPrefix + "client.crt", m.ClientCert},
		{keyringDescriptionPrefix + "ca.crt", m.CACert},
	} {
		if _, err := unix.AddKey("user", kv.desc, kv.val, k.ringID); err != nil {
			return fmt.Errorf("keystore.Keyring.Save: add_key %s: %w", kv.desc, err)
		}
	}
	return nil
}

// Load reads each key by its description. ErrNotFound when any of
// the three is missing — partial state is treated as no state.
func (k *Keyring) Load() (Material, error) {
	descKey := keyringDescriptionPrefix + "client.key"
	descCert := keyringDescriptionPrefix + "client.crt"
	descCA := keyringDescriptionPrefix + "ca.crt"

	keyVal, err := readKey(k.ringID, descKey)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Material{}, ErrNotFound
		}
		return Material{}, fmt.Errorf("keystore.Keyring.Load: %s: %w", descKey, err)
	}
	certVal, err := readKey(k.ringID, descCert)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.Keyring.Load: %s: %w", descCert, err)
	}
	caVal, err := readKey(k.ringID, descCA)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.Keyring.Load: %s: %w", descCA, err)
	}
	return Material{ClientKey: keyVal, ClientCert: certVal, CACert: caVal}, nil
}

// readKey searches ringID for a "user"-type key with description
// desc + reads its payload. Returns ErrNotFound when the key isn't
// present in the ring.
func readKey(ringID int, desc string) ([]byte, error) {
	id, err := unix.KeyctlSearch(ringID, "user", desc, 0)
	if err != nil {
		// ENOKEY = not in ring (this is the "not enrolled yet" case).
		if errors.Is(err, unix.ENOKEY) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// First call with nil buffer returns the required size; second
	// call with the right-sized buffer reads the payload.
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if _, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0); err != nil {
		return nil, err
	}
	return buf, nil
}
