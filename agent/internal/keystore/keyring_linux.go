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
// session keyring (@s) — survives the entire login/service session,
// which for a systemd-managed agent unit means the lifetime of the
// agent process tree.
//
// Why @s and not @u? @u (user keyring) leaks across other tools
// running as the same UID, which could include unrelated background
// services on a multi-tenant host. @s scopes to the agent's session
// (its own systemd unit gets its own session keyring on RHEL/Debian
// 12+ via PAM's pam_keyinit + KeepCaps=true). Operators wanting
// reboot-survivable storage use the File store explicitly — Phase
// 5 #98's keyring path is for runtime confidentiality, not durability.
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

// keyringID returns the session keyring's ID. Falls back to the user
// keyring when the session keyring isn't available (rare, but some
// container shapes detach @s on namespace setup).
func keyringID() (int, error) {
	if id, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true); err == nil {
		return id, nil
	}
	if id, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true); err == nil {
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
