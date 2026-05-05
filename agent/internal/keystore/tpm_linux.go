//go:build linux

// Phase 6 #118 — TPM-sealed cert variant.
//
// Ships behind `agent.keystore.tpm: true`. When opted in + the
// platform satisfies the probe (a) `/dev/tpmrm0` exists and is
// openable, (b) PCR 7 is readable, AutoSelect returns the TPM
// store; otherwise the chain falls through to keyring → file.
//
// Sealing recipe:
//
//   1. Build a TPM2 ECC primary key under the Endorsement hierarchy
//      (TPM2_CreatePrimary). This is the parent the sealed data
//      blob descends from. Re-derived deterministically on every
//      Save / Load — no on-disk parent persistence.
//   2. Compose a PCR policy hash binding the sealed blob to the
//      boot-time value of PCR 7 (Secure Boot policy). A host that
//      re-boots un-Secure-Boot — or one that updates its kernel
//      and changes the PCR 7 measurement — fails the unseal at
//      step 5 with a TPM_RC_POLICY_FAIL we surface as a clear
//      "TPM: PCR 7 mismatch" log line so operators know to
//      re-enroll.
//   3. TPM2_Create produces the sealed-data outerHandle/innerBlob.
//      We persist (public, private, policyDigest) to the agent's
//      state dir at <stateDir>/tpm_sealed.bin. The blob is not a
//      secret — the TPM holds the seed; an attacker with the file
//      can't unseal without satisfying the PCR policy.
//   4. On Load: re-derive the primary, TPM2_Load the sealed object
//      under it, open a TPM2_StartAuthSession with PolicyPCR
//      against current PCR 7 state, TPM2_Unseal the data.
//   5. The sealed payload itself is the JSON-encoded Material
//      (client.key + client.crt + ca.crt). Unseal returns the same
//      bytes Save received.
//
// Failure modes:
//   - /dev/tpmrm0 missing → AutoSelect falls back; logged once.
//   - PCR 7 changed since seal → Unseal fails with a policy error;
//     Load returns ErrNotFound so the agent re-enrols; logged
//     with a "tpm: PCR 7 mismatch (kernel/Secure-Boot change?)" hint.
//   - TPM busy → bubbles up the underlying error; the agent's
//     enrol path retries on next start.

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	linuxtpm "github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// openTPM is the Linux-specific transport opener. linuxtpm.Open
// supersedes the deprecated transport.OpenTPM (SA1019) for Linux
// resource-manager devices.
func openTPM() (transport.TPMCloser, error) {
	return linuxtpm.Open(tpmDevice)
}

// tpmDevice is the kernel resource manager path. /dev/tpm0 is the
// raw device; /dev/tpmrm0 multiplexes context across processes —
// always prefer the rm path.
const tpmDevice = "/dev/tpmrm0"

// sealedBlobName is the file within stateDir that holds the
// (public, private, policyDigest) tuple. The on-disk format is JSON
// for forward compat — adding a Phase 7 field never requires a
// migration script.
const sealedBlobName = "tpm_sealed.bin"

// pcrIndex7 is the Secure Boot policy PCR. Phase 6 #118 binds the
// sealed blob to this index alone — a host that boots
// un-Secure-Boot can't unseal. Phase 7 may extend this to a
// composite (e.g. PCR 0 + PCR 7) for measured-boot-aware deployments;
// the current single-PCR shape covers the dominant
// Secure-Boot-on use case without expanding the configuration
// matrix.
var pcrIndex7 = []uint{7}

// tpmStore is the Phase 6 #118 sealed-cert store.
type tpmStore struct {
	stateDir string
}

// tryTPM probes the platform: opens /dev/tpmrm0 + reads PCR 7. The
// returned Store can Save / Load via the resource-manager device.
// Errors fold into AutoSelect's fallback chain, NOT the agent boot
// path — a missing TPM degrades to keyring + file gracefully.
func tryTPM(stateDir string) (Store, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("keystore.tryTPM: stateDir required")
	}
	tpm, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("keystore.tryTPM: open %s: %w", tpmDevice, err)
	}
	defer tpm.Close()
	// PCR 7 readable? Hash mismatch on tpm2.PCRRead's response is a
	// hard error from the kernel driver, so a successful return
	// means the driver + the TPM agree on PCR 7's current value.
	if _, err := pcrSelectionRead(tpm); err != nil {
		return nil, fmt.Errorf("keystore.tryTPM: pcr 7 read: %w", err)
	}
	return &tpmStore{stateDir: stateDir}, nil
}

// Name implements Store.
func (t *tpmStore) Name() string { return "tpm" }

// Save seals m against the current PCR 7 value and writes the
// sealed blob to <stateDir>/tpm_sealed.bin. Replacing the blob is
// atomic from a reader's perspective via os.Rename.
func (t *tpmStore) Save(m Material) error {
	if err := m.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(m) //nolint:gosec // G117 false positive — Material is sealed by the TPM before write
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: marshal: %w", err)
	}

	tpm, err := openTPM()
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: open: %w", err)
	}
	defer tpm.Close()

	primary, err := createPrimary(tpm)
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: primary: %w", err)
	}
	defer flush(tpm, primary.ObjectHandle)

	policyDigest, err := computePCRPolicyDigest(tpm)
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: policy: %w", err)
	}

	createCmd := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: payload,
				}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:        true,
				FixedParent:     true,
				NoDA:            true,
				UserWithAuth:    false,
				AdminWithPolicy: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: policyDigest},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgNull,
					},
				}),
		}),
	}
	createResp, err := createCmd.Execute(tpm)
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: create: %w", err)
	}

	blob := sealedBlob{
		PublicArea:   createResp.OutPublic.Bytes(),
		PrivateArea:  createResp.OutPrivate.Buffer,
		PolicyDigest: policyDigest,
	}
	out, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: encode blob: %w", err)
	}
	if err := os.MkdirAll(t.stateDir, 0o700); err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: mkdir: %w", err)
	}
	dst := filepath.Join(t.stateDir, sealedBlobName)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil { //nolint:gosec // 0600 is correct
		return fmt.Errorf("keystore.tpmStore.Save: write tmp: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("keystore.tpmStore.Save: rename: %w", err)
	}
	return nil
}

// Load reads the sealed blob, satisfies the PolicyPCR session
// against current PCR 7, and unseals. Returns ErrNotFound when the
// blob doesn't exist (no prior Save) or when the unseal fails the
// policy check (PCR 7 mismatch — host's Secure Boot state changed
// since seal). The PCR-mismatch case is logged via the caller's
// slog facade since this package stays log-free; the operator
// recovers by re-running `slither-agent enroll`.
func (t *tpmStore) Load() (Material, error) {
	src := filepath.Join(t.stateDir, sealedBlobName)
	raw, err := os.ReadFile(src) //nolint:gosec // operator-controlled state dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Material{}, ErrNotFound
		}
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: read blob: %w", err)
	}
	var blob sealedBlob
	if uerr := json.Unmarshal(raw, &blob); uerr != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: decode: %w", uerr)
	}

	tpm, err := openTPM()
	if err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: open: %w", err)
	}
	defer tpm.Close()

	primary, err := createPrimary(tpm)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: primary: %w", err)
	}
	defer flush(tpm, primary.ObjectHandle)

	pubBytes, err := tpm2.Unmarshal[tpm2.TPM2BPublic](blob.PublicArea)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: unmarshal public: %w", err)
	}
	loadCmd := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: blob.PrivateArea},
		InPublic:  *pubBytes,
	}
	loadResp, err := loadCmd.Execute(tpm)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: load: %w", err)
	}
	defer flush(tpm, loadResp.ObjectHandle)

	// Real policy session — no Trial() opt; we satisfy the live PCR
	// state and feed it as the auth for Unseal.
	realSession, realClose, err := tpm2.PolicySession(tpm,
		tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: policy session: %w", err)
	}
	defer realClose() //nolint:errcheck // best-effort session cleanup; failure here doesn't change Load's outcome

	if _, perr := (tpm2.PolicyPCR{
		PolicySession: realSession.Handle(),
		Pcrs:          pcrSelectionForIndex(pcrIndex7...),
	}).Execute(tpm); perr != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: policypcr: %w", perr)
	}

	unsealResp, err := (tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   realSession,
		},
	}).Execute(tpm)
	if err != nil {
		// Most common failure: PCR 7 changed since seal. Surface a
		// distinct error wrapping ErrNotFound so AutoSelect's caller
		// treats it as "no prior material" and triggers a re-enroll
		// rather than retrying with a stale blob.
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: unseal (%w): %w", ErrNotFound, err)
	}

	var m Material
	if err := json.Unmarshal(unsealResp.OutData.Buffer, &m); err != nil {
		return Material{}, fmt.Errorf("keystore.tpmStore.Load: decode payload: %w", err)
	}
	return m, nil
}

// sealedBlob is the on-disk JSON shape of the sealed material. The
// public + private areas are TPM2-canonical bytes the Load path
// hands back to the TPM verbatim. policyDigest is recorded only for
// debug — Load recomputes the policy from current PCR state, so a
// blob written at seal-time PCR matches the live policy iff PCR 7
// hasn't changed.
type sealedBlob struct {
	PublicArea   []byte `json:"public_area"`
	PrivateArea  []byte `json:"private_area"`
	PolicyDigest []byte `json:"policy_digest"`
}

// createPrimary derives the SRK-shaped ECC primary key under the
// Endorsement hierarchy. Re-derived on every call — go-tpm caches
// nothing across processes; the parent is shape-deterministic so
// every call returns the same key under the same TPM.
func createPrimary(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	return cmd.Execute(tpm)
}

// flush is a best-effort handle cleanup. TPM resource exhaustion is
// the realistic failure mode — every Save / Load opens a new
// device handle, and the resource-manager device collapses
// transient handles on close, but flushing explicitly keeps the
// handle slot free for the next caller.
//
// The flushHandle interface lets callers pass either a TPMHandle
// (CreatePrimary's ObjectHandle is uint32-shaped) or a TPMI* alias
// the load path returns; both implement KnownName via go-tpm's
// internal handle interface.
func flush(tpm transport.TPM, h interface {
	HandleValue() uint32
	KnownName() *tpm2.TPM2BName
}) {
	_, _ = (tpm2.FlushContext{FlushHandle: h}).Execute(tpm)
}

// pcrSelectionForIndex builds the TPMLPCRSelection one-PCR
// selection list go-tpm's PolicyPCR + PCRRead expect.
func pcrSelectionForIndex(idx ...uint) tpm2.TPMLPCRSelection {
	bits := make([]byte, 3) // 24-PCR-wide bitmask covers PCR 0..23
	for _, i := range idx {
		if i >= 24 {
			continue
		}
		bits[i/8] |= 1 << (i % 8)
	}
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      tpm2.TPMAlgSHA256,
			PCRSelect: bits,
		}},
	}
}

// pcrSelectionRead reads PCR 7 to confirm the TPM is responsive +
// the kernel driver agrees on the current value. Used by tryTPM as
// the platform probe.
func pcrSelectionRead(tpm transport.TPM) ([]byte, error) {
	resp, err := (tpm2.PCRRead{
		PCRSelectionIn: pcrSelectionForIndex(pcrIndex7...),
	}).Execute(tpm)
	if err != nil {
		return nil, err
	}
	if len(resp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("pcr 7 returned zero digests")
	}
	return resp.PCRValues.Digests[0].Buffer, nil
}

// computePCRPolicyDigest builds the policy digest the seal commits
// to. The Trial session computes the same digest the live policy
// session will produce at unseal time, given the current PCR 7
// value. Storing only the digest (not the PCR value) keeps the
// blob's privacy model intact — an offline attacker can't read
// the PCR target out of the file.
func computePCRPolicyDigest(tpm transport.TPM) ([]byte, error) {
	session, closer, err := tpm2.PolicySession(tpm,
		tpm2.TPMAlgSHA256, 16,
		tpm2.Trial())
	if err != nil {
		return nil, fmt.Errorf("trial session: %w", err)
	}
	defer closer() //nolint:errcheck // best-effort trial-session cleanup; the digest is already returned

	if _, perr := (tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		Pcrs:          pcrSelectionForIndex(pcrIndex7...),
	}).Execute(tpm); perr != nil {
		return nil, fmt.Errorf("policypcr: %w", perr)
	}
	digest, err := (tpm2.PolicyGetDigest{
		PolicySession: session.Handle(),
	}).Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("policygetdigest: %w", err)
	}
	return digest.PolicyDigest.Buffer, nil
}
