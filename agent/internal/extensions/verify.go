package extensions

import (
	"context"
	"errors"

	"github.com/t3rmit3/slither/pkg/sigverify"
)

// SignatureVerifier verifies an extension binary before spawn. The
// agent invokes Verify at spawn-time and refuses to launch if Verify
// returns a non-nil error. Implementations are expected to be
// fail-closed — any operational issue (cosign missing, sigstore
// unavailable, malformed sidecar) reports as an error rather than
// silently passing.
type SignatureVerifier interface {
	// Verify returns nil iff the binary at binaryPath has a valid
	// signature under this verifier's policy. Returns ErrSignatureRefused
	// (wrapped) when the verify itself ran cleanly but rejected; other
	// errors signal infrastructure failures.
	Verify(ctx context.Context, binaryPath string) error
}

// ErrSignatureRefused indicates the signature was checked and rejected.
// Callers can errors.Is on it to distinguish "wrong signature" from
// "couldn't even attempt verify". Aliased onto pkg/sigverify's sentinel
// (Phase 6 #108) so both consumers (this supervisor + slither-db
// rule-bundle import) report the same failure mode.
var ErrSignatureRefused = sigverify.ErrSignatureRefused

// CosignVerifier delegates to pkg/sigverify (ADR-0039) for the
// cosign-keyless verify-blob check. The slither release pipeline
// (Phase 5 #91) signs with the same toolchain, producing detached
// .sig + .pem sidecars alongside each binary; this verifier consumes
// them.
type CosignVerifier struct {
	// IdentityRegexp pins the certificate-identity claim — the URL
	// of the workflow that produced the binary. Empty falls back to
	// pkg/sigverify.DefaultIdentityRegexp (the slither release pipeline).
	IdentityRegexp string

	// OIDCIssuer pins the issuer claim. Empty falls back to
	// pkg/sigverify.DefaultOIDCIssuer.
	OIDCIssuer string

	// SignaturePath + CertificatePath point at the detached .sig + .pem
	// produced by `cosign sign-blob`. When empty, the verifier looks
	// for {binaryPath}.sig + {binaryPath}.pem alongside the binary.
	SignaturePath   string
	CertificatePath string

	// CosignBinary lets tests override the cosign executable. Empty
	// resolves "cosign" via PATH.
	CosignBinary string
}

// Verify delegates to pkg/sigverify.VerifyBlob, with sidecar paths
// resolved per ADR-0039's "alongside the artefact" convention when
// SignaturePath / CertificatePath are empty.
func (v *CosignVerifier) Verify(ctx context.Context, binaryPath string) error {
	sig := v.SignaturePath
	cert := v.CertificatePath
	if sig == "" || cert == "" {
		defSig, defCert := sigverify.SidecarPaths(binaryPath)
		if sig == "" {
			sig = defSig
		}
		if cert == "" {
			cert = defCert
		}
	}
	err := sigverify.VerifyBlob(ctx, binaryPath, sig, cert, sigverify.Options{
		IdentityRegexp: v.IdentityRegexp,
		OIDCIssuer:     v.OIDCIssuer,
		CosignBinary:   v.CosignBinary,
	})
	if err != nil {
		// Surface ErrCosignMissing as the supervisor's "couldn't even
		// attempt verify" path so operators see "extensions: cosign
		// verifier requires cosign on PATH" rather than the package-
		// internal sentinel name.
		if errors.Is(err, sigverify.ErrCosignMissing) {
			return err
		}
		return err
	}
	return nil
}

// DisabledVerifier is a no-op SignatureVerifier for dev/CI. Production
// deployments must not select this — config validation rejects empty
// signature_verification, and the disabled value is documented as
// dev-only in `docs/install.md`.
type DisabledVerifier struct{}

// Verify always returns nil — explicit operator opt-in via
// `signature_verification: disabled`.
func (DisabledVerifier) Verify(_ context.Context, _ string) error { return nil }
