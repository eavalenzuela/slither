package extensions

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
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
// "couldn't even attempt verify".
var ErrSignatureRefused = errors.New("extensions: signature refused")

// CosignVerifier shells out to the `cosign` CLI to perform a keyless
// verify-blob check. The slither release pipeline (Phase 5 #91) signs
// with the same toolchain, producing detached .sig + .pem sidecars
// alongside each binary; this verifier consumes them.
//
// Why shell out rather than vendor the in-process API: github.com/
// sigstore/cosign/v2 pulls in ~150 transitive deps, including a chunk
// of the kubernetes API surface. Verify-on-spawn happens once per
// supervisor restart cycle (long-lived extension processes); the cost
// of forking cosign is negligible compared to the dependency footprint
// of vendoring it.
type CosignVerifier struct {
	// IdentityRegexp pinned the certificate-identity claim — the URL
	// of the workflow that produced the binary. Operators with their
	// own signing pipeline override this to their own workflow URL.
	IdentityRegexp string

	// OIDCIssuer pins the issuer claim. Defaults to GitHub Actions
	// for the keyless flow Slither's release pipeline uses.
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

// Verify runs `cosign verify-blob`, mapping its outcomes onto the
// SignatureVerifier contract.
func (v *CosignVerifier) Verify(ctx context.Context, binaryPath string) error {
	bin := v.CosignBinary
	if bin == "" {
		bin = "cosign"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("extensions: cosign verifier requires %q on PATH: %w", bin, err)
	}

	sig := v.SignaturePath
	if sig == "" {
		sig = binaryPath + ".sig"
	}
	cert := v.CertificatePath
	if cert == "" {
		cert = binaryPath + ".pem"
	}

	args := []string{
		"verify-blob",
		"--certificate-identity-regexp", v.IdentityRegexp,
		"--certificate-oidc-issuer", v.OIDCIssuer,
		"--signature", sig,
		"--certificate", cert,
		binaryPath,
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// cosign exits non-zero on policy mismatch and on missing
		// files; the textual output disambiguates. Map the policy
		// failure cleanly so callers can distinguish.
		text := strings.ToLower(string(out))
		if strings.Contains(text, "no matching signatures") ||
			strings.Contains(text, "certificate identity") ||
			strings.Contains(text, "certificate-identity") ||
			strings.Contains(text, "issuer") {
			return fmt.Errorf("%w: %s: %s", ErrSignatureRefused, binaryPath, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("extensions: cosign verify-blob %s: %w: %s", binaryPath, err, strings.TrimSpace(string(out)))
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
