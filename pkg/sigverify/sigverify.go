// Package sigverify is the shared cosign-keyless verification helper
// for both the agent's extension supervisor (Phase 6 #107) and the
// server's slither-db rule-bundle import path (Phase 6 #108). One
// cosign-shell implementation, one set of error semantics, one set
// of fail-closed guarantees — see ADR-0039 for the trust-root +
// keyless-OIDC rationale.
package sigverify

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Default trust root — the slither release pipeline. Overridable
// by operators with downstream forks via the per-call Options.
const (
	DefaultIdentityRegexp = `^https://github\.com/t3rmit3/slither/\.github/workflows/release\.yml@refs/tags/v.*$`
	DefaultOIDCIssuer     = "https://token.actions.githubusercontent.com"
)

// ErrSignatureRefused is returned when cosign ran cleanly but the
// policy did not match — wrong identity, wrong issuer, no signature,
// expired cert. Distinguishable from infrastructure failures via
// errors.Is so callers can render the right operator message.
var ErrSignatureRefused = errors.New("sigverify: signature refused")

// ErrCosignMissing is returned when the cosign binary cannot be
// resolved on PATH. Callers can errors.Is to distinguish "we
// couldn't even attempt verification" from "verification ran and
// rejected" — operators triage these differently.
var ErrCosignMissing = errors.New("sigverify: cosign binary not on PATH")

// Options bundles the keyless trust-root pins. Zero values fall back
// to ADR-0039 defaults so callers in the common case (verifying
// slither-shipped artefacts) construct an empty Options.
type Options struct {
	// IdentityRegexp pins the certificate-identity claim — the URL
	// of the workflow that produced the artefact.
	IdentityRegexp string

	// OIDCIssuer pins the issuer claim. Defaults to GitHub Actions.
	OIDCIssuer string

	// CosignBinary lets tests + downstream operators override the
	// cosign executable. Empty resolves "cosign" via PATH.
	CosignBinary string
}

// VerifyBlob shells out to `cosign verify-blob` against the artefact
// at artefactPath, with detached signature at sigPath and certificate
// at certPath. Returns nil on success; ErrSignatureRefused (wrapped)
// on policy mismatch; ErrCosignMissing (wrapped) when cosign is
// unavailable; a generic infrastructure error for any other failure.
func VerifyBlob(ctx context.Context, artefactPath, sigPath, certPath string, opts Options) error {
	bin := opts.CosignBinary
	if bin == "" {
		bin = "cosign"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCosignMissing, bin, err)
	}
	identity := opts.IdentityRegexp
	if identity == "" {
		identity = DefaultIdentityRegexp
	}
	issuer := opts.OIDCIssuer
	if issuer == "" {
		issuer = DefaultOIDCIssuer
	}

	args := []string{
		"verify-blob",
		"--certificate-identity-regexp", identity,
		"--certificate-oidc-issuer", issuer,
		"--signature", sigPath,
		"--certificate", certPath,
		artefactPath,
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// cosign exits non-zero on policy mismatch and on missing /
		// malformed inputs. Disambiguate via the textual output;
		// policy mismatch maps to ErrSignatureRefused so callers can
		// render "this artefact's signature did not match the trust
		// root" rather than the cosign internals.
		text := strings.ToLower(string(out))
		if strings.Contains(text, "no matching signatures") ||
			strings.Contains(text, "certificate identity") ||
			strings.Contains(text, "certificate-identity") ||
			strings.Contains(text, "issuer") {
			return fmt.Errorf("%w: %s: %s", ErrSignatureRefused, artefactPath, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("sigverify: cosign verify-blob %s: %w: %s", artefactPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SidecarPaths returns the conventional `.sig` and `.pem` paths for
// an artefact path. Operators typically drop the sidecars alongside
// the binary or bundle they sign, so the agent + slither-db can
// resolve them automatically without per-invocation flags.
func SidecarPaths(artefactPath string) (sig, cert string) {
	return artefactPath + ".sig", artefactPath + ".pem"
}
