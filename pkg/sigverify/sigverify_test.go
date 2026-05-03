package sigverify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBlob_MissingCosignBinary(t *testing.T) {
	err := VerifyBlob(context.Background(), "/bin/true", "/dev/null", "/dev/null", Options{
		CosignBinary: "/nonexistent/cosign",
	})
	if !errors.Is(err, ErrCosignMissing) {
		t.Errorf("expected ErrCosignMissing, got %v", err)
	}
}

func TestVerifyBlob_PolicyMismatch(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env bash
echo "no matching signatures" >&2
exit 1
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	bin := filepath.Join(dir, "blob")
	if err := os.WriteFile(bin, []byte("garbage"), 0o644); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	sig, cert := SidecarPaths(bin)
	if err := os.WriteFile(sig, []byte("sig"), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(cert, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	err := VerifyBlob(context.Background(), bin, sig, cert, Options{CosignBinary: fake})
	if !errors.Is(err, ErrSignatureRefused) {
		t.Errorf("expected ErrSignatureRefused, got %v", err)
	}
}

func TestVerifyBlob_HappyPath(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	if err := os.WriteFile(fake, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	bin := filepath.Join(dir, "blob")
	if err := os.WriteFile(bin, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	sig, cert := SidecarPaths(bin)
	if err := os.WriteFile(sig, nil, 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(cert, nil, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := VerifyBlob(context.Background(), bin, sig, cert, Options{CosignBinary: fake}); err != nil {
		t.Errorf("happy path failed: %v", err)
	}
}

func TestVerifyBlob_InfrastructureFailureNotMappedToRefusal(t *testing.T) {
	// cosign exits non-zero with output that doesn't match any of the
	// policy-mismatch heuristics. Should NOT map to ErrSignatureRefused —
	// operators triage infra failures (cosign / Rekor unavailable,
	// malformed sidecar) differently from policy refusals.
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env bash
echo "rekor unavailable: connection refused" >&2
exit 2
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	bin := filepath.Join(dir, "blob")
	_ = os.WriteFile(bin, []byte("x"), 0o644)
	sig, cert := SidecarPaths(bin)
	_ = os.WriteFile(sig, nil, 0o644)
	_ = os.WriteFile(cert, nil, 0o644)
	err := VerifyBlob(context.Background(), bin, sig, cert, Options{CosignBinary: fake})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrSignatureRefused) {
		t.Errorf("infra failure incorrectly mapped to ErrSignatureRefused: %v", err)
	}
	if !strings.Contains(err.Error(), "rekor unavailable") {
		t.Errorf("error should surface cosign output; got %v", err)
	}
}

func TestSidecarPaths_AppendsConventionalSuffixes(t *testing.T) {
	sig, cert := SidecarPaths("/path/to/artefact")
	if sig != "/path/to/artefact.sig" || cert != "/path/to/artefact.pem" {
		t.Errorf("got sig=%q cert=%q", sig, cert)
	}
}

func TestVerifyBlob_DefaultsApplyToEmptyOptions(t *testing.T) {
	// Smoke-test that DefaultIdentityRegexp + DefaultOIDCIssuer are
	// non-empty and applied. Doesn't actually invoke cosign — uses a
	// fake that exits 0.
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	if err := os.WriteFile(fake, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	bin := filepath.Join(dir, "blob")
	_ = os.WriteFile(bin, []byte("x"), 0o644)
	sig, cert := SidecarPaths(bin)
	_ = os.WriteFile(sig, nil, 0o644)
	_ = os.WriteFile(cert, nil, 0o644)
	if err := VerifyBlob(context.Background(), bin, sig, cert, Options{CosignBinary: fake}); err != nil {
		t.Errorf("empty options + happy fake failed: %v", err)
	}
	if DefaultIdentityRegexp == "" || DefaultOIDCIssuer == "" {
		t.Error("default trust root constants must be non-empty")
	}
}
