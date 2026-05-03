package extensions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisabledVerifier_AlwaysOK(t *testing.T) {
	if err := (DisabledVerifier{}).Verify(context.Background(), "/nonexistent"); err != nil {
		t.Errorf("DisabledVerifier returned %v", err)
	}
}

func TestCosignVerifier_MissingCosignBinary(t *testing.T) {
	v := &CosignVerifier{
		IdentityRegexp: ".*",
		OIDCIssuer:     "https://example",
		CosignBinary:   "/nonexistent/cosign",
	}
	err := v.Verify(context.Background(), "/bin/true")
	if err == nil {
		t.Fatal("expected error when cosign binary missing")
	}
	if !strings.Contains(err.Error(), "cosign verifier requires") {
		t.Errorf("error should mention missing cosign; got %v", err)
	}
}

func TestCosignVerifier_PolicyMismatchSurfacesAsRefused(t *testing.T) {
	// Build a fake cosign script that simulates the policy-mismatch
	// path: exit non-zero with the magic substring "no matching
	// signatures". Any other failure shape would be classified as
	// an infrastructure error rather than a refusal.
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env bash
echo "no matching signatures" >&2
exit 1
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	bin := filepath.Join(dir, "binary")
	if err := os.WriteFile(bin, []byte("garbage"), 0o755); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}
	if err := os.WriteFile(bin+".sig", []byte("sig"), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(bin+".pem", []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	v := &CosignVerifier{
		IdentityRegexp: ".*",
		OIDCIssuer:     "https://example",
		CosignBinary:   fake,
	}
	err := v.Verify(context.Background(), bin)
	if !errors.Is(err, ErrSignatureRefused) {
		t.Errorf("policy mismatch should map to ErrSignatureRefused; got %v", err)
	}
}

func TestCosignVerifier_HappyPath(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env bash
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cosign: %v", err)
	}
	bin := filepath.Join(dir, "binary")
	if err := os.WriteFile(bin, []byte("ok"), 0o755); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}
	if err := os.WriteFile(bin+".sig", []byte("sig"), 0o644); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(bin+".pem", []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	v := &CosignVerifier{
		IdentityRegexp: ".*",
		OIDCIssuer:     "https://example",
		CosignBinary:   fake,
	}
	if err := v.Verify(context.Background(), bin); err != nil {
		t.Errorf("happy path should pass; got %v", err)
	}
}
