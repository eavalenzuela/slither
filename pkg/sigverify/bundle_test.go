package sigverify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTarGz writes a tar.gz to dst with the given files. paths are
// in-tar names; bodies are the raw bytes for each entry. typeflag
// is applied to every file (TypeReg by default).
func makeTarGz(t *testing.T, dst string, files map[string]string, typeflag byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(body)),
			Typeflag: typeflag,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func TestExtractBundle_HappyPath(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "rules.tgz")
	makeTarGz(t, bundle, map[string]string{
		"01-process/reverse-shell.yml": "title: Reverse shell\nid: rule-1\n",
		"02-files/history-clear.yml":   "title: History clear\nid: rule-2\n",
		"README.md":                    "this gets ignored",
	}, tar.TypeReg)

	entries, err := ExtractBundle(bundle)
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want 2 (README.md should be filtered)", len(entries))
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Path, ".yml") {
			t.Errorf("non-YAML entry survived: %q", e.Path)
		}
	}
}

func TestExtractBundle_EmptyBundleRejected(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "empty.tgz")
	makeTarGz(t, bundle, map[string]string{
		"README.md": "no YAML here",
	}, tar.TypeReg)
	_, err := ExtractBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "no YAML") {
		t.Errorf("empty-of-YAML bundle should be rejected; got %v", err)
	}
}

func TestExtractBundle_PathTraversalRefused(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "evil.tgz")
	makeTarGz(t, bundle, map[string]string{
		"../etc/passwd.yml": "id: pwn",
	}, tar.TypeReg)
	_, err := ExtractBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "escapes root") {
		t.Errorf("path-traversal entry should be refused; got %v", err)
	}
}

func TestExtractBundle_AbsolutePathRefused(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "abs.tgz")
	makeTarGz(t, bundle, map[string]string{
		"/etc/passwd.yml": "id: pwn",
	}, tar.TypeReg)
	_, err := ExtractBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "escapes root") {
		t.Errorf("absolute-path entry should be refused; got %v", err)
	}
}

func TestExtractBundle_SymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "sym.tgz")
	// Manually craft because makeTarGz doesn't set linkname.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "evil.yml", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}
	_ = tw.WriteHeader(hdr)
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(bundle, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ExtractBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink entry should be refused; got %v", err)
	}
}

func TestExtractBundle_PreservesByteContent(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "rules.tgz")
	body := "title: round-trip\nid: rt\nlevel: high\n"
	makeTarGz(t, bundle, map[string]string{
		"x.yml": body,
	}, tar.TypeReg)
	entries, err := ExtractBundle(bundle)
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if string(entries[0].Bytes) != body {
		t.Errorf("body diverged: got %q want %q", entries[0].Bytes, body)
	}
}

func TestExtractBundle_BadGzip(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bad.tgz")
	if err := os.WriteFile(bundle, []byte("not gzipped"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ExtractBundle(bundle)
	if err == nil || !strings.Contains(err.Error(), "gunzip") {
		t.Errorf("non-gzip bundle should fail at gunzip; got %v", err)
	}
}

func TestVerifyAndExtractBundle_VerifyFirstThenExtract(t *testing.T) {
	// Verify failure must short-circuit before any tar reading. Use a
	// fake cosign that always exits non-zero with a policy-mismatch
	// signature; the bundle file content is irrelevant because
	// extraction shouldn't run.
	dir := t.TempDir()
	fake := filepath.Join(dir, "cosign")
	script := `#!/usr/bin/env bash
echo "no matching signatures" >&2
exit 1
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake: %v", err)
	}
	bundle := filepath.Join(dir, "rules.tgz")
	makeTarGz(t, bundle, map[string]string{"x.yml": "id: rt"}, tar.TypeReg)
	sig, cert := SidecarPaths(bundle)
	_ = os.WriteFile(sig, nil, 0o644)
	_ = os.WriteFile(cert, nil, 0o644)

	_, err := VerifyAndExtractBundle(t.Context(), bundle, Options{CosignBinary: fake})
	if err == nil {
		t.Fatal("expected refusal")
	}
}
