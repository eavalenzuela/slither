//go:build linux

package respond

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// withTempQuarantineRoot redirects the package-level quarantineRoot
// at a tempdir for the duration of the test. Quarantine writes are
// unguarded against the operator's actual /var/lib/slither/quarantine
// dir, which the test must not pollute.
func withTempQuarantineRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := quarantineRoot
	quarantineRoot = dir
	t.Cleanup(func() { quarantineRoot = prev })
	return dir
}

func TestRefuseQuarantinePath_Blacklist(t *testing.T) {
	t.Parallel()
	for _, p := range []string{
		"/proc/cpuinfo",
		"/sys/kernel/btf/vmlinux",
		"/dev/null",
		"/run/systemd/units/foo.service",
		"/var/lib/slither/host_id",
		"/var/lib/slither/quarantine/somefile",
		"/usr/local/bin/slither-agent",
	} {
		if err := refuseQuarantinePath(p); err == nil {
			t.Errorf("refuseQuarantinePath(%q) = nil, want refusal", p)
		}
	}
}

func TestRefuseQuarantinePath_Allows(t *testing.T) {
	t.Parallel()
	// Lookalike that is NOT under the blacklist.
	for _, p := range []string{
		"/tmp/x.bin",
		"/home/admin/payload",
		"/var/lib/slither-thing/x", // distinct from /var/lib/slither/
	} {
		if err := refuseQuarantinePath(p); err != nil {
			t.Errorf("refuseQuarantinePath(%q) = %v, want nil", p, err)
		}
	}
}

func TestRefuseQuarantinePath_RejectsNonAbsolute(t *testing.T) {
	t.Parallel()
	if err := refuseQuarantinePath("relative/path"); err == nil {
		t.Fatal("relative path should be refused")
	}
}

func TestQuarantineHandler_HappyPath(t *testing.T) {
	stagingRoot := withTempQuarantineRoot(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "evil.bin")
	want := []byte("phase4-quarantine-test-bytes")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "11111111-1111-1111-1111-111111111111",
		Target:    target,
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("status = %s, detail = %q, want DONE", status, detail)
	}

	// Original gone.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("target still exists after quarantine: err = %v", err)
	}
	// Staging contents byte-equal.
	staged := filepath.Join(stagingRoot, "11111111-1111-1111-1111-111111111111", "contents")
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("staged contents = %x, want %x", got, want)
	}
	// Manifest readable + sha256 matches.
	manifest, err := readManifest(filepath.Join(stagingRoot, "11111111-1111-1111-1111-111111111111"))
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if manifest.OriginalPath != target {
		t.Errorf("manifest.OriginalPath = %q, want %q", manifest.OriginalPath, target)
	}
	wantHash := sha256.Sum256(want)
	if manifest.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Errorf("manifest.SHA256 = %q, want %q", manifest.SHA256, hex.EncodeToString(wantHash[:]))
	}
	if manifest.OriginalSize != int64(len(want)) {
		t.Errorf("manifest.OriginalSize = %d, want %d", manifest.OriginalSize, len(want))
	}
}

func TestQuarantineHandler_RefusesBlacklistedTarget(t *testing.T) {
	withTempQuarantineRoot(t)
	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "22222222-2222-2222-2222-222222222222",
		Target:    "/proc/cpuinfo",
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "/proc/") {
		t.Errorf("detail = %q, want /proc refusal", detail)
	}
}

func TestQuarantineHandler_MissingTargetFails(t *testing.T) {
	withTempQuarantineRoot(t)
	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "33333333-3333-3333-3333-333333333333",
		Target:    "/tmp/this-file-does-not-exist-phase4",
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if detail == "" {
		t.Error("detail empty on missing target")
	}
}

func TestQuarantineHandler_BlankTargetFails(t *testing.T) {
	withTempQuarantineRoot(t)
	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "44444444-4444-4444-4444-444444444444",
		Target:    "  ",
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "required") {
		t.Errorf("detail = %q, want 'required'", detail)
	}
}

func TestQuarantineHandler_RequiresControlID(t *testing.T) {
	withTempQuarantineRoot(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "x")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "",
		Target:    target,
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "control_id") {
		t.Errorf("detail = %q, want control_id refusal", detail)
	}
}

func TestRestoreFromQuarantine_RoundTrip(t *testing.T) {
	withTempQuarantineRoot(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "round-trip.bin")
	want := []byte("a-quarantine-then-restore-payload")
	if err := os.WriteFile(target, want, 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}

	h := QuarantineFileHandler()
	if s, _, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "55555555-5555-5555-5555-555555555555",
		Target:    target,
	}); s != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("quarantine status = %s, want DONE", s)
	}

	if err := RestoreFromQuarantine("55555555-5555-5555-5555-555555555555"); err != nil {
		t.Fatalf("RestoreFromQuarantine: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("restored bytes = %x, want %x", got, want)
	}
	// Staging dir should be cleaned up after a successful restore.
	if _, err := os.Stat(filepath.Join(quarantineRoot, "55555555-5555-5555-5555-555555555555")); !os.IsNotExist(err) {
		t.Errorf("staging dir still present after restore: err = %v", err)
	}
}

func TestRestoreFromQuarantine_RefusesOverwrite(t *testing.T) {
	withTempQuarantineRoot(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := QuarantineFileHandler()
	if s, _, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "66666666-6666-6666-6666-666666666666",
		Target:    target,
	}); s != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("quarantine: status = %s", s)
	}

	// Operator (or attacker) re-creates the file before reversal.
	if err := os.WriteFile(target, []byte("squatter"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := RestoreFromQuarantine("66666666-6666-6666-6666-666666666666")
	if err == nil {
		t.Fatal("Restore over existing file should refuse")
	}
	if !strings.Contains(err.Error(), "existing file") {
		t.Errorf("err = %v, want 'existing file' refusal", err)
	}
}

func TestRestoreFromQuarantine_DetectsTamperedContents(t *testing.T) {
	withTempQuarantineRoot(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(target, []byte("trusted-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := QuarantineFileHandler()
	if s, _, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: "77777777-7777-7777-7777-777777777777",
		Target:    target,
	}); s != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("quarantine: status = %s", s)
	}
	staged := filepath.Join(quarantineRoot, "77777777-7777-7777-7777-777777777777", "contents")
	if err := os.WriteFile(staged, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RestoreFromQuarantine("77777777-7777-7777-7777-777777777777")
	if err == nil {
		t.Fatal("Restore should refuse tampered staging contents")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("err = %v, want sha256 mismatch", err)
	}
}

// Phase 4 #85: handler dispatches to RestoreFromQuarantine when
// ResponseRequest.parent_action_id is set. End-to-end: quarantine →
// reversal request with parent_id → file is byte-equal at original path.
func TestQuarantineHandler_ReversalViaParentActionID(t *testing.T) {
	withTempQuarantineRoot(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "revertme.bin")
	want := []byte("revert-roundtrip-bytes")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}

	h := QuarantineFileHandler()
	const parentID = "88888888-8888-8888-8888-888888888888"
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId: parentID,
		Target:    target,
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("quarantine status = %s, detail = %q, want DONE", status, detail)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("original still present after quarantine: %v", err)
	}

	// Reversal request: parent_action_id points at the just-staged
	// quarantine; control_id is a fresh action UUID.
	rev := QuarantineFileHandler()
	revStatus, revDetail, _ := rev(context.Background(), &pb.ResponseRequest{
		ControlId:      "99999999-9999-9999-9999-999999999999",
		ParentActionId: parentID,
	})
	if revStatus != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("reversal status = %s, detail = %q, want DONE", revStatus, revDetail)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored target: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("restored contents = %x, want %x", got, want)
	}
}

func TestQuarantineHandler_ReversalUnknownParentFails(t *testing.T) {
	withTempQuarantineRoot(t)
	h := QuarantineFileHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{
		ControlId:      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		ParentActionId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, detail = %q, want FAILED", status, detail)
	}
}
