//go:build linux

package respond

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// readTarGz unpacks a .tar.gz blob into name → contents.
func readTarGz(t *testing.T, blob []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, rerr := tr.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("tar next: %v", rerr)
		}
		body, rerr := io.ReadAll(tr)
		if rerr != nil {
			t.Fatalf("tar read body of %s: %v", hdr.Name, rerr)
		}
		out[hdr.Name] = body
	}
	return out
}

func TestCollectArtifactsHandler_BadPID(t *testing.T) {
	t.Parallel()
	h := CollectArtifactsHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "abc"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "not a pid") {
		t.Errorf("detail = %q, want parse error", detail)
	}
}

func TestCollectArtifactsHandler_MissingPID(t *testing.T) {
	t.Parallel()
	// Use a PID guaranteed to not exist. Linux's max_pid default is
	// 4194304; agent rarely if ever sees something this high.
	h := CollectArtifactsHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "4194303"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "not present in /proc") {
		t.Errorf("detail = %q, want missing-pid error", detail)
	}
}

func TestCollectArtifactsHandler_HappyPathOnSelf(t *testing.T) {
	t.Parallel()
	// Spawn a sleep so we have a stable, non-self target. Ancestors
	// of the test binary include `go test`, which has a stable
	// process tree we can inspect after collection.
	cmd := mustSpawnSleep(t, "30s")
	defer mustReap(t, cmd)

	h := CollectArtifactsHandler()
	status, detail, blob := h(context.Background(), &pb.ResponseRequest{
		ControlId: "ctrl-collect-1",
		Target:    itoa(cmd.Process.Pid),
	})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("status = %s, detail = %q, want DONE", status, detail)
	}
	if len(blob) == 0 {
		t.Fatal("blob empty, want non-empty tar.gz")
	}

	entries := readTarGz(t, blob)

	// Must include the manifest and at least proc/status + proc/cmdline.
	for _, want := range []string{"manifest.json", "proc/status", "proc/cmdline", "proc/comm"} {
		if _, ok := entries[want]; !ok {
			t.Errorf("missing entry %q in bundle (got %v)", want, keys(entries))
		}
	}

	// Manifest must reference the right PID and action_id.
	var m CollectArtifactsManifest
	if err := json.Unmarshal(entries["manifest.json"], &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if m.TargetPID != cmd.Process.Pid {
		t.Errorf("manifest.target_pid = %d, want %d", m.TargetPID, cmd.Process.Pid)
	}
	if m.ActionID != "ctrl-collect-1" {
		t.Errorf("manifest.action_id = %q, want round-trip", m.ActionID)
	}
	if len(m.Collected) == 0 {
		t.Error("manifest.collected empty — no entries recorded")
	}
}

func TestBuildProcessTree_IncludesAncestorAndComm(t *testing.T) {
	t.Parallel()
	body, err := buildProcessTree(os.Getpid())
	if err != nil {
		t.Fatalf("buildProcessTree: %v", err)
	}
	var doc struct {
		Target    int               `json:"target"`
		Ancestors []processTreeNode `json:"ancestors"`
		Tree      processTreeNode   `json:"tree"`
	}
	if uerr := json.Unmarshal(body, &doc); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	if doc.Target != os.Getpid() {
		t.Errorf("target = %d, want self", doc.Target)
	}
	if doc.Tree.PID != os.Getpid() {
		t.Errorf("tree.pid = %d, want self", doc.Tree.PID)
	}
	// Test binary always has at least one ancestor (`go test` driver).
	if len(doc.Ancestors) == 0 {
		t.Error("ancestors empty, want at least one (test driver)")
	}
}

func TestReadFDListing_HasExpectedFDs(t *testing.T) {
	t.Parallel()
	// Open a temp file so we know an fd exists with a recoverable target.
	f, err := os.CreateTemp(t.TempDir(), "fdcheck-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	body, err := readFDListing(os.Getpid())
	if err != nil {
		t.Fatalf("readFDListing: %v", err)
	}
	got := map[string]string{}
	if uerr := json.Unmarshal(body, &got); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	// The temp file's path should appear as one of the targets.
	found := false
	for _, target := range got {
		if strings.Contains(target, "fdcheck-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("temp fd target not in listing %v", got)
	}
}

func TestWriteBytesEntryStrict_RoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeBytesEntryStrict(tw, "x.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "x.txt" {
		t.Errorf("name = %q, want x.txt", hdr.Name)
	}
	if hdr.Size != 5 {
		t.Errorf("size = %d, want 5", hdr.Size)
	}
	body, _ := io.ReadAll(tr)
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}

func TestCollectArtifacts_RecordsSkipsForMissingFiles(t *testing.T) {
	t.Parallel()
	// Run against an unprivileged kthread (PID 2 / kthreadd) — the
	// test binary can stat /proc/2 but most of its files refuse reads
	// for non-root, populating the Skipped list.
	if _, err := os.Stat("/proc/2"); err != nil {
		t.Skip("/proc/2 not present (likely a non-Linux container)")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root — kthread reads succeed; this test wants the unprivileged path")
	}
	_, manifest, err := collectArtifacts(context.Background(), 2, "ctrl-skip-test")
	if err != nil {
		t.Fatalf("collectArtifacts: %v", err)
	}
	if len(manifest.Skipped) == 0 && len(manifest.Collected) == 0 {
		t.Fatal("both collected and skipped empty — manifest unpopulated")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
