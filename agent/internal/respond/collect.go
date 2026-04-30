//go:build linux

package respond

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// CollectArtifactsManifest is the JSON sidecar inside the tarball.
// Operators inspecting bundles read this for chain-of-custody +
// what-was-attempted-vs-skipped accounting. Field tags are
// wire-stable so a future agent reading a Phase-4-era bundle still
// understands it.
type CollectArtifactsManifest struct {
	ActionID     string    `json:"action_id"`
	TargetPID    int       `json:"target_pid"`
	CollectedAt  time.Time `json:"collected_at"`
	HostHostname string    `json:"hostname,omitempty"`
	// Collected lists the entries that landed in the tarball with
	// their byte counts. Skipped lists the entries the handler tried
	// and couldn't get, with a reason — `ptrace_scope` blocking
	// /proc/<pid>/mem reads, journalctl missing on a non-systemd
	// distro, etc. Present-but-empty bytes are still "collected".
	Collected []CollectedEntry `json:"collected"`
	Skipped   []SkippedEntry   `json:"skipped,omitempty"`
}

type CollectedEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type SkippedEntry struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// collectArtifactsMaxBlobBytes caps the result_blob size. The wire
// path is gRPC ServerMessage.response_result; ResponseResult flows
// over the same long-lived stream as events. A wedged 100MB blob
// would stall the stream + risk grpc-go's default 4MB recv cap on
// the server side. 4MB matches that cap minus a safety margin.
const collectArtifactsMaxBlobBytes = 3 << 20

// CollectArtifactsHandler returns the collect handler. Wired by
// WireCollectHandlers at startup. Phase 4 #81.
func CollectArtifactsHandler() Handler {
	return func(ctx context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		pid, err := parseTargetPID(req.GetTarget())
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		// /proc/<pid> existence is the cheapest "is this PID real" check.
		if _, statErr := os.Stat(procPath(pid)); statErr != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				fmt.Sprintf("pid %d not present in /proc: %v", pid, statErr), nil
		}
		blob, manifest, err := collectArtifacts(ctx, pid, strings.TrimSpace(req.GetControlId()))
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		if len(blob) > collectArtifactsMaxBlobBytes {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				fmt.Sprintf("artefact bundle %d bytes exceeds %d cap", len(blob), collectArtifactsMaxBlobBytes), nil
		}
		detail := fmt.Sprintf("collected %d entries (%d skipped) for pid %d, bundle=%d bytes",
			len(manifest.Collected), len(manifest.Skipped), pid, len(blob))
		return pb.ResponseStatus_RESPONSE_STATUS_DONE, detail, blob
	}
}

// collectArtifacts builds the tarball + manifest. Returns the gzipped
// tar bytes and the manifest (returned separately so the handler can
// fold counts into the detail line).
//
// Each best-effort entry that fails is recorded in manifest.Skipped
// with a reason — the bundle is *not* aborted. The only hard-fail
// path is "tar/gzip writer broke" which would mean we couldn't even
// emit an empty bundle.
func collectArtifacts(ctx context.Context, pid int, actionID string) ([]byte, CollectArtifactsManifest, error) {
	manifest := CollectArtifactsManifest{
		ActionID:    actionID,
		TargetPID:   pid,
		CollectedAt: time.Now().UTC(),
	}
	if h, _ := os.Hostname(); h != "" {
		manifest.HostHostname = h
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// Per-pid /proc files. /proc/<pid>/mem is gated on ptrace_scope —
	// if /proc/<pid>/maps reads but mem returns EACCES, the kernel's
	// kernel.yama.ptrace_scope=1 (or the process's own dumpable=0 +
	// SUID transition) is blocking us. Skip with a reason rather than
	// failing the whole action — the rest of the bundle is still
	// useful for triage.
	procFiles := []struct {
		name string
		path string
	}{
		{"proc/maps", procPath(pid, "maps")},
		{"proc/status", procPath(pid, "status")},
		{"proc/cmdline", procPath(pid, "cmdline")},
		{"proc/environ", procPath(pid, "environ")},
		{"proc/comm", procPath(pid, "comm")},
		{"proc/stat", procPath(pid, "stat")},
		{"proc/wchan", procPath(pid, "wchan")},
	}
	for _, pf := range procFiles {
		writeFileEntry(tw, &manifest, pf.name, pf.path)
	}

	// /proc/<pid>/fd is a directory of symlinks. Capture as a JSON
	// listing rather than the raw symlinks (tar can store symlinks
	// but the targets are what an analyst wants).
	if fdJSON, err := readFDListing(pid); err != nil {
		manifest.Skipped = append(manifest.Skipped, SkippedEntry{
			Name: "proc/fd.json", Reason: err.Error(),
		})
	} else {
		writeBytesEntry(tw, &manifest, "proc/fd.json", fdJSON)
	}

	// Process tree (ancestors + depth-3 descendants). Helps an
	// analyst place the target in context — what's its parent shell,
	// what did it spawn.
	if tree, err := buildProcessTree(pid); err != nil {
		manifest.Skipped = append(manifest.Skipped, SkippedEntry{
			Name: "proc/tree.json", Reason: err.Error(),
		})
	} else {
		writeBytesEntry(tw, &manifest, "proc/tree.json", tree)
	}

	// Host context — passwd/group lets the analyst resolve uid/gid
	// references; os-release identifies the distro. /etc/shadow is
	// deliberately excluded.
	for _, f := range []string{"/etc/passwd", "/etc/group", "/etc/os-release"} {
		writeFileEntry(tw, &manifest, "host"+f, f)
	}

	// Recent journal — best-effort. Distros without systemd-journald
	// (Alpine, slim containers) skip cleanly.
	if journal, err := captureJournal(ctx, 60*time.Second); err != nil {
		manifest.Skipped = append(manifest.Skipped, SkippedEntry{
			Name: "journal.txt", Reason: err.Error(),
		})
	} else {
		writeBytesEntry(tw, &manifest, "journal.txt", journal)
	}

	// Manifest written last so its byte count reflects the entries
	// that actually landed.
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, manifest, fmt.Errorf("marshal manifest: %w", err)
	}
	if werr := writeBytesEntryStrict(tw, "manifest.json", body); werr != nil {
		return nil, manifest, fmt.Errorf("write manifest: %w", werr)
	}

	if err := tw.Close(); err != nil {
		return nil, manifest, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, manifest, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), manifest, nil
}

// writeFileEntry reads path and writes it as name into tw. Failure
// records a Skipped entry on manifest rather than aborting.
func writeFileEntry(tw *tar.Writer, manifest *CollectArtifactsManifest, name, path string) {
	body, err := os.ReadFile(path) //nolint:gosec // operator-driven artefact collection; paths are kernel /proc + /etc whitelist
	if err != nil {
		manifest.Skipped = append(manifest.Skipped, SkippedEntry{
			Name: name, Reason: err.Error(),
		})
		return
	}
	writeBytesEntry(tw, manifest, name, body)
}

// writeBytesEntry writes body as name into tw. Failure to write the
// tar header (tar/gzip is unrecoverable once broken) is recorded as
// a Skipped entry; tw.Close() at the top level is the failure point
// for genuinely-broken streams.
func writeBytesEntry(tw *tar.Writer, manifest *CollectArtifactsManifest, name string, body []byte) {
	if err := writeBytesEntryStrict(tw, name, body); err != nil {
		manifest.Skipped = append(manifest.Skipped, SkippedEntry{
			Name: name, Reason: err.Error(),
		})
		return
	}
	manifest.Collected = append(manifest.Collected, CollectedEntry{
		Name: name, Size: int64(len(body)),
	})
}

func writeBytesEntryStrict(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(body)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}
	return nil
}

// readFDListing walks /proc/<pid>/fd and resolves each symlink's
// target. Returns a JSON object {"<fd>": "<target>", ...}.
func readFDListing(pid int) ([]byte, error) {
	dir := procPath(pid, "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read fd dir: %w", err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		target, rerr := os.Readlink(filepath.Join(dir, e.Name()))
		if rerr != nil {
			out[e.Name()] = "(error: " + rerr.Error() + ")"
			continue
		}
		out[e.Name()] = target
	}
	return json.MarshalIndent(out, "", "  ")
}

// processTreeNode is the JSON shape for buildProcessTree's output.
type processTreeNode struct {
	PID      int               `json:"pid"`
	PPID     int               `json:"ppid"`
	Comm     string            `json:"comm,omitempty"`
	Children []processTreeNode `json:"children,omitempty"`
}

// buildProcessTree returns a JSON document with the target's
// ancestors (up to /proc/1) and depth-3 descendant tree. Reuses
// readPPID + collectDescendants from kill.go for the descendant
// half; the ancestor walk is a simple PPID climb with a depth cap
// (matches collectDescendants's spirit of "bounded blast radius").
func buildProcessTree(pid int) ([]byte, error) {
	const ancestorMax = 16

	type doc struct {
		Target    int               `json:"target"`
		Ancestors []processTreeNode `json:"ancestors"`
		Tree      processTreeNode   `json:"tree"`
	}

	d := doc{Target: pid}

	// Ancestor climb. PID 1 (init) is the natural stop; a corrupt
	// /proc with circular PPIDs is bounded by ancestorMax.
	cur := pid
	for i := 0; i < ancestorMax; i++ {
		ppid, err := readPPID(cur)
		if err != nil || ppid <= 0 {
			break
		}
		d.Ancestors = append(d.Ancestors, processTreeNode{
			PID:  ppid,
			Comm: readCommSafe(ppid),
		})
		if ppid == 1 {
			break
		}
		cur = ppid
	}

	// Depth-3 descendants via collectDescendants (BFS). Render as a
	// flat node + children — analysts read the tarball with `tar t`
	// + `jq`, so a flat listing is easier than a nested doc.
	descendants, err := collectDescendants(pid, 256)
	if err != nil {
		// Cap-exceeds is informative on its own — record but still
		// emit what we have.
		d.Tree = processTreeNode{PID: pid, Comm: readCommSafe(pid)}
		body, mErr := json.MarshalIndent(d, "", "  ")
		if mErr != nil {
			return nil, mErr
		}
		return body, fmt.Errorf("descendants: %w (partial tree emitted)", err)
	}
	root := processTreeNode{PID: pid, Comm: readCommSafe(pid)}
	for _, child := range descendants {
		if child == pid {
			continue
		}
		root.Children = append(root.Children, processTreeNode{
			PID:  child,
			Comm: readCommSafe(child),
		})
	}
	d.Tree = root

	return json.MarshalIndent(d, "", "  ")
}

// readCommSafe reads /proc/<pid>/comm, trimming the trailing newline.
// Failure returns "" — comm is best-effort decoration on the tree.
func readCommSafe(pid int) string {
	body, err := os.ReadFile(procPath(pid, "comm")) //nolint:gosec // kernel-managed /proc
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(body), "\n")
}

// captureJournal runs `journalctl --since=-<window> --no-pager` and
// returns combined stdout. Window is rendered as a relative time
// because journalctl's --since accepts "30 seconds ago" but not "60s".
//
// Return value is the journal text or a wrapped error if journalctl
// is missing / failed. Errors are non-fatal at the caller — distros
// without journald skip this entry cleanly.
func captureJournal(ctx context.Context, window time.Duration) ([]byte, error) {
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return nil, fmt.Errorf("journalctl not on PATH: %w", err)
	}
	since := fmt.Sprintf("%d seconds ago", int(window.Seconds()))
	cmd := exec.CommandContext(ctx, path, "--since="+since, "--no-pager", "-q") //nolint:gosec // path is exec.LookPath-resolved; args are constants + a time literal
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if rerr := cmd.Run(); rerr != nil {
		return nil, fmt.Errorf("run journalctl: %w", rerr)
	}
	return out.Bytes(), nil
}
