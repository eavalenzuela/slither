//go:build linux

package respond

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// quarantineRoot is the on-disk staging path. Mirrors the systemd
// unit's StateDirectory=slither convention so packagers don't need to
// special-case the quarantine dir's ownership / mode. It's a var (not
// a const) so tests redirect to a tempdir without polluting the host.
var quarantineRoot = "/var/lib/slither/quarantine"

// dirMode + fileMode keep the moved bytes readable to the agent +
// inert to anyone else. 0700 / 0600 — only root + the agent's
// effective user touch this material.
const (
	quarantineDirMode  os.FileMode = 0o700
	quarantineFileMode os.FileMode = 0o600
)

// QuarantineRefusedPrefixes are the path prefixes the handler refuses
// to quarantine. The agent must not move:
//
//   - kernel-managed pseudo-filesystems (/proc, /sys, /dev) — the
//     "files" aren't files.
//   - systemd's runtime dir (/run/systemd) — quarantining the
//     service manager's state would brick the host.
//   - the slither state dir itself — circular-bricks the agent on
//     restart.
//   - the slither-agent binary — quarantining the killer kills the
//     killer.
//
// Anything else is fair game; the operator's job is to drive the
// action with a target the rule actually meant.
var QuarantineRefusedPrefixes = []string{
	"/proc/",
	"/sys/",
	"/dev/",
	"/run/systemd/",
	"/var/lib/slither/",
	"/usr/local/bin/slither-agent",
}

// QuarantineManifest is the JSON sidecar that ships next to the
// moved bytes. Reversal (#85) reads it back to put the file at its
// original path; an operator inspecting the staging dir reads it for
// chain-of-custody. Field tags pin wire-stable JSON keys so a future
// agent reading a Phase-4-era sidecar still understands it.
type QuarantineManifest struct {
	ActionID      string    `json:"action_id"`
	OriginalPath  string    `json:"original_path"`
	OriginalSize  int64     `json:"original_size"`
	OriginalMtime time.Time `json:"original_mtime"`
	OriginalMode  uint32    `json:"original_mode"`
	OriginalUID   int       `json:"original_uid"`
	OriginalGID   int       `json:"original_gid"`
	SHA256        string    `json:"sha256"`
	QuarantinedAt time.Time `json:"quarantined_at"`
	HostHostname  string    `json:"hostname,omitempty"`
}

// QuarantineFileHandler returns the quarantine handler. Wired by
// WireQuarantineHandlers at startup.
func QuarantineFileHandler() Handler {
	return func(_ context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		raw := strings.TrimSpace(req.GetTarget())
		if raw == "" {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, "target path required", nil
		}
		// Resolve to absolute, evaluating symlinks. The refuse-set
		// is path-prefix-based, so a relative or symlink-disguised
		// /proc target must not slip through.
		abs, err := filepath.Abs(raw)
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				fmt.Sprintf("resolve target %q: %v", raw, err), nil
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			// Symlinks may legitimately point at gone targets; fall
			// through with abs and let the open below report.
			resolved = abs
		}
		if rerr := refuseQuarantinePath(resolved); rerr != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, rerr.Error(), nil
		}

		actionID := strings.TrimSpace(req.GetControlId())
		if actionID == "" {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED,
				"control_id required (used as the staging-dir name)", nil
		}

		manifest, err := quarantineFile(resolved, actionID)
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}

		return pb.ResponseStatus_RESPONSE_STATUS_DONE,
			fmt.Sprintf("quarantined %s (%d bytes, sha256=%s) to %s",
				resolved, manifest.OriginalSize, manifest.SHA256[:16],
				filepath.Join(quarantineRoot, actionID)),
			nil
	}
}

// refuseQuarantinePath enforces the prefix blacklist + a clean-path
// invariant (no "..", no trailing slash on a file). Symlink resolution
// is the caller's job (filepath.EvalSymlinks happens before this).
func refuseQuarantinePath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("target %q must be absolute", p)
	}
	clean := filepath.Clean(p)
	if clean != p {
		return fmt.Errorf("target %q is not in canonical form (cleaned: %q)", p, clean)
	}
	for _, prefix := range QuarantineRefusedPrefixes {
		// Match on prefix-with-slash so /var/lib/slither/quarantine
		// is refused but /var/lib/slither-thing/x.bin is not.
		if p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix) {
			return fmt.Errorf("refusing to quarantine path under %q", prefix)
		}
	}
	return nil
}

// quarantineFile is the file-mover + manifest-writer. Splits
// atomically across two operations: copy bytes into staging, then
// remove the source — os.Rename would be cleanest but cross-device
// (e.g. /home on a separate FS from /var) breaks rename and we'd
// have to fall back to copy+remove anyway. Always copy+remove keeps
// the path uniform.
func quarantineFile(target, actionID string) (QuarantineManifest, error) {
	stagingDir := filepath.Join(quarantineRoot, actionID)
	if err := os.MkdirAll(stagingDir, quarantineDirMode); err != nil {
		return QuarantineManifest{}, fmt.Errorf("mkdir staging: %w", err)
	}

	src, err := os.Open(target) //nolint:gosec // operator-chosen quarantine target
	if err != nil {
		return QuarantineManifest{}, fmt.Errorf("open target: %w", err)
	}
	defer src.Close()
	srcInfo, err := src.Stat()
	if err != nil {
		return QuarantineManifest{}, fmt.Errorf("stat target: %w", err)
	}
	if !srcInfo.Mode().IsRegular() {
		return QuarantineManifest{}, fmt.Errorf("refusing to quarantine non-regular file (%s)", srcInfo.Mode().String())
	}

	contentsPath := filepath.Join(stagingDir, "contents")
	dst, err := os.OpenFile(contentsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, quarantineFileMode) //nolint:gosec // path is staging-dir-rooted and operator-controlled
	if err != nil {
		return QuarantineManifest{}, fmt.Errorf("open staging contents: %w", err)
	}

	hasher := sha256.New()
	mw := io.MultiWriter(dst, hasher)
	n, err := io.Copy(mw, src)
	if err != nil {
		_ = dst.Close()
		_ = os.Remove(contentsPath)
		return QuarantineManifest{}, fmt.Errorf("copy to staging: %w", err)
	}
	if err := dst.Close(); err != nil {
		return QuarantineManifest{}, fmt.Errorf("close staging contents: %w", err)
	}

	manifest := QuarantineManifest{
		ActionID:      actionID,
		OriginalPath:  target,
		OriginalSize:  n,
		OriginalMtime: srcInfo.ModTime(),
		OriginalMode:  uint32(srcInfo.Mode().Perm()),
		SHA256:        hex.EncodeToString(hasher.Sum(nil)),
		QuarantinedAt: time.Now().UTC(),
	}
	if uid, gid, ok := ownerOf(srcInfo); ok {
		manifest.OriginalUID = uid
		manifest.OriginalGID = gid
	}
	if h, _ := os.Hostname(); h != "" {
		manifest.HostHostname = h
	}
	if err := writeManifest(stagingDir, manifest); err != nil {
		_ = os.Remove(contentsPath)
		return QuarantineManifest{}, fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Remove(target); err != nil {
		// Bytes are in staging + manifest is on disk, but the
		// original is still present. Surface as FAILED so the
		// operator sees the inconsistent state; the staging dir
		// stays so a follow-up reversal call can repair via the
		// sidecar (which still reads correctly).
		return QuarantineManifest{}, fmt.Errorf("remove target after copy: %w", err)
	}
	return manifest, nil
}

// RestoreFromQuarantine is the reversal helper #85 calls to put a
// quarantined file back at its original path. Reads the manifest,
// validates the staged contents' sha256, restores bytes + mode +
// mtime, then deletes the staging dir. Refuses to overwrite an
// existing file at the original path — the operator's job is to
// resolve the conflict before re-inserting the row.
func RestoreFromQuarantine(actionID string) error {
	if strings.TrimSpace(actionID) == "" {
		return errors.New("action_id required")
	}
	stagingDir := filepath.Join(quarantineRoot, actionID)
	manifest, err := readManifest(stagingDir)
	if err != nil {
		return err
	}
	contentsPath := filepath.Join(stagingDir, "contents")
	if vErr := verifyContents(contentsPath, manifest.SHA256); vErr != nil {
		return fmt.Errorf("verify staged contents: %w", vErr)
	}
	if _, sErr := os.Stat(manifest.OriginalPath); sErr == nil {
		return fmt.Errorf("refusing to restore over existing file at %q", manifest.OriginalPath)
	}

	src, err := os.Open(contentsPath) //nolint:gosec // staging dir owned by agent
	if err != nil {
		return fmt.Errorf("open staged contents: %w", err)
	}
	defer src.Close()

	if mkErr := os.MkdirAll(filepath.Dir(manifest.OriginalPath), 0o750); mkErr != nil {
		return fmt.Errorf("mkdir parent: %w", mkErr)
	}
	dst, err := os.OpenFile(manifest.OriginalPath, //nolint:gosec // restoring an operator-driven quarantine; path comes from a previously-validated manifest
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		os.FileMode(manifest.OriginalMode))
	if err != nil {
		return fmt.Errorf("open original path: %w", err)
	}
	if _, copyErr := io.Copy(dst, src); copyErr != nil {
		_ = dst.Close()
		_ = os.Remove(manifest.OriginalPath)
		return fmt.Errorf("copy bytes back: %w", copyErr)
	}
	if closeErr := dst.Close(); closeErr != nil {
		return fmt.Errorf("close restored: %w", closeErr)
	}
	if mtimeErr := os.Chtimes(manifest.OriginalPath, manifest.OriginalMtime, manifest.OriginalMtime); mtimeErr != nil {
		// Mtime restore failure is loud (forensics may rely on it)
		// but not fatal — bytes are back; surface in the error so
		// the audit row records the partial restore.
		return fmt.Errorf("restore mtime: %w", mtimeErr)
	}
	if cleanErr := os.RemoveAll(stagingDir); cleanErr != nil {
		return fmt.Errorf("clean staging dir: %w", cleanErr)
	}
	return nil
}

func writeManifest(stagingDir string, m QuarantineManifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	path := filepath.Join(stagingDir, "manifest.json")
	return os.WriteFile(path, body, quarantineFileMode)
}

func readManifest(stagingDir string) (QuarantineManifest, error) {
	body, err := os.ReadFile(filepath.Join(stagingDir, "manifest.json")) //nolint:gosec // staging dir owned by agent
	if err != nil {
		return QuarantineManifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var m QuarantineManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return QuarantineManifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return m, nil
}

func verifyContents(path, want string) error {
	f, err := os.Open(path) //nolint:gosec // staging dir owned by agent
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 mismatch (manifest %s, staged %s)", want, got)
	}
	return nil
}
