package sigverify

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxBundleSize bounds the total uncompressed bundle bytes. 64 MiB is
// generous for any realistic Sigma rule pack — typical packs run
// under 1 MiB — and small enough to make a malicious or runaway
// bundle obvious well before it OOMs the importer.
const MaxBundleSize = 64 << 20

// MaxBundleEntries bounds the count of YAML files in a single bundle.
// 10k is also generous (the largest in-the-wild Sigma rule sets ship
// ~3k rules); the cap exists so a tar with millions of empty entries
// fails fast rather than spinning the importer.
const MaxBundleEntries = 10_000

// BundleEntry is one YAML rule extracted from a verified bundle.
// Path is the conventional in-tar path (slash-separated, regardless
// of host OS); Bytes is the raw YAML.
type BundleEntry struct {
	Path  string
	Bytes []byte
}

// VerifyAndExtractBundle runs cosign verify-blob against the bundle
// at bundlePath using its conventional `.sig` + `.pem` sidecars (or
// operator-supplied paths via Options), then walks the tar.gz
// contents and returns every `*.yml` / `*.yaml` entry.
//
// Verify-first / extract-second is the right order: a tampered
// bundle fails verification before any tar bytes are interpreted.
//
// Non-YAML entries (READMEs, license files) are silently skipped —
// the bundle's cargo is rule YAML, anything else is noise.
// Directories are skipped. Symlinks are refused (a malicious bundle
// could otherwise smuggle path-traversal via symlink target).
func VerifyAndExtractBundle(ctx context.Context, bundlePath string, opts Options) ([]BundleEntry, error) {
	sig, cert := SidecarPaths(bundlePath)
	if err := VerifyBlob(ctx, bundlePath, sig, cert, opts); err != nil {
		return nil, err
	}
	return extractBundle(bundlePath)
}

// ExtractBundle walks a tar.gz bundle without verifying. Used by the
// CLI's --no-verify path (dev/CI) and by tests; production callers
// must use VerifyAndExtractBundle.
func ExtractBundle(bundlePath string) ([]BundleEntry, error) {
	return extractBundle(bundlePath)
}

func extractBundle(bundlePath string) ([]BundleEntry, error) {
	f, err := os.Open(bundlePath) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("sigverify: open bundle: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("sigverify: gunzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var entries []BundleEntry
	var totalBytes int64
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sigverify: tar next: %w", err)
		}
		count++
		if count > MaxBundleEntries {
			return nil, fmt.Errorf("sigverify: bundle has %d+ entries, exceeds cap %d", count, MaxBundleEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeSymlink, tar.TypeLink:
			return nil, fmt.Errorf("sigverify: bundle contains symlink %q (refused — possible path traversal)", hdr.Name)
		case tar.TypeReg:
			// fall through
		default:
			// Unknown / device / fifo — skip without erroring; rule
			// bundles only carry regular files in the wild.
			continue
		}

		name := hdr.Name
		// Refuse paths that try to escape via "..", absolute components,
		// or backslashes (Windows tarball pathology). We only walk
		// content from a verified-or-explicitly-trusted source, but
		// belt-and-braces.
		clean := filepath.ToSlash(filepath.Clean(name))
		if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
			return nil, fmt.Errorf("sigverify: bundle entry %q escapes root", name)
		}

		ext := strings.ToLower(filepath.Ext(clean))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		if hdr.Size > MaxBundleSize {
			return nil, fmt.Errorf("sigverify: bundle entry %q size %d exceeds MaxBundleSize", name, hdr.Size)
		}
		totalBytes += hdr.Size
		if totalBytes > MaxBundleSize {
			return nil, fmt.Errorf("sigverify: bundle total uncompressed bytes exceeds MaxBundleSize %d", MaxBundleSize)
		}

		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, fmt.Errorf("sigverify: read entry %q: %w", name, err)
		}
		entries = append(entries, BundleEntry{Path: clean, Bytes: buf})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("sigverify: bundle has no YAML rule files")
	}
	return entries, nil
}
