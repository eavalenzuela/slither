package enricher

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cmdlineMax bounds the bytes copied out of /proc/<pid>/cmdline. Mirrors the
// kernel-side PATH_MAX-ish cap in IMPLEMENTATION.md §3.2 so enricher output
// stays predictable regardless of argv size.
const cmdlineMax = 4096

// procReader is a thin wrapper around the procfs read patterns the enricher
// needs. The root is parameterised so tests can point it at a tmpdir.
type procReader struct {
	root string
}

func newProcReader(root string) *procReader {
	if root == "" {
		root = "/proc"
	}
	return &procReader{root: root}
}

func (p *procReader) path(pid uint32, parts ...string) string {
	elems := make([]string, 0, len(parts)+2)
	elems = append(elems, p.root, strconv.FormatUint(uint64(pid), 10))
	elems = append(elems, parts...)
	return filepath.Join(elems...)
}

// comm reads /proc/<pid>/comm, stripping the trailing newline. Returns "" if
// the process is gone or unreadable.
func (p *procReader) comm(pid uint32) string {
	b, err := os.ReadFile(p.path(pid, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\n")
}

// exe resolves /proc/<pid>/exe. On failure (process gone, permission denied,
// kernel thread) returns "".
func (p *procReader) exe(pid uint32) string {
	link, err := os.Readlink(p.path(pid, "exe"))
	if err != nil {
		return ""
	}
	return link
}

// cmdline reads /proc/<pid>/cmdline and converts the nul separators into
// spaces so the result is presentable as a single string. Truncated at
// cmdlineMax bytes.
func (p *procReader) cmdline(pid uint32) string {
	b, err := os.ReadFile(p.path(pid, "cmdline"))
	if err != nil {
		return ""
	}
	if len(b) > cmdlineMax {
		b = b[:cmdlineMax]
	}
	b = bytes.TrimRight(b, "\x00")
	b = bytes.ReplaceAll(b, []byte{0}, []byte{' '})
	return string(b)
}

// ppid scans /proc/<pid>/status for the PPid field. Returns 0 on any failure
// (including the process having exited).
func (p *procReader) ppid(pid uint32) uint32 {
	f, err := os.Open(p.path(pid, "status"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0
		}
		return uint32(n)
	}
	return 0
}
