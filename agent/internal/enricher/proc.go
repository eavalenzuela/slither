package enricher

import (
	"bufio"
	"bytes"
	"io"
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

// cwd resolves /proc/<pid>/cwd. Used by the file enricher to absolutise
// relative paths captured at syscall-entry (dfd-relative / AT_FDCWD-relative).
// Returns "" when the process has exited or the link isn't readable.
func (p *procReader) cwd(pid uint32) string {
	link, err := os.Readlink(p.path(pid, "cwd"))
	if err != nil {
		return ""
	}
	return link
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

// environMax bounds the bytes read out of /proc/<pid>/environ. The
// region is capped by the kernel at 1/4 of the stack rlimit and can be
// hundreds of KiB on services started with a large environment; we only
// ever want a handful of short variables out of it, so reading the
// whole thing to find them is the wrong trade. 32 KiB comfortably
// covers the head of any realistic environment block.
const environMax = 32 * 1024

// envValueMax bounds a single captured value. LD_PRELOAD and friends
// are paths; anything longer than this is either padding or an attempt
// to bloat the event, and truncating still leaves the prefix a rule
// needs to match on.
const envValueMax = 512

// envAllowlist is the set of environment variables the enricher will
// copy into an event, keyed by name.
//
// This is an allowlist and must stay one. A process environment is one
// of the densest concentrations of secrets on a host — cloud keys,
// database passwords, session tokens, CI credentials — and slither
// ships events to a central store that many operators query. Capturing
// the whole block would turn the event store into a credential
// database and would be a far larger liability than the detections are
// worth. Every name below is a loader/interpreter control that carries
// a path or a flag, not a secret.
//
// The set is the Linux code-injection surface:
//
//   - LD_* — the dynamic linker. LD_PRELOAD and LD_AUDIT load
//     attacker-chosen objects into a victim process (T1574.006);
//     LD_LIBRARY_PATH redirects resolution.
//   - GCONV_PATH — the iconv module path, and the actual payload
//     vector in CVE-2021-4034 (PwnKit): pkexec is tricked into
//     re-executing with an attacker-controlled gconv module.
//   - GLIBC_TUNABLES — CVE-2023-4911 (Looney Tunables), a buffer
//     overflow in glibc's tunable parser reachable from any setuid
//     binary.
//   - Interpreter path/startup hooks (PYTHONPATH, PERL5OPT, BASH_ENV,
//     NODE_OPTIONS, ...) — the same trick one layer up, used to get
//     code running inside an interpreter someone else invoked.
var envAllowlist = map[string]struct{}{
	"LD_PRELOAD":      {},
	"LD_LIBRARY_PATH": {},
	"LD_AUDIT":        {},
	"LD_CONFIG_FILE":  {},
	"LD_ORIGIN_PATH":  {},
	"LD_PROFILE":      {},
	"LD_DEBUG_OUTPUT": {},
	"GCONV_PATH":      {},
	"GLIBC_TUNABLES":  {},
	"BASH_ENV":        {},
	"ENV":             {},
	"PYTHONPATH":      {},
	"PYTHONSTARTUP":   {},
	"PERL5LIB":        {},
	"PERL5OPT":        {},
	"RUBYOPT":         {},
	"RUBYLIB":         {},
	"NODE_OPTIONS":    {},
}

// environ reads /proc/<pid>/environ and returns the allowlisted
// variables as "NAME=value" strings, in allowlist-hit order.
//
// Returned in NAME=value form rather than as a map so Sigma's list
// semantics apply directly: `EnvVars|contains: 'GCONV_PATH='` matches
// presence, and `EnvVars|startswith: 'LD_PRELOAD=/tmp/'` matches a
// value prefix, with no new operator or field-shape special case.
//
// Best-effort like every other reader here: a process that has already
// exited, or whose mm is unreadable, yields nil rather than an error.
// An empty result is the overwhelmingly common case — almost no
// process sets any of these.
func (p *procReader) environ(pid uint32) []string {
	f, err := os.Open(p.path(pid, "environ"))
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, environMax)
	n, err := io.ReadFull(f, buf)
	// Short reads are normal — most environments are well under the cap,
	// and a racing exit truncates mid-read. Only a hard error with no
	// bytes is fatal to the attempt.
	if n == 0 && err != nil {
		return nil
	}
	buf = buf[:n]

	var out []string
	for _, kv := range bytes.Split(buf, []byte{0}) {
		if len(kv) == 0 {
			continue
		}
		eq := bytes.IndexByte(kv, '=')
		if eq <= 0 {
			// No '=', or an empty name. Neither is a variable we can
			// key on; the kernel also pads the tail of the region.
			continue
		}
		name := string(kv[:eq])
		if _, ok := envAllowlist[name]; !ok {
			continue
		}
		val := kv[eq+1:]
		if len(val) > envValueMax {
			val = val[:envValueMax]
		}
		out = append(out, name+"="+string(val))
	}
	return out
}
