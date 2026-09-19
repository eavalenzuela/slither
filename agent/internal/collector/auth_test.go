//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	bpfpkg "github.com/t3rmit3/slither/agent/internal/bpf"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

func TestDecodeAuthKind(t *testing.T) {
	cases := map[uint32]pipeline.RawAuthKind{
		0: pipeline.AuthUnknown,
		1: pipeline.AuthAttempt,
		2: pipeline.AuthSessionOpen,
		3: pipeline.AuthSessionClose,
		9: pipeline.AuthUnknown,
	}
	for raw, want := range cases {
		if got := decodeAuthKind(raw); got != want {
			t.Errorf("decodeAuthKind(%d) = %d, want %d", raw, got, want)
		}
	}
}

func fill(dst []int8, s string) {
	for i := range dst {
		dst[i] = 0
	}
	for i := 0; i < len(s) && i < len(dst)-1; i++ {
		dst[i] = int8(s[i])
	}
}

// TestDecodeAuthEvent pins the BPF-record → RawAuthEvent projection: the
// process key is the tgid (not the thread id), the uid is passed through
// untouched, and every string field is NUL-trimmed.
func TestDecodeAuthEvent(t *testing.T) {
	var r bpfpkg.AuthAuthEvent
	r.Kind = 1
	r.Pid = 4242
	r.Tgid = 4200
	r.Uid = 1000
	r.Gid = 1000
	r.Result = 7
	fill(r.Service[:], "sshd")
	fill(r.User[:], "alice")
	fill(r.Rhost[:], "203.0.113.9")
	fill(r.Tty[:], "ssh")
	fill(r.Comm[:], "sshd")

	got := decodeAuthEvent(r)
	if got.Kind != pipeline.AuthAttempt {
		t.Errorf("kind = %d, want AuthAttempt", got.Kind)
	}
	if got.PID != 4200 {
		t.Errorf("PID = %d, want tgid 4200 (thread id must not leak through)", got.PID)
	}
	if got.UID != 1000 || got.Result != 7 {
		t.Errorf("uid/result = %d/%d, want 1000/7", got.UID, got.Result)
	}
	if got.Service != "sshd" || got.User != "alice" || got.RemoteHost != "203.0.113.9" || got.TTY != "ssh" || got.Comm != "sshd" {
		t.Errorf("strings not decoded cleanly: %+v", got)
	}
	if got.Timestamp.IsZero() {
		t.Error("timestamp should be stamped at decode")
	}
}

func TestResolveLibpamOverrideMustExist(t *testing.T) {
	_, err := resolveLibpam(filepath.Join(t.TempDir(), "nope.so.0"))
	if err == nil {
		t.Fatal("missing override path should error, not fall through to discovery")
	}
	if !strings.Contains(err.Error(), "libpam_path") {
		t.Errorf("error should name the config key: %v", err)
	}
}

func TestResolveLibpamOverrideWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "libpam.so.0")
	if err := os.WriteFile(p, []byte{0x7f, 'E', 'L', 'F'}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveLibpam(p)
	if err != nil || got != p {
		t.Fatalf("resolveLibpam(override) = %q, %v; want %q", got, err, p)
	}
}

// TestResolveLibpamDiscoversHostLibrary is a host-dependent smoke check:
// on any box with PAM installed, discovery must land on a real file. It
// skips rather than fails on a PAM-less build host.
func TestResolveLibpamDiscoversHostLibrary(t *testing.T) {
	got, err := resolveLibpam("")
	if err != nil {
		t.Skipf("no libpam on this host: %v", err)
	}
	if _, serr := os.Stat(got); serr != nil {
		t.Fatalf("discovered %q but it does not stat: %v", got, serr)
	}
}
