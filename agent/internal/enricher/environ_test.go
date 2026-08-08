package enricher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// writeEnviron lays down a fake /proc/<pid>/environ with the kernel's
// NUL-separated encoding.
func writeEnviron(t *testing.T, root string, pid uint32, vars ...string) {
	t.Helper()
	dir := filepath.Join(root, "1234")
	if pid != 1234 {
		dir = filepath.Join(root, itoa(pid))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := strings.Join(vars, "\x00") + "\x00"
	if err := os.WriteFile(filepath.Join(dir, "environ"), []byte(body), 0o644); err != nil {
		t.Fatalf("write environ: %v", err)
	}
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var b []byte
	for u > 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

// The whole point of the allowlist: secrets in the environment must not
// leave the host, and everything that is not an injection vector is a
// potential secret.
func TestEnviron_DropsEverythingNotAllowlisted(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeEnviron(t, root, 1234,
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
		"DATABASE_URL=postgres://user:hunter2@db/app",
		"GITHUB_TOKEN=ghp_deadbeef",
		"HOME=/root",
		"PATH=/usr/bin:/bin",
		"LD_PRELOAD=/tmp/eve.so",
	)
	got := newProcReader(root).environ(1234)

	if len(got) != 1 || got[0] != "LD_PRELOAD=/tmp/eve.so" {
		t.Fatalf("environ = %q, want only the allowlisted LD_PRELOAD", got)
	}
	joined := strings.Join(got, "|")
	for _, secret := range []string{"wJalrXUtnFEMI", "hunter2", "ghp_deadbeef"} {
		if strings.Contains(joined, secret) {
			t.Errorf("captured a secret: %q leaked into %q", secret, joined)
		}
	}
}

// The overwhelmingly common case — nothing interesting set — must cost
// nothing downstream, i.e. produce no field at all rather than an empty
// list that still serialises.
func TestEnviron_OrdinaryProcessYieldsNothing(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeEnviron(t, root, 1234, "HOME=/root", "PATH=/usr/bin", "LANG=C.UTF-8")
	if got := newProcReader(root).environ(1234); got != nil {
		t.Errorf("environ = %q, want nil", got)
	}
}

func TestEnviron_CapturesEveryInjectionVector(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeEnviron(t, root, 1234,
		"GCONV_PATH=/tmp/pwnkit",
		"GLIBC_TUNABLES=glibc.malloc.tcache_count=257",
		"LD_AUDIT=/tmp/audit.so",
		"PYTHONPATH=/tmp/py",
		"BASH_ENV=/tmp/rc",
		"NODE_OPTIONS=--require /tmp/x.js",
		"IRRELEVANT=1",
	)
	got := newProcReader(root).environ(1234)
	if len(got) != 6 {
		t.Fatalf("environ = %q, want 6 entries", got)
	}
	for _, want := range []string{
		"GCONV_PATH=/tmp/pwnkit",
		"GLIBC_TUNABLES=glibc.malloc.tcache_count=257",
		"LD_AUDIT=/tmp/audit.so",
		"PYTHONPATH=/tmp/py",
		"BASH_ENV=/tmp/rc",
		"NODE_OPTIONS=--require /tmp/x.js",
	} {
		if !contains(got, want) {
			t.Errorf("missing %q from %q", want, got)
		}
	}
}

// A value containing '=' must keep its tail — GLIBC_TUNABLES is
// literally a list of key=value pairs, so splitting on the last '='
// (or on every one) would corrupt the very variable CVE-2023-4911
// abuses.
func TestEnviron_SplitsOnFirstEqualsOnly(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeEnviron(t, root, 1234, "GLIBC_TUNABLES=glibc.a=1:glibc.b=2")
	got := newProcReader(root).environ(1234)
	if len(got) != 1 || got[0] != "GLIBC_TUNABLES=glibc.a=1:glibc.b=2" {
		t.Fatalf("environ = %q, want the value preserved intact", got)
	}
}

// An oversize value is truncated, not dropped: the prefix is what a
// rule matches on, and dropping it would let an attacker evade the
// rule by padding.
func TestEnviron_TruncatesOversizeValueRatherThanDropping(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	long := "/tmp/" + strings.Repeat("a", envValueMax*2)
	writeEnviron(t, root, 1234, "LD_PRELOAD="+long)
	got := newProcReader(root).environ(1234)
	if len(got) != 1 {
		t.Fatalf("environ = %q, want the entry kept", got)
	}
	if !strings.HasPrefix(got[0], "LD_PRELOAD=/tmp/") {
		t.Errorf("prefix lost: %q", got[0][:40])
	}
	if got := len(got[0]) - len("LD_PRELOAD="); got != envValueMax {
		t.Errorf("value length = %d, want %d", got, envValueMax)
	}
}

// Malformed entries the kernel can leave behind (padding, a bare name
// with no '=') must not panic or produce junk fields.
func TestEnviron_SkipsMalformedEntries(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeEnviron(t, root, 1234, "", "NOEQUALS", "=novalue", "LD_PRELOAD=/tmp/x.so", "")
	got := newProcReader(root).environ(1234)
	if len(got) != 1 || got[0] != "LD_PRELOAD=/tmp/x.so" {
		t.Fatalf("environ = %q, want just the well-formed entry", got)
	}
}

// A process that exited between the exec event and the read is the
// normal race, not an error.
func TestEnviron_MissingProcessIsNotAnError(t *testing.T) {
	t.Parallel()
	if got := newProcReader(t.TempDir()).environ(999999); got != nil {
		t.Errorf("environ = %q, want nil for a vanished pid", got)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// newEnvTestEnricher builds an enricher over a temp /proc with
// CaptureEnv set as requested, returning it alongside that /proc root so
// the caller can plant an environ file for the pid under test.
func newEnvTestEnricher(t *testing.T, capture bool) (e *enricher, procRoot string) {
	t.Helper()
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	procRoot = filepath.Join(dir, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		ParentChainDepth:   8,
		CacheEvictionGrace: 30 * time.Second,
		PasswdPath:         passwd,
		ProcRoot:           procRoot,
		CaptureEnv:         capture,
		Device:             ocsf.Device{HostID: "test-host", Hostname: "test-host"},
		Now:                func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	opts.applyDefaults()
	e = &enricher{
		telem:          telemetry.NewCounters(),
		opts:           opts,
		out:            make(chan ocsf.Event, 16),
		cache:          newProcCache(),
		users:          newUserResolver(opts.PasswdPath),
		proc:           newProcReader(opts.ProcRoot),
		fileFilter:     newPathGlob(nil, nil),
		hasher:         newHasher(opts.HashWorkers),
		reloadFilterCh: make(chan config.FileCollector, 1),
	}
	t.Cleanup(e.hasher.Close)
	return e, procRoot
}

// execRaw is the shape the BPF program produces on a modern kernel:
// exe and cmdline already filled in, so nothing forces a /proc read
// except env capture itself.
func execRaw(pid uint32) pipeline.RawProcessEvent {
	return pipeline.RawProcessEvent{
		Kind: pipeline.ProcExec, PID: pid, UID: 0, Comm: "pkexec",
		Exe: "/usr/bin/pkexec", Cmdline: "pkexec id",
		Timestamp: time.Unix(100, 0),
	}
}

// End-to-end through the enricher: the captured variables must reach the
// OCSF event, which is what the rule engine and the server both read.
func TestEnricher_CaptureEnvPopulatesOCSF(t *testing.T) {
	t.Parallel()
	e, procRoot := newEnvTestEnricher(t, true)
	writeEnviron(t, procRoot, 4242,
		"GCONV_PATH=/tmp/pwnkit", "AWS_SECRET_ACCESS_KEY=shhh")
	// The parent must exist or the chain walk has nothing to do; this
	// mirrors the other exec tests.
	e.cache.upsert(procEntry{pid: 1, ppid: 0, uid: 0, comm: "systemd", createdAt: time.Unix(1, 0)})
	e.cache.upsert(procEntry{pid: 4242, ppid: 1, uid: 0, comm: "pkexec", createdAt: time.Unix(2, 0)})

	e.handleProcess(context.Background(), execRaw(4242))

	ev := <-e.out
	pa, ok := ev.(*ocsf.ProcessActivity)
	if !ok {
		t.Fatalf("got %T, want *ocsf.ProcessActivity", ev)
	}
	if len(pa.Process.EnvVars) != 1 || pa.Process.EnvVars[0] != "GCONV_PATH=/tmp/pwnkit" {
		t.Fatalf("EnvVars = %q, want only the allowlisted GCONV_PATH", pa.Process.EnvVars)
	}
}

// With capture off — the default — the field stays empty even when the
// process has interesting variables set. This is the property that keeps
// the setting meaningful rather than cosmetic.
func TestEnricher_CaptureEnvOffLeavesFieldEmpty(t *testing.T) {
	t.Parallel()
	e, procRoot := newEnvTestEnricher(t, false)
	writeEnviron(t, procRoot, 4242, "GCONV_PATH=/tmp/pwnkit")
	e.cache.upsert(procEntry{pid: 1, ppid: 0, uid: 0, comm: "systemd", createdAt: time.Unix(1, 0)})
	e.cache.upsert(procEntry{pid: 4242, ppid: 1, uid: 0, comm: "pkexec", createdAt: time.Unix(2, 0)})

	e.handleProcess(context.Background(), execRaw(4242))

	ev := <-e.out
	pa := ev.(*ocsf.ProcessActivity)
	if len(pa.Process.EnvVars) != 0 {
		t.Errorf("EnvVars = %q, want empty with capture off", pa.Process.EnvVars)
	}
}

// A later fork/exit for the same pid carries no environment and must not
// erase what exec learnt — otherwise the field would race away between
// the exec event and any rule that looks at a subsequent event.
func TestEnricher_LaterEventDoesNotClearCapturedEnv(t *testing.T) {
	t.Parallel()
	e, procRoot := newEnvTestEnricher(t, true)
	writeEnviron(t, procRoot, 4242, "LD_PRELOAD=/tmp/eve.so")
	e.cache.upsert(procEntry{pid: 1, ppid: 0, uid: 0, comm: "systemd", createdAt: time.Unix(1, 0)})
	e.cache.upsert(procEntry{pid: 4242, ppid: 1, uid: 0, comm: "pkexec", createdAt: time.Unix(2, 0)})

	e.handleProcess(context.Background(), execRaw(4242))
	<-e.out

	e.cache.upsert(procEntry{pid: 4242, ppid: 1, uid: 0, comm: "pkexec"})
	ent, ok := e.cache.get(4242)
	if !ok {
		t.Fatal("cache entry vanished")
	}
	if len(ent.env) != 1 || ent.env[0] != "LD_PRELOAD=/tmp/eve.so" {
		t.Errorf("env = %q after a later upsert, want it preserved", ent.env)
	}
}
