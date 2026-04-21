package enricher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func TestProcCacheUpsertMerge(t *testing.T) {
	c := newProcCache()
	c.upsert(procEntry{pid: 42, ppid: 1, uid: 1000, comm: "bash", createdAt: time.Unix(100, 0)})
	c.upsert(procEntry{pid: 42, exe: "/bin/bash", cmdline: "bash -i"})

	got, ok := c.get(42)
	if !ok {
		t.Fatalf("pid 42 missing after upsert")
	}
	if got.ppid != 1 || got.uid != 1000 || got.comm != "bash" {
		t.Errorf("initial fields lost: %+v", got)
	}
	if got.exe != "/bin/bash" || got.cmdline != "bash -i" {
		t.Errorf("follow-on fields not merged: %+v", got)
	}
	if got.createdAt.Unix() != 100 {
		t.Errorf("createdAt clobbered: %v", got.createdAt)
	}
}

func TestProcCacheEviction(t *testing.T) {
	c := newProcCache()
	c.upsert(procEntry{pid: 10, comm: "a"})
	c.upsert(procEntry{pid: 11, comm: "b"})

	now := time.Unix(1000, 0)
	c.markExit(10, now)

	// grace not elapsed yet
	if n := c.evictExpired(now.Add(1*time.Second), 30*time.Second); n != 0 {
		t.Fatalf("evicted %d entries before grace", n)
	}
	if _, ok := c.get(10); !ok {
		t.Fatalf("pid 10 should survive within grace")
	}

	// grace elapsed
	if n := c.evictExpired(now.Add(31*time.Second), 30*time.Second); n != 1 {
		t.Fatalf("evicted %d, want 1", n)
	}
	if _, ok := c.get(10); ok {
		t.Fatalf("pid 10 should be gone after grace")
	}
	if _, ok := c.get(11); !ok {
		t.Fatalf("pid 11 must not be touched by eviction")
	}
}

func TestProcCacheResurrection(t *testing.T) {
	c := newProcCache()
	now := time.Unix(1000, 0)
	c.upsert(procEntry{pid: 42, comm: "old"})
	c.markExit(42, now)

	// A new event for the same pid (pid wrap within grace) must clear the
	// exit mark so eviction doesn't later drop a live process.
	c.upsert(procEntry{pid: 42, comm: "new"})

	got, _ := c.get(42)
	if got.comm != "new" {
		t.Errorf("comm not refreshed: %q", got.comm)
	}
	if n := c.evictExpired(now.Add(1*time.Hour), 30*time.Second); n != 0 {
		t.Errorf("resurrected entry evicted: %d", n)
	}
}

func TestUserResolver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	body := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"malformed-line",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newUserResolver(path)
	if got := r.Name(0); got != "root" {
		t.Errorf("uid 0 -> %q, want root", got)
	}
	if got := r.Name(1000); got != "alice" {
		t.Errorf("uid 1000 -> %q, want alice", got)
	}
	if got := r.Name(9999); got != "" {
		t.Errorf("unknown uid -> %q, want empty", got)
	}

	// Rewrite and reload swaps the snapshot atomically.
	if err := os.WriteFile(path, []byte("root:x:0:0::/root:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload()
	if got := r.Name(1000); got != "" {
		t.Errorf("post-reload alice still present: %q", got)
	}

	// Reloading against a missing file must not panic and must clear the
	// snapshot to the empty map rather than keep stale data.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.reload()
	if got := r.Name(0); got != "" {
		t.Errorf("post-remove root still present: %q", got)
	}
}

func TestActivityIDMapping(t *testing.T) {
	cases := map[pipeline.RawProcessKind]ocsf.ProcessActivityID{
		pipeline.ProcExec: ocsf.ProcessActivityLaunch,
		pipeline.ProcFork: ocsf.ProcessActivityLaunch,
		pipeline.ProcExit: ocsf.ProcessActivityTerminate,
	}
	for k, want := range cases {
		if got := activityID(k); got != want {
			t.Errorf("activityID(%v) = %d, want %d", k, got, want)
		}
	}
}

func TestBuildOCSFExec(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{pid: 1, ppid: 0, uid: 0, comm: "systemd", createdAt: time.Unix(1, 0)})
	e.cache.upsert(procEntry{pid: 1000, ppid: 1, uid: 0, comm: "login", createdAt: time.Unix(2, 0)})

	raw := pipeline.RawProcessEvent{
		Kind: pipeline.ProcExec, PID: 1000, UID: 0, Comm: "login",
		Timestamp: time.Unix(100, 0),
	}
	ent, _ := e.cache.get(1000)
	ev := e.buildOCSF(raw, ent)

	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev.ActivityID != ocsf.ProcessActivityLaunch {
		t.Errorf("activity_id = %d, want Launch", ev.ActivityID)
	}
	if ev.Process.PID != 1000 {
		t.Errorf("process.pid = %d, want 1000", ev.Process.PID)
	}
	if ev.Process.Parent == nil || ev.Process.Parent.PID != 1 {
		t.Errorf("parent chain missing or wrong: %+v", ev.Process.Parent)
	}
	if ev.Actor.Process.PID != 1 {
		t.Errorf("actor.process = %+v, want parent pid 1", ev.Actor.Process)
	}
	if ev.Metadata.EventCode != "exec" {
		t.Errorf("event_code = %q, want exec", ev.Metadata.EventCode)
	}
	if ev.Time == 0 {
		t.Errorf("time not stamped")
	}
}

func TestBuildOCSFExitCarriesCode(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{pid: 7, ppid: 1, uid: 1000, comm: "sh", createdAt: time.Unix(5, 0)})

	raw := pipeline.RawProcessEvent{
		Kind: pipeline.ProcExit, PID: 7, UID: 1000, Comm: "sh",
		Timestamp: time.Unix(9, 0), ExitCode: 137,
	}
	ent, _ := e.cache.get(7)
	ev := e.buildOCSF(raw, ent)

	if ev.ExitCode == nil || *ev.ExitCode != 137 {
		t.Fatalf("exit_code = %v, want 137", ev.ExitCode)
	}
	if ev.ActivityID != ocsf.ProcessActivityTerminate {
		t.Errorf("activity_id = %d, want Terminate", ev.ActivityID)
	}
}

func TestParentChainDepthBounded(t *testing.T) {
	e := newTestEnricher(t)
	// Chain: 100 -> 99 -> 98 -> ... -> 1 -> 0 (stop).
	for pid := uint32(1); pid <= 100; pid++ {
		e.cache.upsert(procEntry{pid: pid, ppid: pid - 1, comm: "p"})
	}
	p := e.buildParentChain(99, 8)
	// Depth 8 means 8 nodes max along the .Parent chain including the head.
	n := 0
	for cur := p; cur != nil; cur = cur.Parent {
		n++
		if n > 8 {
			t.Fatalf("chain exceeded depth 8")
		}
	}
	if n != 8 {
		t.Errorf("chain length = %d, want 8", n)
	}
}

func newTestEnricher(t *testing.T) *enricher {
	t.Helper()
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	procRoot := filepath.Join(dir, "proc")
	if err := os.MkdirAll(procRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		ParentChainDepth:   8,
		CacheEvictionGrace: 30 * time.Second,
		PasswdPath:         passwd,
		ProcRoot:           procRoot,
		Device:             ocsf.Device{HostID: "test-host", Hostname: "test-host"},
		Now:                func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	opts.applyDefaults()
	return &enricher{
		telem: telemetry.NewCounters(),
		opts:  opts,
		out:   make(chan ocsf.Event, 16),
		cache: newProcCache(),
		users: newUserResolver(opts.PasswdPath),
		proc:  newProcReader(opts.ProcRoot),
	}
}
