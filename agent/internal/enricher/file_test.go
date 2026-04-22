package enricher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func TestFileActivityIDMapping(t *testing.T) {
	cases := map[pipeline.RawFileKind]ocsf.FileSystemActivityID{
		pipeline.FileOpenCreate: ocsf.FileActivityCreate,
		pipeline.FileOpenWrite:  ocsf.FileActivityUpdate,
		pipeline.FileUnlink:     ocsf.FileActivityDelete,
		pipeline.FileRename:     ocsf.FileActivityRename,
		pipeline.FileChmod:      ocsf.FileActivitySetAttr,
		pipeline.FileChown:      ocsf.FileActivitySetOwner,
	}
	for k, want := range cases {
		if got := fileActivityID(k); got != want {
			t.Errorf("fileActivityID(%v) = %d, want %d", k, got, want)
		}
	}
}

func TestHandleFileBuildsValidOCSF(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{
		pid: 500, ppid: 1, uid: 1000, comm: "vi", exe: "/usr/bin/vi",
		cmdline: "vi /etc/passwd", createdAt: time.Unix(10, 0),
	})

	raw := pipeline.RawFileEvent{
		Kind: pipeline.FileOpenWrite, PID: 500, UID: 1000,
		Path: "/etc/passwd", Flags: 0x0002,
		Timestamp: time.Unix(42, 0),
	}
	e.handleFile(context.Background(), raw)

	select {
	case ev := <-e.out:
		fa, ok := ev.(*ocsf.FileSystemActivity)
		if !ok {
			t.Fatalf("emitted %T, want *FileSystemActivity", ev)
		}
		if err := fa.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if fa.ActivityID != ocsf.FileActivityUpdate {
			t.Errorf("activity_id = %d, want Update", fa.ActivityID)
		}
		if fa.File.Path != "/etc/passwd" || fa.File.Name != "passwd" {
			t.Errorf("file = %+v", fa.File)
		}
		if fa.Actor.Process.PID != 500 || fa.Actor.Process.Name != "vi" {
			t.Errorf("actor.process = %+v", fa.Actor.Process)
		}
		if fa.Actor.User.Name != "alice" {
			t.Errorf("actor.user.name = %q, want alice", fa.Actor.User.Name)
		}
		if fa.Metadata.EventCode != "open_write" {
			t.Errorf("event_code = %q", fa.Metadata.EventCode)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event emitted")
	}
}

func TestHandleFileRenamePopulatesDiff(t *testing.T) {
	e := newTestEnricher(t)
	raw := pipeline.RawFileEvent{
		Kind: pipeline.FileRename, PID: 600, UID: 0,
		Path: "/tmp/old", NewPath: "/tmp/new",
		Timestamp: time.Unix(1, 0),
	}
	e.handleFile(context.Background(), raw)

	ev := <-e.out
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.RenameTo == nil || fa.RenameTo.Path != "/tmp/new" {
		t.Fatalf("rename_to = %+v", fa.RenameTo)
	}
	if err := fa.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestHandleFileChmodStashesMode(t *testing.T) {
	e := newTestEnricher(t)
	raw := pipeline.RawFileEvent{
		Kind: pipeline.FileChmod, PID: 700, UID: 0,
		Path: "/usr/bin/sudo", Mode: 0o4755,
		Timestamp: time.Unix(1, 0),
	}
	e.handleFile(context.Background(), raw)

	ev := <-e.out
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.File.Type != "mode:04755" {
		t.Errorf("file.type = %q, want mode:04755", fa.File.Type)
	}
}

func TestHandleFileFilterExcludes(t *testing.T) {
	e := newTestEnricher(t)
	e.fileFilter = newPathGlob([]string{"/etc/**"}, []string{"/etc/mtab"})

	// excluded even though it matches the include
	e.handleFile(context.Background(), pipeline.RawFileEvent{
		Kind: pipeline.FileOpenWrite, PID: 1, Path: "/etc/mtab",
		Timestamp: time.Unix(1, 0),
	})
	// outside include set
	e.handleFile(context.Background(), pipeline.RawFileEvent{
		Kind: pipeline.FileOpenWrite, PID: 1, Path: "/var/log/app.log",
		Timestamp: time.Unix(1, 0),
	})
	// allowed
	e.handleFile(context.Background(), pipeline.RawFileEvent{
		Kind: pipeline.FileOpenWrite, PID: 1, Path: "/etc/passwd",
		Timestamp: time.Unix(1, 0),
	})

	select {
	case ev := <-e.out:
		fa := ev.(*ocsf.FileSystemActivity)
		if fa.File.Path != "/etc/passwd" {
			t.Fatalf("emitted wrong event: %q", fa.File.Path)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("allowed event not emitted")
	}
	// And the other two must not show up.
	select {
	case ev := <-e.out:
		t.Fatalf("unexpected additional emission: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestResolvePathJoinsCwd(t *testing.T) {
	e := newTestEnricher(t)

	// Stage /proc/<pid>/cwd as a symlink to /var/log.
	procRoot := e.opts.ProcRoot
	pidDir := filepath.Join(procRoot, "1234")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/log", filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}

	got := e.resolvePath(1234, "app.log")
	if got != "/var/log/app.log" {
		t.Errorf("resolvePath = %q, want /var/log/app.log", got)
	}

	// Absolute paths pass through untouched.
	if got := e.resolvePath(1234, "/etc/passwd"); got != "/etc/passwd" {
		t.Errorf("absolute passthrough failed: %q", got)
	}
}

func TestHandleFileUnknownKindDropped(t *testing.T) {
	e := newTestEnricher(t)
	before := e.telem.Snapshot().EventsDropped
	e.handleFile(context.Background(), pipeline.RawFileEvent{
		Kind: pipeline.FileUnknown, PID: 1, Path: "/etc/passwd",
		Timestamp: time.Unix(1, 0),
	})
	if e.telem.Snapshot().EventsDropped != before+1 {
		t.Errorf("unknown-kind event did not bump drops")
	}
	select {
	case ev := <-e.out:
		t.Fatalf("unknown kind emitted: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}
}
