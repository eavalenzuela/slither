package enricher

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

const cid = "21473fb59dd89a9b9cff0ad8a1ceb82168feb3fc0ea41055565c26bd634bb4bd"

func TestParseContainerCgroup(t *testing.T) {
	cases := []struct {
		path        string
		id, runtime string
		own, ok     bool
	}{
		{"/system.slice/docker-" + cid + ".scope", cid, "docker", true, true},
		{"/docker/" + cid, cid, "docker", true, true},
		{"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-" + cid + ".scope", cid, "containerd", true, true},
		{"/kubepods/burstable/podabc/" + cid, cid, "containerd", true, true},
		{"/system.slice/crio-" + cid + ".scope", cid, "cri-o", true, true},
		{"/machine.slice/libpod-" + cid + ".scope", cid, "podman", true, true},
		{"/machine.slice/libpod-conmon-" + cid + ".scope", "", "", false, false},
		{"/system.slice/containerd-" + cid + ".scope", cid, "containerd", true, true},
		{"/lxc.payload.web1", "web1", "lxc", true, true},
		{"/machine.slice/machine-vm1.scope", "vm1", "nspawn", true, true},
		// Nested inside a container: maps to the container, but is not its own cgroup.
		{"/system.slice/docker-" + cid + ".scope/init.scope", cid, "docker", false, true},
		// Not containers.
		{"/system.slice/sshd.service", "", "", false, false},
		{"/user.slice/user-1000.slice/session-3.scope", "", "", false, false},
		{"/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice", "", "", false, false},
		{"/" + cid, "", "", false, false}, // bare id with no runtime marker anywhere
	}
	for _, c := range cases {
		id, rt, own, ok := parseContainerCgroup(c.path)
		if id != c.id || rt != c.runtime || own != c.own || ok != c.ok {
			t.Errorf("%s → (%q, %q, %v, %v), want (%q, %q, %v, %v)", c.path, id, rt, own, ok, c.id, c.runtime, c.own, c.ok)
		}
	}
}

// TestContainerIndexSeedFromCgroupfs — a pre-existing container is known
// after seeding, keyed by its directory inode, and is already "started".
func TestContainerIndexSeedFromCgroupfs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "system.slice", "docker-"+cid+".scope")
	if err := os.MkdirAll(filepath.Join(dir, "init.scope"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "sshd.service"), 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino

	idx := newContainerIndex()
	if n := idx.seed(root); n != 1 {
		t.Fatalf("seeded %d containers, want 1", n)
	}
	if got, ok := idx.lookup(ino); !ok || got != cid {
		t.Errorf("lookup(%d) = %q, %v", ino, got, ok)
	}
	if _, started := idx.markStarted(cid); started {
		t.Error("a pre-existing container must already count as started")
	}
	if _, ok := idx.lookup(0); ok {
		t.Error("cgroup id 0 must never resolve")
	}
}

func TestContainerLifecycleEndToEnd(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{pid: 300, uid: 0, comm: "containerd-shim", exe: "/usr/bin/containerd-shim-runc-v2"})

	// create
	e.handleCgroup(context.Background(), pipeline.RawCgroupEvent{
		Kind: pipeline.CgroupMkdir, PID: 300, UID: 0, Root: 0, ID: 777,
		Path: "/system.slice/docker-" + cid + ".scope", Comm: "containerd-shim", Timestamp: time.Unix(10, 0),
	})
	ev := (<-e.out).(*ocsf.ContainerLifecycle)
	if err := ev.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ev.ActivityID != ocsf.ContainerActivityCreate || ev.Metadata.EventCode != "container_create" || ev.TypeUID != 600001 {
		t.Errorf("create = %+v", ev)
	}
	if ev.Container.UID != cid || ev.Container.Runtime != "docker" || ev.Container.CgroupID != 777 || ev.Container.CgroupPath != "/system.slice/docker-"+cid+".scope" {
		t.Errorf("container = %+v", ev.Container)
	}
	if ev.Actor.Process.File == nil || ev.Actor.Process.File.Path != "/usr/bin/containerd-shim-runc-v2" {
		t.Errorf("actor = %+v", ev.Actor.Process)
	}

	// a nested cgroup inside it: mapped, no event
	e.handleCgroup(context.Background(), pipeline.RawCgroupEvent{
		Kind: pipeline.CgroupMkdir, PID: 300, Root: 0, ID: 778,
		Path: "/system.slice/docker-" + cid + ".scope/init.scope", Timestamp: time.Unix(10, 0),
	})
	select {
	case ev := <-e.out:
		t.Fatalf("nested cgroup must not emit: %+v", ev)
	default:
	}
	if got, ok := e.containers.lookup(778); !ok || got != cid {
		t.Errorf("nested cgroup should map to the container: %q %v", got, ok)
	}

	// first exec inside the cgroup → start, then the process event, stamped
	e.handleProcess(context.Background(), pipeline.RawProcessEvent{
		Kind: pipeline.ProcExec, PID: 301, PPID: 300, UID: 0, Comm: "sh", Exe: "/bin/sh", Cmdline: "sh -c app",
		CgroupID: 777, Timestamp: time.Unix(11, 0),
	})
	start := (<-e.out).(*ocsf.ContainerLifecycle)
	if start.ActivityID != ocsf.ContainerActivityStart || start.Metadata.EventCode != "container_start" || start.Actor.Process.PID != 301 {
		t.Errorf("start = %+v", start)
	}
	proc := (<-e.out).(*ocsf.ProcessActivity)
	if proc.Process.ContainerID != cid {
		t.Errorf("process event not stamped with the container: %+v", proc.Process)
	}

	// second exec: no second start
	e.handleProcess(context.Background(), pipeline.RawProcessEvent{
		Kind: pipeline.ProcExec, PID: 302, PPID: 301, UID: 0, Comm: "app", Exe: "/app", Cmdline: "/app",
		CgroupID: 778, Timestamp: time.Unix(12, 0),
	})
	proc2 := (<-e.out).(*ocsf.ProcessActivity)
	if proc2.Process.ContainerID != cid {
		t.Errorf("nested-cgroup process not stamped: %+v", proc2.Process)
	}

	// exit of that process still carries the container from the cache
	e.handleProcess(context.Background(), pipeline.RawProcessEvent{
		Kind: pipeline.ProcExit, PID: 302, Timestamp: time.Unix(13, 0),
	})
	exit := (<-e.out).(*ocsf.ProcessActivity)
	if exit.Process.ContainerID != cid {
		t.Errorf("exit event lost the container: %+v", exit.Process)
	}

	// stop
	e.handleCgroup(context.Background(), pipeline.RawCgroupEvent{
		Kind: pipeline.CgroupRmdir, PID: 300, Root: 0, ID: 777,
		Path: "/system.slice/docker-" + cid + ".scope", Timestamp: time.Unix(20, 0),
	})
	stop := (<-e.out).(*ocsf.ContainerLifecycle)
	if stop.ActivityID != ocsf.ContainerActivityStop || stop.Metadata.EventCode != "container_stop" || stop.Container.UID != cid {
		t.Errorf("stop = %+v", stop)
	}
	if _, ok := e.containers.lookup(777); ok {
		t.Error("stopped container's cgroup id must be forgotten")
	}
	// rmdir of an unknown cgroup: silent
	e.handleCgroup(context.Background(), pipeline.RawCgroupEvent{Kind: pipeline.CgroupRmdir, Root: 0, ID: 999, Path: "/system.slice/x.service"})
	select {
	case ev := <-e.out:
		t.Fatalf("unknown rmdir must not emit: %+v", ev)
	default:
	}
}

// TestContainerV1HierarchyDedupes — on cgroup v1 the same container's
// mkdir fires once per controller with per-hierarchy ids: one create
// event, and none of the v1 ids enter the process map.
func TestContainerV1HierarchyDedupes(t *testing.T) {
	e := newTestEnricher(t)
	for i, root := range []int32{1, 2, 3} {
		e.handleCgroup(context.Background(), pipeline.RawCgroupEvent{
			Kind: pipeline.CgroupMkdir, PID: 1, Root: root, ID: uint64(100 + i),
			Path: "/docker/" + cid, Timestamp: time.Unix(1, 0),
		})
	}
	if ev := (<-e.out).(*ocsf.ContainerLifecycle); ev.Container.UID != cid || ev.Container.CgroupID != 0 {
		t.Errorf("first v1 mkdir should create with no v2 cgroup id: %+v", ev.Container)
	}
	select {
	case ev := <-e.out:
		t.Fatalf("v1 duplicates must not emit: %+v", ev)
	default:
	}
	if _, ok := e.containers.lookup(100); ok {
		t.Error("v1 hierarchy ids must not map to containers")
	}
}
