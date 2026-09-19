//go:build linux && integration

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
)

// TestCgroupCollector_MkdirRmdirObserved attaches cgroup.bpf.c and makes
// a container-shaped cgroup directly in cgroupfs, which is exactly what
// a runtime does; then removes it.
func TestCgroupCollector_MkdirRmdirObserved(t *testing.T) {
	requirePrivileged(t)
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		t.Skip("cgroup v2 not mounted at /sys/fs/cgroup")
	}
	id := strings.Repeat("ab", 32)
	dir := filepath.Join(root, "docker-"+id+".scope")

	out := make(chan pipeline.RawCgroupEvent, 256)
	c := newCgroupCollector(out, newCounters())
	_, stop := startCollector(t, c)
	defer stop()

	time.Sleep(200 * time.Millisecond)

	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir cgroup: %v", err)
	}
	defer os.Remove(dir)

	ev, ok := waitForEvent(t, out, func(e pipeline.RawCgroupEvent) bool {
		return e.Kind == pipeline.CgroupMkdir && strings.HasSuffix(e.Path, "docker-"+id+".scope")
	}, 3*time.Second)
	if !ok {
		t.Fatal("no cgroup_mkdir event within 3s")
	}
	if ev.Root != 0 || ev.ID == 0 {
		t.Errorf("mkdir event = %+v (want root 0 and a cgroup id)", ev)
	}

	if err := os.Remove(dir); err != nil {
		t.Fatalf("rmdir cgroup: %v", err)
	}
	if _, ok := waitForEvent(t, out, func(e pipeline.RawCgroupEvent) bool {
		return e.Kind == pipeline.CgroupRmdir && e.ID == ev.ID
	}, 3*time.Second); !ok {
		t.Fatal("no cgroup_rmdir event within 3s")
	}
}
