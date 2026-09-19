package enricher

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// containerCgroupRE picks the container id out of one cgroup path
// component. Every mainstream runtime names the container's own cgroup
// after its 64-hex id, with a runtime-specific prefix:
//
//	docker-<id>.scope            docker, systemd cgroup driver
//	<id>                          docker / containerd, cgroupfs driver (under /docker or /kubepods...)
//	cri-containerd-<id>.scope    containerd CRI (kubernetes)
//	crio-<id>.scope              cri-o
//	libpod-<id>.scope            podman (libpod-conmon-<id>.scope is the monitor, not the container)
//	containerd-<id>.scope        nerdctl / plain containerd with the systemd driver
//
// LXC (`lxc.payload.<name>`) and systemd-nspawn (`machine-<name>.scope`)
// name by machine name rather than id and are matched separately.
var containerCgroupRE = regexp.MustCompile(`^(?:(docker|cri-containerd|crio|libpod|containerd)-)?([0-9a-f]{64})(?:\.scope)?$`)

var machineCgroupRE = regexp.MustCompile(`^(?:lxc\.payload\.(.+)|machine-(.+)\.scope)$`)

// parseContainerCgroup returns the container id and runtime encoded in a
// cgroup path, plus whether the LAST component is the container's own
// cgroup (as opposed to a cgroup nested inside it, such as systemd's
// init.scope inside a container). ok is false for paths that are not
// under any container.
func parseContainerCgroup(path string) (id, runtime string, own, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasPrefix(p, "libpod-conmon-") {
			continue
		}
		if m := containerCgroupRE.FindStringSubmatch(p); m != nil {
			rt := m[1]
			if rt == "" {
				rt = runtimeFromAncestors(parts[:i])
				if rt == "" {
					// A bare 64-hex component with no runtime marker
					// anywhere above it is not something we recognise.
					continue
				}
			}
			return m[2], normaliseRuntime(rt), i == len(parts)-1, true
		}
		if m := machineCgroupRE.FindStringSubmatch(p); m != nil {
			name := m[1]
			rt := "lxc"
			if name == "" {
				name = m[2]
				rt = "nspawn"
			}
			return name, rt, i == len(parts)-1, true
		}
	}
	return "", "", false, false
}

// runtimeFromAncestors infers the runtime for a bare-id cgroup from the
// parents that the cgroupfs-driver layouts use.
func runtimeFromAncestors(ancestors []string) string {
	for _, a := range ancestors {
		switch {
		case a == "docker":
			return "docker"
		case strings.HasPrefix(a, "kubepods"):
			return "containerd"
		case a == "machine.slice" || a == "libpod_parent":
			return "podman"
		}
	}
	return ""
}

func normaliseRuntime(rt string) string {
	switch rt {
	case "cri-containerd":
		return "containerd"
	case "libpod":
		return "podman"
	case "crio":
		return "cri-o"
	}
	return rt
}

type containerState struct {
	id         string
	runtime    string
	cgroupPath string
	cgroupID   uint64
	started    bool
}

// containerIndex is the enricher's view of live containers: cgroup v2 id
// → container id for stamping process events, and per-container state
// for the lifecycle events. Shared between the main loop (cgroup events)
// and the process workers (exec stamping), hence the lock.
type containerIndex struct {
	mu       sync.RWMutex
	byCgroup map[uint64]string
	known    map[string]*containerState
}

func newContainerIndex() *containerIndex {
	return &containerIndex{
		byCgroup: make(map[uint64]string),
		known:    make(map[string]*containerState),
	}
}

// seed walks an existing cgroup v2 mount so containers that predate the
// agent are known: their cgroup id is the directory inode. Pre-existing
// containers are marked started, since their first exec is long gone.
func (c *containerIndex) seed(cgroupRoot string) int {
	n := 0
	_ = filepath.WalkDir(cgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(cgroupRoot, p)
		if rerr != nil || rel == "." {
			return nil
		}
		id, rt, own, ok := parseContainerCgroup("/" + filepath.ToSlash(rel))
		if !ok {
			return nil
		}
		info, serr := os.Stat(p)
		if serr != nil {
			return nil
		}
		st, sok := info.Sys().(*syscall.Stat_t)
		if !sok {
			return nil
		}
		c.mu.Lock()
		c.byCgroup[st.Ino] = id
		if own {
			if _, seen := c.known[id]; !seen {
				c.known[id] = &containerState{id: id, runtime: rt, cgroupPath: "/" + filepath.ToSlash(rel), cgroupID: st.Ino, started: true}
				n++
			}
		}
		c.mu.Unlock()
		return nil
	})
	return n
}

func (c *containerIndex) lookup(cgroupID uint64) (string, bool) {
	if cgroupID == 0 {
		return "", false
	}
	c.mu.RLock()
	id, ok := c.byCgroup[cgroupID]
	c.mu.RUnlock()
	return id, ok
}

// created records a cgroup mkdir. It returns the container state when
// this mkdir is a container's own cgroup that was not known before —
// i.e. exactly when a create event should be emitted.
func (c *containerIndex) created(raw pipeline.RawCgroupEvent) (*containerState, bool) {
	id, rt, own, ok := parseContainerCgroup(raw.Path)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if raw.Root == 0 {
		c.byCgroup[raw.ID] = id
	}
	if !own {
		return nil, false
	}
	if _, seen := c.known[id]; seen {
		return nil, false
	}
	st := &containerState{id: id, runtime: rt, cgroupPath: raw.Path}
	if raw.Root == 0 {
		st.cgroupID = raw.ID
	}
	c.known[id] = st
	return st, true
}

// removed records a cgroup rmdir. It returns the container state when
// the removed cgroup was a known container's own cgroup.
func (c *containerIndex) removed(raw pipeline.RawCgroupEvent) (*containerState, bool) {
	id, _, own, ok := parseContainerCgroup(raw.Path)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if raw.Root == 0 {
		delete(c.byCgroup, raw.ID)
	}
	if !own {
		return nil, false
	}
	st, seen := c.known[id]
	if !seen {
		return nil, false
	}
	delete(c.known, id)
	return st, true
}

// markStarted flips a container to started on its first observed exec.
// Returns the state exactly once per container.
func (c *containerIndex) markStarted(id string) (*containerState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.known[id]
	if !ok || st.started {
		return nil, false
	}
	st.started = true
	return st, true
}

// handleCgroup turns cgroup directory events into container create /
// stop events. The actor is the runtime process that made the cgroup
// (runc, containerd-shim, crun, conmon).
func (e *enricher) handleCgroup(ctx context.Context, raw pipeline.RawCgroupEvent) {
	switch raw.Kind {
	case pipeline.CgroupMkdir:
		if st, ok := e.containers.created(raw); ok {
			e.emitContainer(ctx, ocsf.ContainerActivityCreate, "container_create", st, e.actorEntry(raw.PID, raw.UID, raw.Comm), raw.Timestamp)
		}
	case pipeline.CgroupRmdir:
		if st, ok := e.containers.removed(raw); ok {
			e.emitContainer(ctx, ocsf.ContainerActivityStop, "container_stop", st, e.actorEntry(raw.PID, raw.UID, raw.Comm), raw.Timestamp)
		}
	default:
		e.telem.IncDrops()
	}
}

// actorEntry resolves a pid through the cache with the BPF-supplied
// identity as the fallback.
func (e *enricher) actorEntry(pid, uid uint32, comm string) procEntry {
	ent, ok := e.cache.get(pid)
	if !ok {
		ent = procEntry{pid: pid, uid: uid, comm: comm}
		if exe := e.proc.exe(pid); exe != "" {
			ent.exe = exe
		}
	}
	if ent.comm == "" {
		ent.comm = comm
	}
	return ent
}

func (e *enricher) emitContainer(ctx context.Context, activity ocsf.ContainerActivityID, code string, st *containerState, actor procEntry, at time.Time) {
	ev := e.buildContainerOCSF(activity, code, st, actor, at)
	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDropEnricher()
	}
}

func (e *enricher) buildContainerOCSF(activity ocsf.ContainerActivityID, code string, st *containerState, actor procEntry, at time.Time) *ocsf.ContainerLifecycle {
	username := e.users.Name(actor.uid)
	actorProc := processFromEntry(actor, username)
	ts := at.UnixMilli()
	return &ocsf.ContainerLifecycle{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "container",
			EventCode: code,
			UID:       ocsf.NewUID(),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassContainerLifecycle,
		ClassName:  ocsf.ClassContainerLifecycle.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassContainerLifecycle)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor: ocsf.Actor{
			Process: *actorProc,
			User: ocsf.User{
				UID:  actorProc.UID,
				Name: username,
				Type: userType(actor.uid),
			},
		},
		Container: ocsf.Container{
			UID:        st.id,
			Runtime:    st.runtime,
			CgroupPath: st.cgroupPath,
			CgroupID:   st.cgroupID,
		},
	}
}
