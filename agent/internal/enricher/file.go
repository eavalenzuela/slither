package enricher

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// handleFile converts a raw file syscall event into an OCSF FileSystemActivity
// and emits it on the enricher output channel. Actor identity is resolved via
// the same process cache the process path populates, so correlation with
// exec/fork is free when both events have been seen.
func (e *enricher) handleFile(ctx context.Context, raw pipeline.RawFileEvent) {
	if raw.Kind == pipeline.FileUnknown {
		e.telem.IncDrops()
		return
	}

	path := e.resolvePath(raw.PID, raw.Path)
	newPath := ""
	if raw.NewPath != "" {
		newPath = e.resolvePath(raw.PID, raw.NewPath)
	}

	// Path filter is evaluated post-resolution so `/etc/**`-style rules work
	// for both absolute-at-syscall and relative-resolved-via-cwd paths. We
	// only require one of (path, newPath) to pass the filter; rename to a
	// watched directory is as interesting as rename out of one.
	if !e.fileFilter.allow(path) && (newPath == "" || !e.fileFilter.allow(newPath)) {
		return
	}

	ent, ok := e.cache.get(raw.PID)
	if !ok {
		// Best-effort fill from /proc for a process we haven't seen an exec
		// for (agent started mid-lifetime). A zero-only entry still yields
		// a valid event; Actor.Process keeps the pid for correlation.
		ent = procEntry{pid: raw.PID, uid: raw.UID}
		if comm := e.proc.comm(raw.PID); comm != "" {
			ent.comm = comm
		}
		if exe := e.proc.exe(raw.PID); exe != "" {
			ent.exe = exe
		}
	}

	ev := e.buildFileOCSF(raw, ent, path, newPath)

	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDrops()
	}
}

// resolvePath absolutises rawPath against /proc/<pid>/cwd when it isn't
// already absolute. Relative paths at syscall-entry are common when the
// caller passes AT_FDCWD with a relative arg; resolving them server-side
// would require carrying the dfd map, which is out of Phase 1 scope.
func (e *enricher) resolvePath(pid uint32, rawPath string) string {
	if rawPath == "" || strings.HasPrefix(rawPath, "/") {
		return rawPath
	}
	cwd := e.proc.cwd(pid)
	if cwd == "" {
		return rawPath
	}
	return filepath.Join(cwd, rawPath)
}

func (e *enricher) buildFileOCSF(raw pipeline.RawFileEvent, ent procEntry, path, newPath string) *ocsf.FileSystemActivity {
	username := e.users.Name(ent.uid)
	actorProc := processFromEntry(ent, username)

	activity := fileActivityID(raw.Kind)
	ts := raw.Timestamp.UnixMilli()

	file := ocsf.File{Path: path, Name: filepath.Base(path)}
	if raw.Kind == pipeline.FileChmod {
		// OCSF File carries no mode field in Phase 1 shape; stash the numeric
		// mode into Type so rule packs that key on chmod decisions have
		// something to match. Cheap, and loseless at octal granularity.
		file.Type = "mode:0" + strconv.FormatUint(uint64(raw.Mode), 8)
	}

	ev := &ocsf.FileSystemActivity{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "file",
			EventCode: fileEventCode(raw.Kind),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassFileSystemActivity)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor: ocsf.Actor{
			Process: *actorProc,
			User: ocsf.User{
				UID:  actorProc.UID,
				Name: username,
				Type: userType(ent.uid),
			},
		},
		File: file,
	}
	if raw.Kind == pipeline.FileRename && newPath != "" {
		ev.RenameTo = &ocsf.File{Path: newPath, Name: filepath.Base(newPath)}
	}
	return ev
}

// fileActivityID maps raw kinds onto OCSF 1001 activity_id values.
func fileActivityID(k pipeline.RawFileKind) ocsf.FileSystemActivityID {
	switch k {
	case pipeline.FileOpenCreate:
		return ocsf.FileActivityCreate
	case pipeline.FileOpenWrite:
		return ocsf.FileActivityUpdate
	case pipeline.FileUnlink:
		return ocsf.FileActivityDelete
	case pipeline.FileRename:
		return ocsf.FileActivityRename
	case pipeline.FileChmod:
		return ocsf.FileActivitySetAttr
	case pipeline.FileChown:
		return ocsf.FileActivitySetOwner
	default:
		return ocsf.FileActivityOther
	}
}

func fileEventCode(k pipeline.RawFileKind) string {
	switch k {
	case pipeline.FileOpenCreate:
		return "open_create"
	case pipeline.FileOpenWrite:
		return "open_write"
	case pipeline.FileUnlink:
		return "unlink"
	case pipeline.FileRename:
		return "rename"
	case pipeline.FileChmod:
		return "chmod"
	case pipeline.FileChown:
		return "chown"
	default:
		return "unknown"
	}
}
