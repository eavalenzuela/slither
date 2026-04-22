package enricher

import (
	"path/filepath"
	"strconv"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// slitherProduct is stamped into every emitted OCSF event's metadata so
// downstream consumers can distinguish slither output without relying on
// transport framing.
func slitherProduct() ocsf.Product {
	return ocsf.Product{
		Name:       "slither-agent",
		VendorName: "slither",
		Version:    "0.0.0-dev",
		Language:   "en",
	}
}

// activityID maps the raw BPF kind to the OCSF 1007 activity enum. Fork and
// exec both carry activity_id=1 (Launch) — the distinction is preserved in
// metadata.event_code so rules can key on it without losing OCSF shape.
func activityID(k pipeline.RawProcessKind) ocsf.ProcessActivityID {
	switch k {
	case pipeline.ProcExec, pipeline.ProcFork:
		return ocsf.ProcessActivityLaunch
	case pipeline.ProcExit:
		return ocsf.ProcessActivityTerminate
	default:
		return ocsf.ProcessActivityOther
	}
}

func eventCode(k pipeline.RawProcessKind) string {
	switch k {
	case pipeline.ProcExec:
		return "exec"
	case pipeline.ProcFork:
		return "fork"
	case pipeline.ProcExit:
		return "exit"
	default:
		return "unknown"
	}
}

// userType picks the OCSF `user.type` enum value based on effective uid. The
// OCSF spec enumerates User / Admin / System / Other; root → Admin is the
// cheapest useful signal at this stage.
func userType(uid uint32) string {
	if uid == 0 {
		return "Admin"
	}
	return "User"
}

// labelFollowup tags an event as a deferred enrichment of a prior event. The
// rule engine short-circuits on this label so followups don't double-fire
// rules that already evaluated against the original.
const labelFollowup = "followup"

// buildHashFollowup emits a minimal ProcessActivity that carries the SHA-256
// of the original event's executable. It reuses the original's device, actor,
// and process identity; Metadata.CorrelationUID links back to the original's
// UID so the collector can stitch hash onto the in-DB event.
func buildHashFollowup(orig *ocsf.ProcessActivity, hash string) *ocsf.ProcessActivity {
	proc := orig.Process
	if proc.File != nil {
		f := *proc.File
		f.HashesSHA256 = hash
		proc.File = &f
	}
	return &ocsf.ProcessActivity{
		Metadata: ocsf.Metadata{
			Version:        ocsf.Version,
			Product:        orig.Metadata.Product,
			LogName:        orig.Metadata.LogName,
			EventCode:      "hash_followup",
			Labels:         []string{labelFollowup},
			UID:            ocsf.NewUID(),
			CorrelationUID: orig.Metadata.UID,
			OriginalT:      orig.Metadata.OriginalT,
		},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: orig.ActivityID,
		TypeUID:    orig.TypeUID,
		Severity:   orig.Severity,
		Time:       orig.Time,
		Device:     orig.Device,
		Actor:      orig.Actor,
		Process:    proc,
	}
}

// processFromEntry projects a cache entry into the OCSF Process field group.
// The parent chain is filled in by the caller to avoid duplicating the
// depth-bounded walk here.
func processFromEntry(ent procEntry, username string) *ocsf.Process {
	p := &ocsf.Process{
		PID:     ent.pid,
		UID:     strconv.FormatUint(uint64(ent.uid), 10),
		Name:    ent.comm,
		Cmdline: ent.cmdline,
	}
	if !ent.createdAt.IsZero() {
		p.CreatedT = ocsf.TimeOCSF(ent.createdAt.UnixMilli())
	}
	if ent.exe != "" {
		p.File = &ocsf.File{Path: ent.exe, Name: filepath.Base(ent.exe)}
	}
	p.User = &ocsf.User{
		UID:  strconv.FormatUint(uint64(ent.uid), 10),
		Name: username,
		Type: userType(ent.uid),
	}
	return p
}
