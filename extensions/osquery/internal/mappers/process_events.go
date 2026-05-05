package mappers

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// ProcessEvents maps osquery's process_events table (audit-driven
// exec/exit observations). One row = one OCSF ProcessActivity event.
//
// Schema reference (osquery 5.x):
//
//	pid, path, cmdline, ctime, atime, mtime, uid, gid, euid, egid, owner_uid,
//	parent (ppid), syscall ("execve" / "exit"), cwd, time, eid.
//
// We surface the action via syscall: execve → ProcessActivityLaunch,
// exit → ProcessActivityTerminate. Anything else falls through to
// ProcessActivityOther so downstream rules see the row even if the
// schema gains a new syscall verb.
func ProcessEvents(row Row) (ocsf.Event, error) {
	if err := requireField("pid", row["pid"]); err != nil {
		return nil, err
	}
	activity := ocsf.ProcessActivityOther
	switch row["syscall"] {
	case "execve", "execveat":
		activity = ocsf.ProcessActivityLaunch
	case "exit", "exit_group":
		activity = ocsf.ProcessActivityTerminate
	}
	pid := atoiU32(row["pid"])
	ppid := atoiU32(row["parent"])

	ev := &ocsf.ProcessActivity{
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: activity,
		Severity:   ocsf.SeverityInformational,
		Actor: ocsf.Actor{
			Process: ocsf.Process{
				PID:     pid,
				Cmdline: row["cmdline"],
				Name:    row["path"],
				File: &ocsf.File{
					Path: row["path"],
				},
			},
			User: ocsf.User{
				UID: row["uid"],
			},
		},
		Process: ocsf.Process{
			PID:     pid,
			Cmdline: row["cmdline"],
			Name:    row["path"],
			File: &ocsf.File{
				Path: row["path"],
			},
		},
	}
	if ppid != 0 {
		ev.Process.Parent = &ocsf.Process{PID: ppid}
		ev.Actor.Process.Parent = &ocsf.Process{PID: ppid}
	}
	return ev, nil
}
