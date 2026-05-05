package mappers

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// FileEvents maps osquery's file_events table (inotify/FANotify-driven
// path watches; rows arrive only for paths the operator configured
// under file_paths). One row = one OCSF FileSystemActivity.
//
// Schema reference (osquery 5.x):
//
//	target_path, category, action ("CREATED"/"UPDATED"/"DELETED"/"MOVED_FROM"/...),
//	transaction_id, inode, uid, gid, mode, size, atime, mtime, ctime,
//	md5, sha1, sha256, hashed, time, eid.
//
// action → activity_id mapping covers CREATE/UPDATE/DELETE/RENAME with
// MOVED_FROM/MOVED_TO mapping into Rename. Anything we don't recognise
// becomes FileActivityOther so downstream rule authors aren't blocked
// by osquery's schema additions.
func FileEvents(row Row) (ocsf.Event, error) {
	if err := requireField("target_path", row["target_path"]); err != nil {
		return nil, err
	}
	action := row["action"]
	activity := ocsf.FileActivityOther
	var renameTo *ocsf.File
	switch action {
	case "CREATED", "ADDED":
		activity = ocsf.FileActivityCreate
	case "UPDATED", "ATTRIBUTES_MODIFIED":
		activity = ocsf.FileActivityUpdate
	case "DELETED":
		activity = ocsf.FileActivityDelete
	case "MOVED_FROM", "MOVED_TO":
		// osquery emits one row per side; we represent both as Rename
		// with the surviving path on the appropriate side.
		activity = ocsf.FileActivityRename
		renameTo = &ocsf.File{Path: row["target_path"]}
	case "OPENED":
		activity = ocsf.FileActivityOpen
	}

	ev := &ocsf.FileSystemActivity{
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: activity,
		Severity:   ocsf.SeverityInformational,
		Actor: ocsf.Actor{
			User: ocsf.User{UID: row["uid"]},
		},
		File: ocsf.File{
			Path:         row["target_path"],
			Size:         atoiU64(row["size"]),
			HashesSHA256: row["sha256"],
		},
		RenameTo: renameTo,
	}
	return ev, nil
}
