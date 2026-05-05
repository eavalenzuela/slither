package mappers

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// AuthorizedKeys maps osquery's authorized_keys table — every entry in
// every user's ~/.ssh/authorized_keys file. Each row becomes one
// FileSystemActivity{Open} so rule authors can detect new entries
// (the rule engine's job to dedup against last-seen state).
//
// Schema reference (osquery 5.x):
//
//	uid, algorithm, key, key_file, comment.
//
// We promote the key_file path into File.Path and stash the SSH key's
// algorithm into File.Type so detections like "ed25519 added to
// root's authorized_keys" remain expressible.
func AuthorizedKeys(row Row) (ocsf.Event, error) {
	if err := requireField("key_file", row["key_file"]); err != nil {
		return nil, err
	}
	algo := row["algorithm"]
	if algo == "" {
		algo = "authorized_key"
	}
	ev := &ocsf.FileSystemActivity{
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: ocsf.FileActivityOpen,
		Severity:   ocsf.SeverityInformational,
		Actor: ocsf.Actor{
			User: ocsf.User{UID: row["uid"]},
		},
		File: ocsf.File{
			Path: row["key_file"],
			Type: algo,
		},
	}
	return ev, nil
}
