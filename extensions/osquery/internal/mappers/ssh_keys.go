package mappers

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// SSHKeys maps osquery's ssh_keys table (private keys discovered under
// each user's ~/.ssh/). Each row becomes one
// FileSystemActivity{Open} so rule authors can detect new private
// keys appearing under unexpected uids.
//
// Schema reference (osquery 5.x):
//
//	uid (the user's uid the key belongs to), path, encrypted.
//
// Encrypted-vs-not is surfaced via Severity: an unencrypted private
// key is a higher-noise signal than an encrypted one, so unencrypted
// rows ride at SeverityLow vs Informational for encrypted.
func SSHKeys(row Row) (ocsf.Event, error) {
	if err := requireField("path", row["path"]); err != nil {
		return nil, err
	}
	severity := ocsf.SeverityInformational
	if row["encrypted"] == "0" {
		severity = ocsf.SeverityLow
	}
	ev := &ocsf.FileSystemActivity{
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: ocsf.FileActivityOpen,
		Severity:   severity,
		Actor: ocsf.Actor{
			User: ocsf.User{UID: row["uid"]},
		},
		File: ocsf.File{
			Path: row["path"],
			Type: "ssh_private_key",
		},
	}
	return ev, nil
}
