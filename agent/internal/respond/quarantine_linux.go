//go:build linux

package respond

import pb "github.com/t3rmit3/slither/proto/gen/slither/v1"

// WireQuarantineHandlers installs the Linux quarantine_file handler
// on e. Same shape as WireKillHandlers — agent/internal/app calls it
// at startup. Reverse (un-quarantine) lands with #85 alongside the
// rest of the parent_action plumbing.
func WireQuarantineHandlers(e *Executor) {
	if e == nil {
		return
	}
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_QUARANTINE_FILE, QuarantineFileHandler())
}
