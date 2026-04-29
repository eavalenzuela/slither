//go:build linux

package respond

import pb "github.com/t3rmit3/slither/proto/gen/slither/v1"

// WireKillHandlers installs the Linux kill_process / kill_tree
// handlers on e. Called from agent/internal/app at startup. macOS /
// Windows agents (post-v1.0 per project_windows_post_v1.md memory)
// will ship their own kill_$os.go with the same WireKillHandlers
// signature and the build-tag guard switches at compile time.
func WireKillHandlers(e *Executor) {
	if e == nil {
		return
	}
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS, KillProcessHandler())
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_KILL_PROCESS_TREE, KillTreeHandler())
}
