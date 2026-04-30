//go:build linux

package respond

import pb "github.com/t3rmit3/slither/proto/gen/slither/v1"

// WireCollectHandlers installs the Linux collect_artifacts handler
// on e. Phase 4 #81.
func WireCollectHandlers(e *Executor) {
	if e == nil {
		return
	}
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_COLLECT_ARTIFACTS, CollectArtifactsHandler())
}
