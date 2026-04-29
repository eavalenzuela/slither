//go:build linux

package respond

import pb "github.com/t3rmit3/slither/proto/gen/slither/v1"

// WireIsolationHandlers installs the Linux isolate_host and
// unisolate_host handlers on e. Both share AllowIsolate per ADR-0034
// (reverse actions inherit their forward's policy bit).
func WireIsolationHandlers(e *Executor) {
	if e == nil {
		return
	}
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_ISOLATE_HOST, IsolateHostHandler())
	e.SetHandler(pb.ResponseAction_RESPONSE_ACTION_UNISOLATE_HOST, UnisolateHostHandler())
}
