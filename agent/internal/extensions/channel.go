package extensions

import (
	"errors"
	"fmt"
	"io"

	"github.com/t3rmit3/slither/pkg/extsdk"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Channel is the bidirectional length-delimited protobuf wire that
// carries AgentToExtension and ExtensionToAgent envelopes between the
// supervisor and one extension process. Reads and writes are
// independent goroutines on the supervisor side; Channel itself is a
// thin layer over the codec helpers in pkg/extsdk that adds capability-
// gate enforcement.
//
// Capability gating is one-direction-strict: the supervisor refuses to
// forward AgentToExtension envelopes whose payload kind requires a
// capability the extension didn't declare on Hello, AND refuses to
// accept ExtensionToAgent envelopes whose payload kind requires one
// the extension didn't declare. Either violation is fatal to the
// connection — the supervisor closes the channel, ticks
// ext_capability_violations, and lets the supervisor restart with
// backoff.
type Channel struct {
	r            io.Reader
	w            io.Writer
	capabilities map[pb.Capability]struct{}
}

// NewChannel wraps the read + write halves of the unix socket.
// capabilities seeds the gate with the post-Hello allow list (i.e.
// the operator's authorised set ∩ what the extension declared).
func NewChannel(r io.Reader, w io.Writer, capabilities []pb.Capability) *Channel {
	set := make(map[pb.Capability]struct{}, len(capabilities))
	for _, c := range capabilities {
		set[c] = struct{}{}
	}
	return &Channel{r: r, w: w, capabilities: set}
}

// ErrCapabilityViolation is returned by Send / Recv when the envelope's
// payload kind requires a capability not in the channel's allow list.
// The supervisor maps this to ext_capability_violations + connection
// teardown.
var ErrCapabilityViolation = errors.New("extensions: capability violation")

// Send writes m to the extension. Refuses to send envelopes whose
// payload kind is gated on a capability the extension did not declare.
func (c *Channel) Send(m *pb.AgentToExtension) error {
	if err := c.gateAgentToExtension(m); err != nil {
		return err
	}
	return extsdk.WriteAgentToExtension(c.w, m)
}

// Recv reads one envelope from the extension. Refuses envelopes whose
// payload kind is gated on a capability not in the allow list.
func (c *Channel) Recv() (*pb.ExtensionToAgent, error) {
	m, err := extsdk.ReadExtensionToAgent(c.r)
	if err != nil {
		return nil, err
	}
	if err := c.gateExtensionToAgent(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Channel) gateAgentToExtension(m *pb.AgentToExtension) error {
	switch m.Payload.(type) {
	case *pb.AgentToExtension_LiveQueryRequest:
		return c.requireCapability(pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND)
	case *pb.AgentToExtension_SnapshotRequest:
		return c.requireCapability(pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE)
	}
	return nil
}

func (c *Channel) gateExtensionToAgent(m *pb.ExtensionToAgent) error {
	switch m.Payload.(type) {
	case *pb.ExtensionToAgent_Hello:
		// Hello has no capability gate — it's the message that
		// establishes the gate. Caller policy is to refuse Hello
		// after the first one, but that's at a higher layer.
		return nil
	case *pb.ExtensionToAgent_OcsfEvent:
		return c.requireCapability(pb.Capability_CAPABILITY_OCSF_EMIT)
	case *pb.ExtensionToAgent_LiveQueryRow,
		*pb.ExtensionToAgent_LiveQueryComplete:
		return c.requireCapability(pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND)
	case *pb.ExtensionToAgent_SnapshotChunk,
		*pb.ExtensionToAgent_SnapshotComplete:
		return c.requireCapability(pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE)
	}
	return nil
}

func (c *Channel) requireCapability(want pb.Capability) error {
	if _, ok := c.capabilities[want]; ok {
		return nil
	}
	return fmt.Errorf("%w: %s not declared on Hello", ErrCapabilityViolation, want)
}

// CapabilityFromString maps an operator-facing YAML capability string
// onto the proto enum. Returns CAPABILITY_UNSPECIFIED for unknown
// strings — config validation should have rejected those before the
// supervisor sees them.
func CapabilityFromString(s string) pb.Capability {
	switch s {
	case "ocsf_emit":
		return pb.Capability_CAPABILITY_OCSF_EMIT
	case "live_query_respond":
		return pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND
	case "snapshot_provide":
		return pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE
	}
	return pb.Capability_CAPABILITY_UNSPECIFIED
}

// CapabilityToString reverses CapabilityFromString for log/audit messages.
func CapabilityToString(c pb.Capability) string {
	switch c {
	case pb.Capability_CAPABILITY_OCSF_EMIT:
		return "ocsf_emit"
	case pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND:
		return "live_query_respond"
	case pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE:
		return "snapshot_provide"
	}
	return "unspecified"
}
