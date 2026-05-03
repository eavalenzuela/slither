package extensions

import (
	"bytes"
	"errors"
	"testing"

	"github.com/t3rmit3/slither/pkg/extsdk"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func TestChannel_AllowsDeclaredCapability(t *testing.T) {
	caps := []pb.Capability{pb.Capability_CAPABILITY_OCSF_EMIT}
	var buf bytes.Buffer
	// Pre-populate the buffer with a frame the channel will read.
	in := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_OcsfEvent{
			OcsfEvent: &pb.OCSFEvent{
				ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
				Payload: []byte(`{"class_uid":1007}`),
			},
		},
	}
	if err := extsdk.WriteExtensionToAgent(&buf, in); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ch := NewChannel(&buf, &buf, caps)
	out, err := ch.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if out.GetOcsfEvent() == nil {
		t.Fatalf("expected OcsfEvent payload, got %T", out.Payload)
	}
}

func TestChannel_RefusesUndeclaredCapability(t *testing.T) {
	// Extension declared LIVE_QUERY_RESPOND but tries to push an OCSF
	// event — must be refused with ErrCapabilityViolation.
	caps := []pb.Capability{pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND}
	var buf bytes.Buffer
	in := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_OcsfEvent{
			OcsfEvent: &pb.OCSFEvent{ClassId: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY},
		},
	}
	if err := extsdk.WriteExtensionToAgent(&buf, in); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ch := NewChannel(&buf, &buf, caps)
	_, err := ch.Recv()
	if !errors.Is(err, ErrCapabilityViolation) {
		t.Errorf("Recv: want ErrCapabilityViolation, got %v", err)
	}
}

func TestChannel_HelloAlwaysAllowed(t *testing.T) {
	// Hello has no capability gate — it's the message that establishes
	// the gate. Recv must accept it even when the channel was
	// constructed with an empty capability set.
	var buf bytes.Buffer
	in := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_Hello{
			Hello: &pb.Hello{Name: "test", Version: "v0"},
		},
	}
	if err := extsdk.WriteExtensionToAgent(&buf, in); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ch := NewChannel(&buf, &buf, nil)
	out, err := ch.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if out.GetHello() == nil {
		t.Errorf("expected Hello, got %T", out.Payload)
	}
}

func TestChannel_SendRefusesUndeclaredCapability(t *testing.T) {
	// Agent tries to send a SnapshotRequest to an extension that
	// declared only OCSF_EMIT. Must refuse without writing to the
	// underlying writer.
	caps := []pb.Capability{pb.Capability_CAPABILITY_OCSF_EMIT}
	var buf bytes.Buffer
	ch := NewChannel(&buf, &buf, caps)
	err := ch.Send(&pb.AgentToExtension{
		Payload: &pb.AgentToExtension_SnapshotRequest{
			SnapshotRequest: &pb.SnapshotRequest{SnapshotId: "snap-1"},
		},
	})
	if !errors.Is(err, ErrCapabilityViolation) {
		t.Errorf("Send: want ErrCapabilityViolation, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Send wrote %d bytes despite gate refusal", buf.Len())
	}
}

func TestCapabilityFromString_RoundTrip(t *testing.T) {
	cases := []struct {
		s string
		c pb.Capability
	}{
		{"ocsf_emit", pb.Capability_CAPABILITY_OCSF_EMIT},
		{"live_query_respond", pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND},
		{"snapshot_provide", pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE},
		{"bogus", pb.Capability_CAPABILITY_UNSPECIFIED},
	}
	for _, tc := range cases {
		got := CapabilityFromString(tc.s)
		if got != tc.c {
			t.Errorf("FromString(%q) = %v, want %v", tc.s, got, tc.c)
		}
		if tc.c != pb.Capability_CAPABILITY_UNSPECIFIED {
			if back := CapabilityToString(got); back != tc.s {
				t.Errorf("ToString(FromString(%q)) = %q", tc.s, back)
			}
		}
	}
}
