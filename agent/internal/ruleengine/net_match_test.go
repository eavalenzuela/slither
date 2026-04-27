package ruleengine

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

const netConnectSigma = `title: Connection to suspicious port
id: 44444444-4444-4444-8444-444444444444
level: medium
logsource:
  product: linux
  category: network_connection
detection:
  sel:
    DestinationPort: 4444
    Protocol: tcp
  condition: sel
`

func netActivityFixture(proto, dstIP string, dstPort uint16, exe string) *ocsf.NetworkActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.NetworkActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-n"},
		ClassUID:   ocsf.ClassNetworkActivity,
		ClassName:  ocsf.ClassNetworkActivity.String(),
		ActivityID: ocsf.NetActivityOpen,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor: ocsf.Actor{
			Process: ocsf.Process{
				PID: 4321, Name: "nc",
				File: &ocsf.File{Path: exe, Name: "nc"},
			},
			User: ocsf.User{Name: "root", UID: "0", Type: "Admin"},
		},
		Connection: ocsf.NetConnectionInfo{
			Protocol: proto, ProtoNum: 6,
			Direction: "outbound", DirID: 2,
		},
		SrcEndpoint: ocsf.NetEndpoint{IP: "10.0.0.5", Port: 55555},
		DstEndpoint: ocsf.NetEndpoint{IP: dstIP, Port: dstPort},
	}
}

func TestNetworkRuleFiresDetection(t *testing.T) {
	compiled, err := CompileRules([]*ruleast.Rule{compileFixture(t, netConnectSigma)}, nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	in := make(chan ocsf.Event, 1)
	in <- netActivityFixture("tcp", "203.0.113.9", 4444, "/usr/bin/nc")
	close(in)

	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), in) }()

	var gotFinding bool
	for out := range eng.Output() {
		if _, ok := out.(*ocsf.DetectionFinding); ok {
			gotFinding = true
		}
	}
	<-done
	if !gotFinding {
		t.Fatal("matching network event did not produce a DetectionFinding")
	}
}

func TestNetworkRuleNoMatchOnDifferentPort(t *testing.T) {
	compiled, err := CompileRules([]*ruleast.Rule{compileFixture(t, netConnectSigma)}, nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	in := make(chan ocsf.Event, 1)
	in <- netActivityFixture("tcp", "203.0.113.9", 80, "/usr/bin/curl")
	close(in)

	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), in) }()

	var findings int
	for out := range eng.Output() {
		if _, ok := out.(*ocsf.DetectionFinding); ok {
			findings++
		}
	}
	<-done
	if findings != 0 {
		t.Fatalf("non-matching network event produced %d findings", findings)
	}
}
