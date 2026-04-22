package ruleengine

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

const shadowWriteSigma = `title: Write to /etc/shadow
id: 33333333-3333-4333-8333-333333333333
level: high
logsource:
  product: linux
  category: file_event
detection:
  sel:
    TargetFilename|startswith: /etc/shadow
  condition: sel
`

func fileActivityFixture(path, exe string) *ocsf.FileSystemActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.FileSystemActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-f"},
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: ocsf.FileActivityUpdate,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor: ocsf.Actor{
			Process: ocsf.Process{
				PID:  4321,
				Name: "vi",
				File: &ocsf.File{Path: exe, Name: "vi"},
			},
			User: ocsf.User{Name: "root", UID: "0", Type: "Admin"},
		},
		File: ocsf.File{Path: path, Name: "shadow"},
	}
}

func TestFileEventRuleFiresDetection(t *testing.T) {
	compiled, err := CompileRules([]*ruleast.Rule{compileFixture(t, shadowWriteSigma)})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	ev := fileActivityFixture("/etc/shadow", "/usr/bin/vi")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan ocsf.Event, 1)
	in <- ev
	close(in)

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, in) }()

	// Original event comes out first, then the finding.
	var gotEvent, gotFinding bool
	for out := range eng.Output() {
		switch out.(type) {
		case *ocsf.FileSystemActivity:
			gotEvent = true
		case *ocsf.DetectionFinding:
			gotFinding = true
		}
	}
	<-done
	if !gotEvent {
		t.Fatal("file event not forwarded")
	}
	if !gotFinding {
		t.Fatal("rule match did not produce a DetectionFinding")
	}
}

func TestFileEventRuleNoMatch(t *testing.T) {
	compiled, err := CompileRules([]*ruleast.Rule{compileFixture(t, shadowWriteSigma)})
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	eng := New(compiled, telemetry.NewCounters()).(*engine)

	ev := fileActivityFixture("/tmp/other", "/usr/bin/cat")

	in := make(chan ocsf.Event, 1)
	in <- ev
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
		t.Fatalf("non-matching event produced %d findings", findings)
	}
}
