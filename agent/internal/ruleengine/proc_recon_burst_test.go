package ruleengine

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// reconEvent builds a process-launch event for a recon binary whose
// parent shell carries parentPID — the key proc-recon-burst groups on.
func reconEvent(image string, parentPID uint32) *ocsf.ProcessActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-recon"},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Process: ocsf.Process{
			PID:    9000,
			Name:   filepath.Base(image),
			File:   &ocsf.File{Path: image},
			Parent: &ocsf.Process{PID: parentPID, File: &ocsf.File{Path: "/usr/bin/bash"}},
		},
	}
}

func reconBurstRule(t *testing.T) *sigmaCompiledRule {
	t.Helper()
	rule := loadRule(t, "rules/linux/proc-recon-burst.yml")
	rules, err := CompileRules([]*ruleast.Rule{rule}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	scr, ok := rules[0].(*sigmaCompiledRule)
	if !ok {
		t.Fatalf("expected a stateful sigmaCompiledRule, got %T", rules[0])
	}
	return scr
}

// TestReconBurstFiresOnThirdCommand — three distinct recon commands under
// one parent shell inside the 30 s window cross the `count() > 2` threshold;
// a non-recon exec in the middle does not advance the count.
func TestReconBurstFiresOnThirdCommand(t *testing.T) {
	scr := reconBurstRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	if scr.Match(reconEvent("/usr/bin/whoami", 4242)) {
		t.Fatal("1st recon command should not fire")
	}
	clk.advance(3 * time.Second)

	// A non-recon exec under the same shell must not count toward the burst.
	if scr.Match(reconEvent("/usr/bin/ls", 4242)) {
		t.Fatal("non-recon exec should not match the rule at all")
	}
	clk.advance(3 * time.Second)

	if scr.Match(reconEvent("/usr/bin/id", 4242)) {
		t.Fatal("2nd recon command should not fire (count=2, threshold >2)")
	}
	clk.advance(3 * time.Second)

	if !scr.Match(reconEvent("/usr/bin/hostname", 4242)) {
		t.Error("3rd recon command under one shell should cross the threshold")
	}
}

// TestReconBurstPartitionsByParentShell — counts are per parent shell, so
// recon spread across three separate shells never crosses the threshold.
func TestReconBurstPartitionsByParentShell(t *testing.T) {
	scr := reconBurstRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i, parent := range []uint32{100, 200, 300} {
		if scr.Match(reconEvent("/usr/bin/whoami", parent)) {
			t.Errorf("one recon command under shell #%d should not fire", i+1)
		}
		clk.advance(2 * time.Second)
	}
}

// TestReconBurstWindowExpires — recon commands spaced beyond the 30 s
// timeframe age out, so the count never reaches the threshold.
func TestReconBurstWindowExpires(t *testing.T) {
	scr := reconBurstRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i, img := range []string{"/usr/bin/whoami", "/usr/bin/id", "/usr/bin/groups"} {
		if scr.Match(reconEvent(img, 4242)) {
			t.Errorf("recon command %d spaced past the window should not fire", i+1)
		}
		clk.advance(40 * time.Second)
	}
}
