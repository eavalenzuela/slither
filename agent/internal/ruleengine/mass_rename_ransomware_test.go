package ruleengine

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// createExtEvent models the write-new-file pattern: the ransomware writes
// a fresh `<orig>.locked` and deletes the original, so the suffix lands in
// File/TargetFilename. pid is the actor PID the rule partitions on.
func createExtEvent(path string, pid uint32) *ocsf.FileSystemActivity {
	ts := time.Now().UnixMilli()
	return &ocsf.FileSystemActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-c"},
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: ocsf.FileActivityCreate,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor:      ocsf.Actor{Process: ocsf.Process{PID: pid, Name: "encryptor"}},
		File:       ocsf.File{Path: path},
	}
}

// renameExtEvent models the in-place pattern: rename(orig -> orig.locked).
// The suffix lands only in RenameTo; File still holds the source path.
func renameExtEvent(src, dst string, pid uint32) *ocsf.FileSystemActivity {
	ev := createExtEvent(src, pid)
	ev.ActivityID = ocsf.FileActivityRename
	ev.RenameTo = &ocsf.File{Path: dst}
	return ev
}

func massRenameRule(t *testing.T) *sigmaCompiledRule {
	t.Helper()
	rule := loadRule(t, "rules/linux/file-mass-rename-ransomware.yml")
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

// TestMassRenameFiresAtThreshold — count() by ProcessId > 20, so the 21st
// ransom-suffix event from one PID inside the window crosses it. The burst
// mixes both I/O patterns (create-with-suffix and in-place rename), proving
// RenameTo and TargetFilename feed one shared per-PID counter.
func TestMassRenameFiresAtThreshold(t *testing.T) {
	scr := massRenameRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	const encryptorPID = 7777
	for i := 0; i < 20; i++ {
		var ev *ocsf.FileSystemActivity
		if i%2 == 0 {
			ev = createExtEvent("/home/alice/doc.txt.locked", encryptorPID)
		} else {
			ev = renameExtEvent("/home/alice/doc.txt", "/home/alice/doc.txt.encrypted", encryptorPID)
		}
		if scr.Match(ev) {
			t.Fatalf("event %d should not cross count() > 20", i+1)
		}
		clk.advance(time.Second)
	}
	if !scr.Match(renameExtEvent("/home/alice/last.txt", "/home/alice/last.txt.ryuk", encryptorPID)) {
		t.Error("21st ransom-suffix event from one PID in the window should fire")
	}
}

// TestMassRenamePartitionsByProcess — counts are per PID, so a burst spread
// across distinct processes (each below the threshold) never fires. This is
// what makes the firing PID a clean kill target.
func TestMassRenamePartitionsByProcess(t *testing.T) {
	scr := massRenameRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 60; i++ {
		pid := uint32(1000 + i%3) // three distinct PIDs, 20 events each
		if scr.Match(createExtEvent("/srv/data/file.locked", pid)) {
			t.Fatalf("event %d split across 3 PIDs should not cross the per-PID threshold", i+1)
		}
		clk.advance(time.Second)
	}
}

// TestMassRenameIgnoresBenignWrites — ordinary file activity (no ransom
// suffix on either side) never advances the counter, so it cannot fire.
func TestMassRenameIgnoresBenignWrites(t *testing.T) {
	scr := massRenameRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 30; i++ {
		if scr.Match(renameExtEvent("/var/log/app.log", "/var/log/app.log.1", 4242)) {
			t.Fatalf("benign logrotate-style rename %d must not match", i+1)
		}
		clk.advance(time.Second)
	}
}

// TestMassRenameWindowExpires — suffix events spaced beyond the 60 s window
// age out, so the count never reaches the threshold.
func TestMassRenameWindowExpires(t *testing.T) {
	scr := massRenameRule(t)
	clk := &fakeNow{t: time.Unix(1_700_000_000, 0)}
	defer withFakeClock(scr, clk.Now)()

	for i := 0; i < 30; i++ {
		if scr.Match(createExtEvent("/home/alice/doc.txt.locked", 7777)) {
			t.Fatalf("event %d spaced past the window should not fire", i+1)
		}
		clk.advance(90 * time.Second)
	}
}
