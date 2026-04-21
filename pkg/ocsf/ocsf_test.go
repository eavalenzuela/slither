package ocsf

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// All event types implement Event. Compile-time + runtime check.
var _ = []Event{
	&ProcessActivity{},
	&FileSystemActivity{},
	&NetworkActivity{},
	&DnsActivity{},
	&Authentication{},
	&KernelActivity{},
	&ContainerLifecycle{},
	&DetectionFinding{},
}

func TestClassIDs(t *testing.T) {
	cases := []struct {
		ev   Event
		want ClassID
	}{
		{&ProcessActivity{}, ClassProcessActivity},
		{&FileSystemActivity{}, ClassFileSystemActivity},
		{&NetworkActivity{}, ClassNetworkActivity},
		{&DnsActivity{}, ClassDnsActivity},
		{&Authentication{}, ClassAuthentication},
		{&KernelActivity{}, ClassKernelActivity},
		{&ContainerLifecycle{}, ClassContainerLifecycle},
		{&DetectionFinding{}, ClassDetectionFinding},
	}
	for _, c := range cases {
		got := c.ev.ClassID()
		if got != c.want {
			t.Errorf("%T.ClassID() = %d, want %d", c.ev, got, c.want)
		}
	}
}

func TestValidateRejectsUnfilledEvents(t *testing.T) {
	events := []Event{
		&ProcessActivity{},
		&FileSystemActivity{},
		&NetworkActivity{},
		&DnsActivity{},
		&Authentication{},
		&KernelActivity{},
		&ContainerLifecycle{},
		&DetectionFinding{},
	}
	for _, ev := range events {
		err := ev.Validate()
		if err == nil {
			t.Errorf("%T.Validate() = nil, want error on empty event", ev)
			continue
		}
		if !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%T.Validate() error = %v, want it to wrap ErrInvalidEvent", ev, err)
		}
	}
}

func TestProcessActivityRoundTrip(t *testing.T) {
	e := ProcessActivity{
		Metadata: Metadata{Version: Version, Product: slitherProduct()},
		ClassUID: ClassProcessActivity, ClassName: "process_activity",
		ActivityID: ProcessActivityLaunch,
		Severity:   SeverityInformational,
		Time:       1_700_000_000_000,
		Device:     Device{HostID: "host-abc"},
		Process:    Process{PID: 1234, Name: "sh", Cmdline: "/bin/sh -c id"},
		Actor:      Actor{Process: Process{PID: 1}},
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate on well-formed event: %v", err)
	}
	b, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A few stability checks — OCSF field names we depend on.
	for _, field := range []string{`"class_uid":1007`, `"activity_id":1`, `"pid":1234`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("json missing %q; got %s", field, b)
		}
	}
}

func TestFileSystemRenameRequiresDiff(t *testing.T) {
	e := FileSystemActivity{
		ClassUID: ClassFileSystemActivity, ActivityID: FileActivityRename,
		Time: 1, File: File{Path: "/a"},
	}
	err := e.Validate()
	if err == nil || !strings.Contains(err.Error(), "file_diff") {
		t.Fatalf("expected file_diff error, got %v", err)
	}
	e.RenameTo = &File{Path: "/b"}
	if err := e.Validate(); err != nil {
		t.Fatalf("valid rename rejected: %v", err)
	}
}

func slitherProduct() Product {
	return Product{Name: "slither-agent", VendorName: "slither", Version: "dev", Language: "en"}
}
