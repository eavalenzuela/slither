package ocsf

import (
	"errors"
	"fmt"
)

// ClassID is the OCSF class_uid.
type ClassID uint32

const (
	ClassFileSystemActivity ClassID = 1001
	ClassKernelActivity     ClassID = 1003
	ClassProcessActivity    ClassID = 1007
	ClassDetectionFinding   ClassID = 2004
	ClassAuthentication     ClassID = 3002
	ClassNetworkActivity    ClassID = 4001
	ClassDnsActivity        ClassID = 4003
	ClassContainerLifecycle ClassID = 6000
)

func (c ClassID) String() string {
	switch c {
	case ClassFileSystemActivity:
		return "file_system_activity"
	case ClassKernelActivity:
		return "kernel_activity"
	case ClassProcessActivity:
		return "process_activity"
	case ClassDetectionFinding:
		return "detection_finding"
	case ClassAuthentication:
		return "authentication"
	case ClassNetworkActivity:
		return "network_activity"
	case ClassDnsActivity:
		return "dns_activity"
	case ClassContainerLifecycle:
		return "container_lifecycle"
	}
	return fmt.Sprintf("unknown_class_%d", uint32(c))
}

// Severity mirrors OCSF severity_id. Values are intentionally equal to the
// OCSF-defined numbers so this type round-trips cleanly.
type Severity uint8

const (
	SeverityUnknown       Severity = 0
	SeverityInformational Severity = 1
	SeverityLow           Severity = 2
	SeverityMedium        Severity = 3
	SeverityHigh          Severity = 4
	SeverityCritical      Severity = 5
	SeverityFatal         Severity = 6
)

// ActivityID is an event-class-local enum of the underlying verb
// (exec vs. exit for ProcessActivity, etc.). Concrete values live on each class.
type ActivityID uint8

// Event is the contract every OCSF event type in this package implements.
type Event interface {
	ClassID() ClassID
	Validate() error
}

// ErrInvalidEvent is returned by Validate when an OCSF event fails its schema
// constraints. Wrap with more context at the call site.
var ErrInvalidEvent = errors.New("invalid ocsf event")

// Metadata is the OCSF metadata object carried by every event.
type Metadata struct {
	Version   string    `json:"version"`    // OCSF schema version, e.g. "1.3.0"
	Product   Product   `json:"product"`
	LogName   string    `json:"log_name,omitempty"`
	EventCode string    `json:"event_code,omitempty"`
	Labels    []string  `json:"labels,omitempty"`
	UID       string    `json:"uid,omitempty"`        // event_id (UUIDv7)
	OriginalT int64     `json:"original_time,omitempty"`
}

// Product identifies slither as the emitting product. Pinned here so every
// event carries consistent identity without the caller filling it in.
type Product struct {
	Name     string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version  string `json:"version"`
	Language string `json:"lang,omitempty"`
}

// TimeOCSF is the OCSF convention: unix-epoch milliseconds as int64.
type TimeOCSF int64

// User is the shared user-identity field group (OCSF `user` object).
type User struct {
	Name     string `json:"name,omitempty"`
	UID      string `json:"uid,omitempty"`      // uid as string per OCSF
	Type     string `json:"type,omitempty"`     // User, System, Admin, Other
	Domain   string `json:"domain,omitempty"`
	FullName string `json:"full_name,omitempty"`
}

// Device is the shared device-identity field group (OCSF `device` object).
// slither populates this from agent-side enrichment at ingest.
type Device struct {
	HostID       string `json:"uid,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	OSName       string `json:"os.name,omitempty"`
	OSVersion    string `json:"os.version,omitempty"`
	KernelVersion string `json:"os.kernel_release,omitempty"`
	Arch         string `json:"hw_info.cpu_architecture,omitempty"`
}

// FilePath + File are the shared file-identity field group.
type File struct {
	Name         string   `json:"name,omitempty"`
	Path         string   `json:"path,omitempty"`
	Type         string   `json:"type,omitempty"`
	Size         uint64   `json:"size,omitempty"`
	HashesSHA256 string   `json:"hashes.sha256,omitempty"`
	ModifiedT    TimeOCSF `json:"modified_time,omitempty"`
	AccessedT    TimeOCSF `json:"accessed_time,omitempty"`
	CreatedT     TimeOCSF `json:"created_time,omitempty"`
	Owner        *User    `json:"owner,omitempty"`
}

// Process is the shared process-identity field group.
// Parent is nested recursively to carry up to N ancestors (bounded at depth 8).
type Process struct {
	PID         uint32   `json:"pid,omitempty"`
	UID         string   `json:"uid,omitempty"`
	Name        string   `json:"name,omitempty"`
	Cmdline     string   `json:"cmd_line,omitempty"`
	CreatedT    TimeOCSF `json:"created_time,omitempty"`
	File        *File    `json:"file,omitempty"`    // executable file
	User        *User    `json:"user,omitempty"`    // running user
	Parent      *Process `json:"parent_process,omitempty"`
	ContainerID string   `json:"x_container_id,omitempty"` // slither extension; Phase 2+
}
