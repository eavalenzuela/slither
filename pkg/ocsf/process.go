package ocsf

import "fmt"

// ProcessActivity (OCSF class_uid 1007).
//
// Emitted on process lifecycle transitions observed via eBPF
// tracepoint/sched_process_* hooks.
type ProcessActivity struct {
	Metadata   Metadata          `json:"metadata"`
	ClassUID   ClassID           `json:"class_uid"`
	ClassName  string            `json:"class_name"`
	ActivityID ProcessActivityID `json:"activity_id"`
	TypeUID    uint64            `json:"type_uid"`
	Severity   Severity          `json:"severity_id"`
	SeverityStr string           `json:"severity,omitempty"`
	Time       TimeOCSF          `json:"time"`
	Device     Device            `json:"device"`
	Actor      Actor             `json:"actor"`
	Process    Process           `json:"process"`
	ExitCode   *int32            `json:"exit_code,omitempty"`
}

// Actor wraps the process that caused the activity — typically the parent
// for exec, or the process itself for exit.
type Actor struct {
	Process Process `json:"process"`
	User    User    `json:"user"`
}

// ProcessActivityID enumerates OCSF 1007 activity_id values.
type ProcessActivityID uint8

const (
	ProcessActivityUnknown    ProcessActivityID = 0
	ProcessActivityLaunch     ProcessActivityID = 1 // exec
	ProcessActivityTerminate  ProcessActivityID = 2 // exit
	ProcessActivityOpen       ProcessActivityID = 3 // debug/trace open
	ProcessActivityInject     ProcessActivityID = 4
	ProcessActivitySetUserID  ProcessActivityID = 5
	ProcessActivityOther      ProcessActivityID = 99
)

func (p *ProcessActivity) ClassID() ClassID { return ClassProcessActivity }

// Validate enforces required OCSF 1007 fields for slither-emitted events.
func (p *ProcessActivity) Validate() error {
	if p.ClassUID != ClassProcessActivity {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, p.ClassUID, ClassProcessActivity)
	}
	if p.ActivityID == ProcessActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if p.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if p.Process.PID == 0 {
		return fmt.Errorf("%w: process.pid required", ErrInvalidEvent)
	}
	if p.Device.HostID == "" {
		return fmt.Errorf("%w: device.uid required", ErrInvalidEvent)
	}
	return nil
}
