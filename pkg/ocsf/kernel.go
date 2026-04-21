package ocsf

import "fmt"

// KernelActivity (OCSF class_uid 1003).
// Covers kernel-module loads, kprobe/uprobe attach, and similar kernel-level
// actions. Used for rootkit defense-in-depth detections.
type KernelActivity struct {
	Metadata    Metadata        `json:"metadata"`
	ClassUID    ClassID         `json:"class_uid"`
	ClassName   string          `json:"class_name"`
	ActivityID  KernelActivityID `json:"activity_id"`
	TypeUID     uint64          `json:"type_uid"`
	Severity    Severity        `json:"severity_id"`
	SeverityStr string          `json:"severity,omitempty"`
	Time        TimeOCSF        `json:"time"`
	Device      Device          `json:"device"`
	Actor       Actor           `json:"actor"`
	Kernel      KernelObject    `json:"kernel"`
}

type KernelActivityID uint8

const (
	KernelActivityUnknown KernelActivityID = 0
	KernelActivityCreate  KernelActivityID = 1 // module load
	KernelActivityRead    KernelActivityID = 2
	KernelActivityDelete  KernelActivityID = 3 // module unload
	KernelActivityInvoke  KernelActivityID = 4 // kprobe/uprobe attach
	KernelActivityOther   KernelActivityID = 99
)

type KernelObject struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"` // Driver, Module, Probe
	Path string `json:"path,omitempty"`
}

func (k *KernelActivity) ClassID() ClassID { return ClassKernelActivity }

func (k *KernelActivity) Validate() error {
	if k.ClassUID != ClassKernelActivity {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, k.ClassUID, ClassKernelActivity)
	}
	if k.ActivityID == KernelActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if k.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if k.Kernel.Name == "" {
		return fmt.Errorf("%w: kernel.name required", ErrInvalidEvent)
	}
	return nil
}
