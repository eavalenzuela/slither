package ocsf

import "fmt"

// KernelActivity (OCSF class_uid 1003).
// Covers kernel-module loads / unloads / rejected loads, BPF program
// loads, and kprobe / uprobe attaches. Used for rootkit defence-in-depth
// detections.
type KernelActivity struct {
	Metadata    Metadata         `json:"metadata"`
	ClassUID    ClassID          `json:"class_uid"`
	ClassName   string           `json:"class_name"`
	ActivityID  KernelActivityID `json:"activity_id"`
	TypeUID     uint64           `json:"type_uid"`
	Severity    Severity         `json:"severity_id"`
	SeverityStr string           `json:"severity,omitempty"`
	Time        TimeOCSF         `json:"time"`
	Device      Device           `json:"device"`
	Actor       Actor            `json:"actor"`
	Kernel      KernelObject     `json:"kernel"`
	// Status is Success or Failure. A rejected module load is a Failure
	// whose StatusCode carries the errno and StatusDetail its name
	// (EKEYREJECTED is signature enforcement, EPERM is lockdown).
	Status       string `json:"status,omitempty"`
	StatusID     uint8  `json:"status_id,omitempty"`
	StatusCode   string `json:"status_code,omitempty"`
	StatusDetail string `json:"status_detail,omitempty"`
}

type KernelActivityID uint8

const (
	KernelActivityUnknown KernelActivityID = 0
	KernelActivityCreate  KernelActivityID = 1 // module load
	KernelActivityRead    KernelActivityID = 2
	KernelActivityDelete  KernelActivityID = 3 // module unload
	KernelActivityInvoke  KernelActivityID = 4 // kprobe/uprobe attach, BPF program load
	KernelActivityOther   KernelActivityID = 99
)

// KernelObject is the OCSF `kernel` object plus slither extensions for
// what an eBPF collector can say about a module, probe, or BPF program.
type KernelObject struct {
	// Name is the module name, the BPF program name, the kprobe symbol,
	// or the uprobe path.
	Name string `json:"name,omitempty"`
	// Type is Module, Kprobe, Kretprobe, Uprobe, Uretprobe, or BPF Program.
	Type string `json:"type,omitempty"`
	// Path is the file a uprobe attaches to; empty for the other types
	// (a module's path is not visible at load time — the loader's
	// command line in Actor.Process usually carries it).
	Path string `json:"path,omitempty"`
	// SystemCall is the syscall that produced the event: init_module,
	// delete_module, bpf, perf_event_open.
	SystemCall string `json:"system_call,omitempty"`
	// Taints lists the kernel taint flags a loaded module added, by
	// name: out_of_tree, unsigned_module, proprietary_module, staging,
	// ... slither extension.
	Taints []string `json:"x_taints,omitempty"`
	// ProgType is the BPF program type by name (kprobe, tracepoint,
	// xdp, cgroup_skb, ...). slither extension.
	ProgType string `json:"x_bpf_prog_type,omitempty"`
	// Offset is the kprobe address or uprobe file offset, in hex.
	// slither extension.
	Offset string `json:"x_probe_offset,omitempty"`
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
	if k.Kernel.Name == "" && k.Kernel.Type == "" {
		return fmt.Errorf("%w: kernel.name or kernel.type required", ErrInvalidEvent)
	}
	return nil
}
