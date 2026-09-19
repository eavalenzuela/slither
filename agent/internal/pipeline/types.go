// Package pipeline defines the data types flowing between agent stages.
//
// Collector → Enricher → RuleEngine → Output.
//
// Raw* types are the decoded-from-kernel representation that only the collector
// and enricher need to know about. Everything downstream of the enricher works
// on OCSF events (pkg/ocsf).
package pipeline

import "time"

// Priority classifies items on inter-stage queues. Overflow drops lower
// priorities first. Detection is never dropped: if the detection queue is
// full, the agent exits with a diagnostic (see IMPLEMENTATION.md §3.5).
type Priority uint8

const (
	PriorityHeartbeat Priority = iota
	PriorityEvent
	PriorityDetection
)

// RawProcessEvent is the decoded form of a process.bpf.c ringbuffer record.
type RawProcessEvent struct {
	Kind      RawProcessKind
	PID       uint32
	PPID      uint32
	TGID      uint32
	UID       uint32
	GID       uint32
	Comm      string
	Exe       string
	Cmdline   string
	Timestamp time.Time
	ExitCode  int32
	// CgroupID is the cgroup v2 id (cgroupfs inode) the task was in. The
	// enricher maps it to a container id through the cgroup collector.
	// 0 on a cgroup-v1-only host.
	CgroupID uint64
}

// RawProcessKind enumerates the lifecycle hook that produced an event.
type RawProcessKind uint8

const (
	ProcUnknown RawProcessKind = iota
	ProcExec
	ProcExit
	ProcFork
)

// RawFileEvent is the decoded form of a file.bpf.c ringbuffer record.
type RawFileEvent struct {
	Kind      RawFileKind
	PID       uint32
	UID       uint32
	Path      string
	NewPath   string
	Flags     uint32
	Mode      uint32
	Timestamp time.Time
}

// RawFileKind enumerates file-event tracepoint origins.
type RawFileKind uint8

const (
	FileUnknown RawFileKind = iota
	FileOpenCreate
	FileOpenWrite
	FileUnlink
	FileRename
	FileChmod
	FileChown
)

// RawNetEvent is the decoded form of a net.bpf.c ringbuffer record.
type RawNetEvent struct {
	Kind      RawNetKind
	PID       uint32
	Proto     uint8
	SrcAddr   string
	SrcPort   uint16
	DstAddr   string
	DstPort   uint16
	Timestamp time.Time
}

// RawNetKind distinguishes the kernel hook an event came from.
type RawNetKind uint8

const (
	NetUnknown RawNetKind = iota
	NetTCPConnect
	NetTCPAccept
	NetUDPSend
)

// RawAuthEvent is the decoded form of an auth.bpf.c ringbuffer record: one
// libpam API result (pam_authenticate / pam_open_session /
// pam_close_session) plus the transaction context accumulated between
// pam_start and pam_end.
type RawAuthEvent struct {
	Kind RawAuthKind
	// PID is the tgid of the PAM client — sshd's per-connection monitor,
	// sudo, su, login — which is also the enricher's process-cache key.
	PID uint32
	// UID is the real uid of that client. For a setuid client such as
	// sudo that is the invoking user, not root.
	UID uint32
	// Result is the raw PAM return code; 0 is PAM_SUCCESS.
	Result int32
	// Service is the PAM service name passed to pam_start ("sshd",
	// "sudo", "su", "login", ...).
	Service string
	// User is the account being authenticated (PAM_USER).
	User string
	// RemoteHost is PAM_RHOST as the client set it — an IP for sshd,
	// sometimes a hostname, empty for local clients.
	RemoteHost string
	// TTY is PAM_TTY; empty when the client never set it.
	TTY       string
	Comm      string
	Timestamp time.Time
}

// RawAuthKind distinguishes which libpam call produced the event.
type RawAuthKind uint8

const (
	AuthUnknown RawAuthKind = iota
	// AuthAttempt is a pam_authenticate return: a credential check.
	AuthAttempt
	// AuthSessionOpen is a pam_open_session return: a login or a
	// privilege use (sudo/su) after the credential and account checks.
	AuthSessionOpen
	// AuthSessionClose is a pam_close_session return.
	AuthSessionClose
)

// RawKernelEvent is the decoded form of a kernel.bpf.c ringbuffer record:
// a module load / unload / rejected load, a BPF program load, or a
// kprobe / uprobe attach through perf_event_open.
type RawKernelEvent struct {
	Kind RawKernelKind
	// PID is the tgid of the process that made the request; the
	// enricher's process-cache key.
	PID uint32
	UID uint32
	// Errno is the positive errno of a rejected module load; 0 otherwise.
	Errno int32
	// Taints is the taint mask a loaded module added (module_load only).
	Taints uint32
	// Name is the module name, the BPF program name, or — for a probe —
	// the kprobe symbol or uprobe path.
	Name string
	// ProgType is bpf_attr.prog_type for a BPF program load.
	ProgType uint32
	// Probe is "kprobe" or "uprobe" for a probe attach, "" otherwise.
	Probe string
	// Retprobe is set when the probe fires on function return.
	Retprobe bool
	// Offset is the kprobe address or uprobe file offset.
	Offset uint64
	// SystemCall names the syscall that produced the event.
	SystemCall string
	Comm       string
	Timestamp  time.Time
}

// RawKernelKind distinguishes what the kernel reported.
type RawKernelKind uint8

const (
	KernelUnknown RawKernelKind = iota
	KernelModuleLoad
	KernelModuleUnload
	KernelModuleLoadRejected
	KernelBPFProgLoad
	KernelProbeAttach
)

// RawCgroupEvent is the decoded form of a cgroup.bpf.c ringbuffer record:
// a cgroup directory was created or removed. Container runtimes name a
// container's cgroup after its id, so these are the runtime-agnostic
// container create / stop signal.
type RawCgroupEvent struct {
	Kind RawCgroupKind
	// PID is the tgid of the process that created or removed the cgroup
	// (the runtime: runc, containerd-shim, crun, conmon, ...).
	PID uint32
	UID uint32
	// Root is the cgroup hierarchy id; 0 is the cgroup v2 default
	// hierarchy, whose ids match RawProcessEvent.CgroupID.
	Root int32
	// ID is the cgroup id in that hierarchy.
	ID uint64
	// Path is the cgroup path relative to the hierarchy root.
	Path      string
	Comm      string
	Timestamp time.Time
}

// RawCgroupKind distinguishes creation from removal.
type RawCgroupKind uint8

const (
	CgroupUnknown RawCgroupKind = iota
	CgroupMkdir
	CgroupRmdir
)

// RawDNSEvent is the decoded form of a dns.bpf.c ringbuffer record: one
// UDP/53 datagram, outbound (query) or inbound (response), with the
// raw DNS payload for the enricher to parse.
type RawDNSEvent struct {
	Kind RawDNSKind
	// PID is the tgid of the process that sent or received the datagram.
	PID       uint32
	UID       uint32
	SrcAddr   string
	SrcPort   uint16
	DstAddr   string
	DstPort   uint16
	Payload   []byte
	Comm      string
	Timestamp time.Time
}

// RawDNSKind distinguishes direction.
type RawDNSKind uint8

const (
	DNSUnknown RawDNSKind = iota
	DNSQuery
	DNSResponse
)
