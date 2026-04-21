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
