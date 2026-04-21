package ruleengine

import (
	"strconv"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// fieldAccessor projects Sigma field names onto OCSF values for a single event
// class. The lookup is nil for unknown fields so the Env can report (nil, false)
// and the rule treats the predicate as a non-match, matching Sigma semantics.
type fieldAccessor map[string]func(ocsf.Event) []string

// categoryToClass maps the Sigma logsource categories the compiler accepts
// onto the OCSF class whose events carry the same concept.
func categoryToClass(c ruleast.Category) (ocsf.ClassID, bool) {
	switch c {
	case ruleast.CategoryProcessCreation:
		return ocsf.ClassProcessActivity, true
	case ruleast.CategoryFileEvent:
		return ocsf.ClassFileSystemActivity, true
	case ruleast.CategoryNetworkConnection:
		return ocsf.ClassNetworkActivity, true
	}
	return 0, false
}

// accessorFor returns the Sigma→OCSF projection table for a category.
func accessorFor(c ruleast.Category) fieldAccessor {
	switch c {
	case ruleast.CategoryProcessCreation:
		return processAccessor
	case ruleast.CategoryFileEvent:
		return fileAccessor
	case ruleast.CategoryNetworkConnection:
		return netAccessor
	}
	return nil
}

// processAccessor maps the Sigma process_creation vocabulary onto fields of
// ocsf.ProcessActivity. Field names match Sigma's canonical camel-case form;
// aliases commonly used by public rule packs are included.
var processAccessor = fieldAccessor{
	"Image":             func(e ocsf.Event) []string { return procExePath(procOf(e)) },
	"ProcessName":       func(e ocsf.Event) []string { return nonEmpty(procOf(e).Name) },
	"CommandLine":       func(e ocsf.Event) []string { return nonEmpty(procOf(e).Cmdline) },
	"User":              func(e ocsf.Event) []string { return procUserName(procOf(e)) },
	"ProcessId":         func(e ocsf.Event) []string { return u32Str(procOf(e).PID) },
	"PID":               func(e ocsf.Event) []string { return u32Str(procOf(e).PID) },
	"ParentImage":       func(e ocsf.Event) []string { return procExePath(parentOf(e)) },
	"ParentCommandLine": func(e ocsf.Event) []string { return nonEmpty(parentCmd(e)) },
	"ParentProcessId":   func(e ocsf.Event) []string { return u32Str(parentPID(e)) },
	"PPID":              func(e ocsf.Event) []string { return u32Str(parentPID(e)) },
}

// fileAccessor maps Sigma file_event fields onto ocsf.FileSystemActivity.
var fileAccessor = fieldAccessor{
	"TargetFilename": fileTargetPath,
	"Filename":       fileTargetPath,
	"Path":           fileTargetPath,
	"Image":          func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine":    func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":           actorUserName,
}

// netAccessor maps Sigma network_connection fields onto ocsf.NetworkActivity.
var netAccessor = fieldAccessor{
	"DestinationIp":   netDstIP,
	"DestinationPort": netDstPort,
	"SourceIp":        netSrcIP,
	"SourcePort":      netSrcPort,
	"Protocol":        netProto,
	"Image":           func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine":     func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":            actorUserName,
}

// --- helpers (kept tiny and boring; they are the glue, not the logic) -------

func procOf(e ocsf.Event) ocsf.Process {
	if p, ok := e.(*ocsf.ProcessActivity); ok {
		return p.Process
	}
	return ocsf.Process{}
}

func parentOf(e ocsf.Event) ocsf.Process {
	p := procOf(e)
	if p.Parent == nil {
		return ocsf.Process{}
	}
	return *p.Parent
}

func parentCmd(e ocsf.Event) string {
	p := procOf(e)
	if p.Parent == nil {
		return ""
	}
	return p.Parent.Cmdline
}

func parentPID(e ocsf.Event) uint32 {
	p := procOf(e)
	if p.Parent == nil {
		return 0
	}
	return p.Parent.PID
}

func procExePath(p ocsf.Process) []string {
	if p.File == nil || p.File.Path == "" {
		return nil
	}
	return []string{p.File.Path}
}

func procUserName(p ocsf.Process) []string {
	if p.User == nil || p.User.Name == "" {
		return nil
	}
	return []string{p.User.Name}
}

func actorProcess(e ocsf.Event) ocsf.Process {
	switch v := e.(type) {
	case *ocsf.FileSystemActivity:
		return v.Actor.Process
	case *ocsf.NetworkActivity:
		return v.Actor.Process
	case *ocsf.ProcessActivity:
		return v.Actor.Process
	}
	return ocsf.Process{}
}

func actorUserName(e ocsf.Event) []string {
	var u ocsf.User
	switch v := e.(type) {
	case *ocsf.FileSystemActivity:
		u = v.Actor.User
	case *ocsf.NetworkActivity:
		u = v.Actor.User
	case *ocsf.ProcessActivity:
		u = v.Actor.User
	default:
		return nil
	}
	if u.Name == "" {
		return nil
	}
	return []string{u.Name}
}

func fileTargetPath(e ocsf.Event) []string {
	f, ok := e.(*ocsf.FileSystemActivity)
	if !ok {
		return nil
	}
	var out []string
	if f.File.Path != "" {
		out = append(out, f.File.Path)
	} else if f.File.Name != "" {
		out = append(out, f.File.Name)
	}
	return out
}

func netDstIP(e ocsf.Event) []string {
	n, ok := e.(*ocsf.NetworkActivity)
	if !ok || n.DstEndpoint.IP == "" {
		return nil
	}
	return []string{n.DstEndpoint.IP}
}

func netDstPort(e ocsf.Event) []string {
	n, ok := e.(*ocsf.NetworkActivity)
	if !ok || n.DstEndpoint.Port == 0 {
		return nil
	}
	return []string{strconv.FormatUint(uint64(n.DstEndpoint.Port), 10)}
}

func netSrcIP(e ocsf.Event) []string {
	n, ok := e.(*ocsf.NetworkActivity)
	if !ok || n.SrcEndpoint.IP == "" {
		return nil
	}
	return []string{n.SrcEndpoint.IP}
}

func netSrcPort(e ocsf.Event) []string {
	n, ok := e.(*ocsf.NetworkActivity)
	if !ok || n.SrcEndpoint.Port == 0 {
		return nil
	}
	return []string{strconv.FormatUint(uint64(n.SrcEndpoint.Port), 10)}
}

func netProto(e ocsf.Event) []string {
	n, ok := e.(*ocsf.NetworkActivity)
	if !ok || n.Connection.Protocol == "" {
		return nil
	}
	return []string{n.Connection.Protocol}
}

func u32Str(v uint32) []string {
	if v == 0 {
		return nil
	}
	return []string{strconv.FormatUint(uint64(v), 10)}
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
