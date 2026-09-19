package ruleeval

import (
	"strconv"

	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

// Accessor projects Sigma field names onto OCSF values for a single
// event class. Lookup of an unknown field returns nil so callers can
// honour Sigma's missing-field-is-not-a-match contract without
// special cases.
type Accessor map[string]func(ocsf.Event) []string

// CategoryToClass maps the Sigma logsource categories the compiler
// accepts onto the OCSF class whose events carry the same concept.
func CategoryToClass(c ruleast.Category) (ocsf.ClassID, bool) {
	switch c {
	case ruleast.CategoryProcessCreation:
		return ocsf.ClassProcessActivity, true
	case ruleast.CategoryFileEvent:
		return ocsf.ClassFileSystemActivity, true
	case ruleast.CategoryNetworkConnection:
		return ocsf.ClassNetworkActivity, true
	case ruleast.CategoryAuthentication:
		return ocsf.ClassAuthentication, true
	case ruleast.CategoryDriverLoad:
		return ocsf.ClassKernelActivity, true
	case ruleast.CategoryContainerLifecycle:
		return ocsf.ClassContainerLifecycle, true
	case ruleast.CategoryDNSQuery:
		return ocsf.ClassDnsActivity, true
	}
	return 0, false
}

// AccessorFor returns the Sigma→OCSF projection table for a category.
func AccessorFor(c ruleast.Category) Accessor {
	switch c {
	case ruleast.CategoryProcessCreation:
		return processAccessor
	case ruleast.CategoryFileEvent:
		return fileAccessor
	case ruleast.CategoryNetworkConnection:
		return netAccessor
	case ruleast.CategoryAuthentication:
		return authAccessor
	case ruleast.CategoryDriverLoad:
		return kernelAccessor
	case ruleast.CategoryContainerLifecycle:
		return containerAccessor
	case ruleast.CategoryDNSQuery:
		return dnsAccessor
	}
	return nil
}

// processAccessor maps the Sigma process_creation vocabulary onto fields of
// ocsf.ProcessActivity. Field names match Sigma's canonical camel-case form;
// aliases commonly used by public rule packs are included.
var processAccessor = Accessor{
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
	// EnvVars is a multi-valued field: one "NAME=value" string per
	// allowlisted variable the agent captured. Sigma's list semantics
	// then give presence and prefix matching for free —
	// `EnvVars|contains: 'GCONV_PATH='` and
	// `EnvVars|startswith: 'LD_PRELOAD=/tmp/'` both work with no new
	// operator. Empty (and so never a match) unless the agent runs with
	// collectors.process.capture_env.
	"EnvVars": func(e ocsf.Event) []string { return procOf(e).EnvVars },
	"Env":     func(e ocsf.Event) []string { return procOf(e).EnvVars },
	// ContainerId is the container the process runs in (x_container_id),
	// resolved from its cgroup; absent on the host. `ContainerId|exists:
	// true` is the "inside any container" predicate.
	"ContainerId": func(e ocsf.Event) []string { return nonEmpty(procOf(e).ContainerID) },
}

// fileAccessor maps Sigma file_event fields onto ocsf.FileSystemActivity.
var fileAccessor = Accessor{
	"TargetFilename": fileTargetPath,
	"Filename":       fileTargetPath,
	"Path":           fileTargetPath,
	// Rename destination (OCSF RenameTo, activity_id 6). For an in-place
	// rename the new extension lands here, not in File/TargetFilename —
	// so a rule that wants to catch `orig -> orig.locked` must key on this
	// field, while the create-new-file pattern stays on TargetFilename.
	"RenameTo":    fileRenameToPath,
	"NewFilename": fileRenameToPath,
	"Image":       func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine": func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":        actorUserName,
	// Actor PID — the process touching the file. Exposed so file_event
	// rules can both partition (`count() by ProcessId`) and name a kill
	// target (`slither.response.target_field: ProcessId`). Mirrors the
	// process_creation accessor's ProcessId/PID pair.
	"ProcessId":   func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"PID":         func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"ContainerId": actorContainerID,
}

// netAccessor maps Sigma network_connection fields onto ocsf.NetworkActivity.
var netAccessor = Accessor{
	"DestinationIp":   netDstIP,
	"DestinationPort": netDstPort,
	"SourceIp":        netSrcIP,
	"SourcePort":      netSrcPort,
	"Protocol":        netProto,
	"Image":           func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine":     func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":            actorUserName,
	"ContainerId":     actorContainerID,
}

// authAccessor maps Sigma authentication fields onto ocsf.Authentication.
// The vocabulary follows Sigma's Windows logon rules where a Linux
// equivalent exists (TargetUserName, SubjectUserName, LogonType) and
// slither's own names for the PAM-specific parts. Note the asymmetry
// with the other categories: here `User` is the account being
// authenticated, not the actor — that is what every auth rule wants to
// key on, and the actor (sshd, sudo) is reachable as SubjectUserName.
var authAccessor = Accessor{
	"User":            authUserName,
	"TargetUserName":  authUserName,
	"SubjectUserName": actorUserName,
	"Service":         authService,
	"PamService":      authService,
	"EventCode":       authEventCode,
	"EventType":       authEventCode,
	"Status":          authStatusStr,
	"StatusCode":      authStatusCode,
	"StatusDetail":    authStatusDetail,
	"SourceIp":        authSrcIP,
	"SourceHostname":  authSrcHost,
	// RemoteHost is PAM_RHOST as set, whichever shape it took — the
	// right field for `count() by RemoteHost` when a rule must not care
	// whether the client reported a name or an address.
	"RemoteHost":  authRemoteHost,
	"LogonType":   authLogonType,
	"Tty":         authTTY,
	"Image":       func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine": func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"ProcessId":   func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"PID":         func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"ContainerId": actorContainerID,
}

// kernelAccessor maps Sigma driver_load fields onto ocsf.KernelActivity.
// ImageLoaded is Sigma's own name for the loaded object; for a Linux
// module only the name is known at load time, so ImageLoaded falls back
// to it when there is no path (uprobes are the one type with a path).
var kernelAccessor = Accessor{
	"ImageLoaded":  kernelImageLoaded,
	"Module":       kernelName,
	"ModuleName":   kernelName,
	"Name":         kernelName,
	"Symbol":       kernelName,
	"Type":         kernelType,
	"EventCode":    kernelEventCode,
	"EventType":    kernelEventCode,
	"SystemCall":   kernelSystemCall,
	"Status":       kernelStatus,
	"StatusCode":   kernelStatusCode,
	"StatusDetail": kernelStatusDetail,
	// Taints is multi-valued: one name per taint flag the module added,
	// so `Taints: unsigned_module` is a membership test.
	"Taints":      kernelTaints,
	"ProgType":    kernelProgType,
	"Image":       func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine": func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":        actorUserName,
	"ProcessId":   func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"PID":         func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"ContainerId": actorContainerID,
}

// containerAccessor maps Sigma container_lifecycle fields onto
// ocsf.ContainerLifecycle.
var containerAccessor = Accessor{
	"ContainerId": containerID,
	"Runtime":     containerRuntime,
	"EventCode":   containerEventCode,
	"EventType":   containerEventCode,
	"CgroupPath":  containerCgroupPath,
	"Image":       func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine": func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":        actorUserName,
	"ProcessId":   func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"PID":         func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
}

// dnsAccessor maps Sigma dns_query fields onto ocsf.DnsActivity. The
// vocabulary is Sysmon 22's (QueryName, QueryResults, QueryStatus) plus
// the endpoint fields shared with network_connection.
var dnsAccessor = Accessor{
	"QueryName":  dnsQueryName,
	"Query":      dnsQueryName,
	"QueryType":  dnsQueryType,
	"QueryClass": dnsQueryClass,
	// QueryResults is multi-valued: every answer's rdata (an address, a
	// CNAME target, a TXT string) — so `QueryResults|cidr` and
	// `QueryResults|contains` both do what a Sysmon rule expects.
	"QueryResults":    dnsQueryResults,
	"QueryStatus":     dnsRCode,
	"RCode":           dnsRCode,
	"EventCode":       dnsEventCode,
	"EventType":       dnsEventCode,
	"DestinationIp":   dnsDstIP,
	"DestinationPort": dnsDstPort,
	"SourceIp":        dnsSrcIP,
	"Image":           func(e ocsf.Event) []string { return procExePath(actorProcess(e)) },
	"CommandLine":     func(e ocsf.Event) []string { return nonEmpty(actorProcess(e).Cmdline) },
	"User":            actorUserName,
	"ProcessId":       func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"PID":             func(e ocsf.Event) []string { return u32Str(actorProcess(e).PID) },
	"ContainerId":     actorContainerID,
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
	case *ocsf.Authentication:
		return v.Actor.Process
	case *ocsf.KernelActivity:
		return v.Actor.Process
	case *ocsf.ContainerLifecycle:
		return v.Actor.Process
	case *ocsf.DnsActivity:
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
	case *ocsf.Authentication:
		u = v.Actor.User
	case *ocsf.KernelActivity:
		u = v.Actor.User
	case *ocsf.ContainerLifecycle:
		u = v.Actor.User
	case *ocsf.DnsActivity:
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

func fileRenameToPath(e ocsf.Event) []string {
	f, ok := e.(*ocsf.FileSystemActivity)
	if !ok || f.RenameTo == nil {
		return nil
	}
	if f.RenameTo.Path != "" {
		return []string{f.RenameTo.Path}
	}
	if f.RenameTo.Name != "" {
		return []string{f.RenameTo.Name}
	}
	return nil
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

// --- authentication (3002) accessors ---------------------------------------

func authOf(e ocsf.Event) (*ocsf.Authentication, bool) {
	a, ok := e.(*ocsf.Authentication)
	return a, ok
}

func authUserName(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.User.Name)
}

func authService(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok || a.Service == nil {
		return nil
	}
	return nonEmpty(a.Service.Name)
}

func authEventCode(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.Metadata.EventCode)
}

func authStatusStr(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.Status)
}

func authStatusCode(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.StatusCode)
}

func authStatusDetail(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.StatusDetail)
}

func authSrcIP(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok || a.SrcEndpoint == nil {
		return nil
	}
	return nonEmpty(a.SrcEndpoint.IP)
}

func authSrcHost(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok || a.SrcEndpoint == nil {
		return nil
	}
	return nonEmpty(a.SrcEndpoint.Hostname)
}

func authRemoteHost(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok || a.SrcEndpoint == nil {
		return nil
	}
	if a.SrcEndpoint.IP != "" {
		return []string{a.SrcEndpoint.IP}
	}
	return nonEmpty(a.SrcEndpoint.Hostname)
}

func authLogonType(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.LogonType)
}

func authTTY(e ocsf.Event) []string {
	a, ok := authOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(a.TTY)
}

// --- kernel activity (1003) accessors --------------------------------------

func kernelOf(e ocsf.Event) (*ocsf.KernelActivity, bool) {
	k, ok := e.(*ocsf.KernelActivity)
	return k, ok
}

func kernelImageLoaded(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	if k.Kernel.Path != "" {
		return []string{k.Kernel.Path}
	}
	return nonEmpty(k.Kernel.Name)
}

func kernelName(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Kernel.Name)
}

func kernelType(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Kernel.Type)
}

func kernelEventCode(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Metadata.EventCode)
}

func kernelSystemCall(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Kernel.SystemCall)
}

func kernelStatus(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Status)
}

func kernelStatusCode(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.StatusCode)
}

func kernelStatusDetail(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.StatusDetail)
}

func kernelTaints(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return k.Kernel.Taints
}

func kernelProgType(e ocsf.Event) []string {
	k, ok := kernelOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(k.Kernel.ProgType)
}

// --- container lifecycle (6000) accessors + shared container id -------------

// actorContainerID is the container the acting process runs in, for
// every class that carries an actor process.
func actorContainerID(e ocsf.Event) []string {
	return nonEmpty(actorProcess(e).ContainerID)
}

func containerOf(e ocsf.Event) (*ocsf.ContainerLifecycle, bool) {
	c, ok := e.(*ocsf.ContainerLifecycle)
	return c, ok
}

func containerID(e ocsf.Event) []string {
	c, ok := containerOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(c.Container.UID)
}

func containerRuntime(e ocsf.Event) []string {
	c, ok := containerOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(c.Container.Runtime)
}

func containerEventCode(e ocsf.Event) []string {
	c, ok := containerOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(c.Metadata.EventCode)
}

func containerCgroupPath(e ocsf.Event) []string {
	c, ok := containerOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(c.Container.CgroupPath)
}

// --- dns activity (4003) accessors -----------------------------------------

func dnsOf(e ocsf.Event) (*ocsf.DnsActivity, bool) {
	d, ok := e.(*ocsf.DnsActivity)
	return d, ok
}

func dnsQueryName(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(d.Query.Name)
}

func dnsQueryType(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(d.Query.Type)
}

func dnsQueryClass(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(d.Query.Class)
}

func dnsQueryResults(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok || len(d.Answers) == 0 {
		return nil
	}
	out := make([]string, 0, len(d.Answers))
	for _, a := range d.Answers {
		if a.RData != "" {
			out = append(out, a.RData)
		}
	}
	return out
}

func dnsRCode(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(d.RCode)
}

func dnsEventCode(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok {
		return nil
	}
	return nonEmpty(d.Metadata.EventCode)
}

func dnsDstIP(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok || d.DstEndpoint == nil {
		return nil
	}
	return nonEmpty(d.DstEndpoint.IP)
}

func dnsDstPort(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok || d.DstEndpoint == nil || d.DstEndpoint.Port == 0 {
		return nil
	}
	return []string{strconv.FormatUint(uint64(d.DstEndpoint.Port), 10)}
}

func dnsSrcIP(e ocsf.Event) []string {
	d, ok := dnsOf(e)
	if !ok || d.SrcEndpoint == nil {
		return nil
	}
	return nonEmpty(d.SrcEndpoint.IP)
}
