package enricher

import (
	"context"
	"strconv"

	"github.com/t3rmit3/slither/agent/internal/pipeline"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// handleKernel converts a raw kernel-activity event into an OCSF
// KernelActivity (1003) event. The agent's own BPF program loads and
// probe attaches are dropped here by pid: they happen on every start
// and collector restart and would otherwise be the loudest thing in
// the class.
func (e *enricher) handleKernel(ctx context.Context, raw pipeline.RawKernelEvent) {
	if raw.Kind == pipeline.KernelUnknown {
		e.telem.IncDrops()
		return
	}
	if e.selfPID != 0 && raw.PID == e.selfPID {
		return
	}

	ent, ok := e.cache.get(raw.PID)
	if !ok {
		ent = procEntry{pid: raw.PID, uid: raw.UID, comm: raw.Comm}
		if exe := e.proc.exe(raw.PID); exe != "" {
			ent.exe = exe
		}
		if cmd := e.proc.cmdline(raw.PID); cmd != "" {
			ent.cmdline = cmd
		}
	}
	if ent.comm == "" {
		ent.comm = raw.Comm
	}

	ev := e.buildKernelOCSF(raw, ent)

	select {
	case e.out <- ev:
	case <-ctx.Done():
	default:
		e.telem.IncDropEnricher()
	}
}

func (e *enricher) buildKernelOCSF(raw pipeline.RawKernelEvent, ent procEntry) *ocsf.KernelActivity {
	username := e.users.Name(ent.uid)
	actorProc := processFromEntry(ent, username)

	activity := kernelActivityID(raw.Kind)
	ts := raw.Timestamp.UnixMilli()

	ev := &ocsf.KernelActivity{
		Metadata: ocsf.Metadata{
			Version:   ocsf.Version,
			Product:   slitherProduct(),
			LogName:   "kernel",
			EventCode: kernelEventCode(raw.Kind),
			UID:       ocsf.NewUID(),
			OriginalT: ts,
		},
		ClassUID:   ocsf.ClassKernelActivity,
		ClassName:  ocsf.ClassKernelActivity.String(),
		ActivityID: activity,
		TypeUID:    uint64(ocsf.ClassKernelActivity)*100 + uint64(activity),
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     e.opts.Device,
		Actor: ocsf.Actor{
			Process: *actorProc,
			User: ocsf.User{
				UID:  actorProc.UID,
				Name: username,
				Type: userType(ent.uid),
			},
		},
		Kernel: ocsf.KernelObject{
			Name:       raw.Name,
			SystemCall: raw.SystemCall,
		},
		Status:   "Success",
		StatusID: 1,
	}

	switch raw.Kind {
	case pipeline.KernelModuleLoad:
		ev.Kernel.Type = "Module"
		ev.Kernel.Taints = taintNames(raw.Taints)
	case pipeline.KernelModuleUnload:
		ev.Kernel.Type = "Module"
	case pipeline.KernelModuleLoadRejected:
		ev.Kernel.Type = "Module"
		ev.Status = "Failure"
		ev.StatusID = 2
		ev.StatusCode = strconv.FormatInt(int64(raw.Errno), 10)
		ev.StatusDetail = errnoName(raw.Errno)
	case pipeline.KernelBPFProgLoad:
		ev.Kernel.Type = "BPF Program"
		ev.Kernel.ProgType = bpfProgTypeName(raw.ProgType)
	case pipeline.KernelProbeAttach:
		ev.Kernel.Type = probeTypeName(raw.Probe, raw.Retprobe)
		if raw.Probe == "uprobe" {
			ev.Kernel.Path = raw.Name
		}
		if raw.Offset != 0 {
			ev.Kernel.Offset = "0x" + strconv.FormatUint(raw.Offset, 16)
		}
	}
	return ev
}

func kernelActivityID(k pipeline.RawKernelKind) ocsf.KernelActivityID {
	switch k {
	case pipeline.KernelModuleLoad, pipeline.KernelModuleLoadRejected:
		return ocsf.KernelActivityCreate
	case pipeline.KernelModuleUnload:
		return ocsf.KernelActivityDelete
	case pipeline.KernelBPFProgLoad, pipeline.KernelProbeAttach:
		return ocsf.KernelActivityInvoke
	default:
		return ocsf.KernelActivityOther
	}
}

func kernelEventCode(k pipeline.RawKernelKind) string {
	switch k {
	case pipeline.KernelModuleLoad:
		return "module_load"
	case pipeline.KernelModuleUnload:
		return "module_unload"
	case pipeline.KernelModuleLoadRejected:
		return "module_load_rejected"
	case pipeline.KernelBPFProgLoad:
		return "bpf_prog_load"
	case pipeline.KernelProbeAttach:
		return "probe_attach"
	default:
		return "unknown"
	}
}

func probeTypeName(probe string, ret bool) string {
	switch probe {
	case "kprobe":
		if ret {
			return "Kretprobe"
		}
		return "Kprobe"
	case "uprobe":
		if ret {
			return "Uretprobe"
		}
		return "Uprobe"
	}
	return "Probe"
}

// taintNames expands a module's taint mask into names. Bit positions are
// the TAINT_* constants in include/linux/panic.h; the letter each maps
// to in /proc/sys/kernel/tainted is noted for operators used to those.
var taintBitNames = [...]string{
	"proprietary_module",    // 0  P
	"forced_module",         // 1  F
	"cpu_out_of_spec",       // 2  S
	"forced_rmmod",          // 3  R
	"machine_check",         // 4  M
	"bad_page",              // 5  B
	"user",                  // 6  U
	"die",                   // 7  D
	"overridden_acpi_table", // 8  A
	"warn",                  // 9  W
	"staging",               // 10 C
	"firmware_workaround",   // 11 I
	"out_of_tree",           // 12 O
	"unsigned_module",       // 13 E
	"softlockup",            // 14 L
	"livepatch",             // 15 K
	"aux",                   // 16 X
	"randstruct",            // 17 T
	"test",                  // 18 N
	"fwctl",                 // 19 J
}

func taintNames(mask uint32) []string {
	if mask == 0 {
		return nil
	}
	var out []string
	for bit := 0; bit < 32; bit++ {
		if mask&(1<<bit) == 0 {
			continue
		}
		if bit < len(taintBitNames) {
			out = append(out, taintBitNames[bit])
		} else {
			out = append(out, "taint_"+strconv.Itoa(bit))
		}
	}
	return out
}

// bpfProgTypeName names enum bpf_prog_type values (uapi/linux/bpf.h).
var bpfProgTypeNames = [...]string{
	"unspec", "socket_filter", "kprobe", "sched_cls", "sched_act",
	"tracepoint", "xdp", "perf_event", "cgroup_skb", "cgroup_sock",
	"lwt_in", "lwt_out", "lwt_xmit", "sock_ops", "sk_skb",
	"cgroup_device", "sk_msg", "raw_tracepoint", "cgroup_sock_addr",
	"lwt_seg6local", "lirc_mode2", "sk_reuseport", "flow_dissector",
	"cgroup_sysctl", "raw_tracepoint_writable", "cgroup_sockopt",
	"tracing", "struct_ops", "ext", "lsm", "sk_lookup", "syscall",
	"netfilter",
}

func bpfProgTypeName(t uint32) string {
	if int(t) < len(bpfProgTypeNames) {
		return bpfProgTypeNames[t]
	}
	return "prog_type_" + strconv.FormatUint(uint64(t), 10)
}

// errnoName names the errnos a module load can fail with. The ones an
// operator needs to recognise on sight are the signature and lockdown
// family; everything else falls back to E<n>.
func errnoName(n int32) string {
	switch n {
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 8:
		return "ENOEXEC"
	case 12:
		return "ENOMEM"
	case 13:
		return "EACCES"
	case 14:
		return "EFAULT"
	case 16:
		return "EBUSY"
	case 17:
		return "EEXIST"
	case 22:
		return "EINVAL"
	case 65:
		return "ENOPKG"
	case 74:
		return "EBADMSG"
	case 75:
		return "EOVERFLOW"
	case 80:
		return "ELIBBAD"
	case 126:
		return "ENOKEY"
	case 127:
		return "EKEYEXPIRED"
	case 128:
		return "EKEYREVOKED"
	case 129:
		return "EKEYREJECTED"
	}
	return "E" + strconv.FormatInt(int64(n), 10)
}
