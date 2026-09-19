package ruleengine

import (
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

func kernelEvent(eventCode, ktype, name, image string, mutate func(*ocsf.KernelActivity)) *ocsf.KernelActivity {
	ts := time.Now().UnixMilli()
	ev := &ocsf.KernelActivity{
		Metadata:   ocsf.Metadata{Version: ocsf.Version, OriginalT: ts, UID: "ev-k", EventCode: eventCode},
		ClassUID:   ocsf.ClassKernelActivity,
		ClassName:  ocsf.ClassKernelActivity.String(),
		ActivityID: ocsf.KernelActivityCreate,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(ts),
		Device:     ocsf.Device{HostID: "host-a"},
		Actor: ocsf.Actor{
			Process: ocsf.Process{PID: 500, Name: "x", File: &ocsf.File{Path: image}},
			User:    ocsf.User{Name: "root", UID: "0"},
		},
		Kernel:   ocsf.KernelObject{Name: name, Type: ktype},
		Status:   "Success",
		StatusID: 1,
	}
	if mutate != nil {
		mutate(ev)
	}
	return ev
}

func shippedKernelRule(t *testing.T, file string) *sigmaCompiledRule {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{loadRule(t, "rules/linux/"+file)}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	return rules[0].(*sigmaCompiledRule)
}

func TestKmodLoadRejectedSignature(t *testing.T) {
	scr := shippedKernelRule(t, "kmod-load-rejected-signature.yml")
	rejected := func(detail string) *ocsf.KernelActivity {
		return kernelEvent("module_load_rejected", "Module", "", "/usr/sbin/insmod", func(k *ocsf.KernelActivity) {
			k.Status, k.StatusID, k.StatusDetail = "Failure", 2, detail
		})
	}
	for _, d := range []string{"EKEYREJECTED", "ENOKEY", "EPERM", "EBADMSG"} {
		if !scr.Match(rejected(d)) {
			t.Errorf("%s should fire", d)
		}
	}
	for _, d := range []string{"ENOENT", "ENOEXEC", "EEXIST", "EBUSY"} {
		if scr.Match(rejected(d)) {
			t.Errorf("%s (not a signature/lockdown code) should not fire", d)
		}
	}
	if scr.Match(kernelEvent("module_load", "Module", "rk", "/usr/sbin/insmod", nil)) {
		t.Error("a successful load must not fire the rejected rule")
	}
}

func TestKmodTaintRulesSplitHighAndLow(t *testing.T) {
	unsigned := shippedKernelRule(t, "kmod-load-unsigned.yml")
	oot := shippedKernelRule(t, "kmod-load-out-of-tree.yml")
	with := func(taints ...string) *ocsf.KernelActivity {
		return kernelEvent("module_load", "Module", "m", "/usr/sbin/modprobe", func(k *ocsf.KernelActivity) { k.Kernel.Taints = taints })
	}
	if !unsigned.Match(with("out_of_tree", "unsigned_module")) || oot.Match(with("unsigned_module")) {
		t.Error("unsigned_module belongs to the high rule only")
	}
	if !oot.Match(with("out_of_tree")) || unsigned.Match(with("out_of_tree")) {
		t.Error("out_of_tree alone belongs to the low rule only")
	}
	if unsigned.Match(with()) || oot.Match(with()) {
		t.Error("an in-tree signed module must fire neither")
	}
	if unsigned.Match(kernelEvent("module_unload", "Module", "m", "/usr/sbin/rmmod", func(k *ocsf.KernelActivity) { k.Kernel.Taints = []string{"unsigned_module"} })) {
		t.Error("unload must not fire the load rule")
	}
}

func TestKmodBPFTracingProgLoadFilter(t *testing.T) {
	scr := shippedKernelRule(t, "kmod-bpf-tracing-prog-load.yml")
	load := func(progType, image string) *ocsf.KernelActivity {
		return kernelEvent("bpf_prog_load", "BPF Program", "hook", image, func(k *ocsf.KernelActivity) {
			k.ActivityID = ocsf.KernelActivityInvoke
			k.Kernel.ProgType = progType
		})
	}
	if !scr.Match(load("kprobe", "/tmp/rk")) || !scr.Match(load("xdp", "/opt/x/loader")) {
		t.Error("tracing/packet-path program from an unknown loader should fire")
	}
	if scr.Match(load("cgroup_skb", "/usr/lib/systemd/systemd")) || scr.Match(load("socket_filter", "/usr/sbin/tcpdump")) {
		t.Error("cgroup and socket program types are out of scope")
	}
	if scr.Match(load("kprobe", "/usr/local/bin/slither-agent")) || scr.Match(load("tracepoint", "/usr/bin/bpftrace")) {
		t.Error("expected loaders are filtered")
	}
}

func TestKmodProbeAttachFilter(t *testing.T) {
	scr := shippedKernelRule(t, "kmod-probe-attach-unexpected.yml")
	probe := func(image string) *ocsf.KernelActivity {
		return kernelEvent("probe_attach", "Uprobe", "/usr/lib/libssl.so.3", image, func(k *ocsf.KernelActivity) {
			k.ActivityID = ocsf.KernelActivityInvoke
		})
	}
	if !scr.Match(probe("/tmp/stealer")) {
		t.Error("probe from an unknown process should fire")
	}
	if scr.Match(probe("/usr/bin/bpftrace")) || scr.Match(probe("/usr/local/bin/slither-agent")) {
		t.Error("expected tracers are filtered")
	}
}
