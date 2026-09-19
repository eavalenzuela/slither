package ruleengine

import (
	"testing"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	"github.com/t3rmit3/slither/pkg/ruleast"
)

const testCID = "21473fb59dd89a9b9cff0ad8a1ceb82168feb3fc0ea41055565c26bd634bb4bd"

func containerProc(image, parent, cid string) *ocsf.ProcessActivity {
	ev := reconEvent(image, 300)
	ev.Process.ContainerID = cid
	ev.Process.Parent = &ocsf.Process{PID: 300, File: &ocsf.File{Path: parent}}
	return ev
}

func shippedProcRule(t *testing.T, file string) *sigmaCompiledRule {
	t.Helper()
	rules, err := CompileRules([]*ruleast.Rule{loadRule(t, "rules/linux/"+file)}, telemetry.NewCounters(), nil)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	return rules[0].(*sigmaCompiledRule)
}

func TestContainerKmodAndNamespaceToolsRequireContainer(t *testing.T) {
	kmod := shippedProcRule(t, "container-exec-kmod-tools.yml")
	ns := shippedProcRule(t, "container-exec-namespace-tools.yml")
	if !kmod.Match(containerProc("/usr/sbin/insmod", "/bin/sh", testCID)) {
		t.Error("insmod in a container should fire")
	}
	if kmod.Match(containerProc("/usr/sbin/insmod", "/bin/sh", "")) {
		t.Error("insmod on the host is proc-kmod-load-from-staging's job, not this rule's")
	}
	if kmod.Match(containerProc("/usr/bin/ls", "/bin/sh", testCID)) {
		t.Error("ls in a container must not fire")
	}
	if !ns.Match(containerProc("/usr/bin/nsenter", "/bin/sh", testCID)) || !ns.Match(containerProc("/usr/bin/mount", "/bin/sh", testCID)) {
		t.Error("nsenter / mount in a container should fire")
	}
	if ns.Match(containerProc("/usr/bin/mount", "/bin/sh", "")) {
		t.Error("mount on the host must not fire")
	}
}

func TestContainerRuntimeExecShell(t *testing.T) {
	scr := shippedProcRule(t, "container-runtime-exec-shell.yml")
	if !scr.Match(containerProc("/bin/sh", "/usr/bin/runc", testCID)) {
		t.Error("sh under runc in a container should fire")
	}
	if scr.Match(containerProc("/bin/sh", "/usr/bin/bash", testCID)) {
		t.Error("a shell spawned by a shell inside the container is not a runtime exec")
	}
	if scr.Match(containerProc("/bin/sh", "/usr/bin/runc", "")) {
		t.Error("no container id, no match")
	}
}
