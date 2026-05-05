package mappers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/t3rmit3/slither/pkg/ocsf"
)

func loadFixture(t *testing.T, name string) Row {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var row Row
	if err := json.Unmarshal(b, &row); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return row
}

func TestProcessEvents_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "process_events.json")
	ev, err := ProcessEvents(row)
	if err != nil {
		t.Fatalf("ProcessEvents: %v", err)
	}
	pa, ok := ev.(*ocsf.ProcessActivity)
	if !ok {
		t.Fatalf("expected *ProcessActivity, got %T", ev)
	}
	if pa.ActivityID != ocsf.ProcessActivityLaunch {
		t.Errorf("activity_id=%d, want Launch", pa.ActivityID)
	}
	if pa.Process.PID != 12345 {
		t.Errorf("process.pid=%d, want 12345", pa.Process.PID)
	}
	if pa.Process.Cmdline != "sshd -D" {
		t.Errorf("cmd=%q", pa.Process.Cmdline)
	}
	if pa.Process.File == nil || pa.Process.File.Path != "/usr/bin/sshd" {
		t.Errorf("process.file.path missing")
	}
	if pa.Process.Parent == nil || pa.Process.Parent.PID != 1 {
		t.Errorf("parent missing")
	}
}

func TestProcessEvents_ExitMapsTerminate(t *testing.T) {
	row := Row{"pid": "100", "syscall": "exit"}
	ev, err := ProcessEvents(row)
	if err != nil {
		t.Fatalf("ProcessEvents: %v", err)
	}
	pa := ev.(*ocsf.ProcessActivity)
	if pa.ActivityID != ocsf.ProcessActivityTerminate {
		t.Errorf("activity_id=%d, want Terminate", pa.ActivityID)
	}
}

func TestProcessEvents_MissingPIDFails(t *testing.T) {
	if _, err := ProcessEvents(Row{}); err == nil {
		t.Fatal("expected error from missing pid")
	}
}

func TestSocketEvents_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "socket_events.json")
	ev, err := SocketEvents(row)
	if err != nil {
		t.Fatalf("SocketEvents: %v", err)
	}
	na := ev.(*ocsf.NetworkActivity)
	if na.ActivityID != ocsf.NetActivityOpen {
		t.Errorf("activity_id=%d, want Open", na.ActivityID)
	}
	if na.Connection.Protocol != "tcp" {
		t.Errorf("protocol=%q, want tcp", na.Connection.Protocol)
	}
	if na.DstEndpoint.IP != "1.2.3.4" || na.DstEndpoint.Port != 443 {
		t.Errorf("dst endpoint wrong: %+v", na.DstEndpoint)
	}
	if na.SrcEndpoint.IP != "10.0.0.5" || na.SrcEndpoint.Port != 55432 {
		t.Errorf("src endpoint wrong: %+v", na.SrcEndpoint)
	}
	if na.Actor.Process.PID != 999 {
		t.Errorf("actor.pid=%d, want 999", na.Actor.Process.PID)
	}
}

func TestSocketEvents_BindMapsToListen(t *testing.T) {
	row := Row{"action": "bind", "protocol": "tcp", "local_port": "22", "pid": "1"}
	ev, _ := SocketEvents(row)
	na := ev.(*ocsf.NetworkActivity)
	if na.ActivityID != ocsf.NetActivityListen {
		t.Errorf("bind should map to NetActivityListen, got %d", na.ActivityID)
	}
	if na.Connection.Direction != "inbound" {
		t.Errorf("bind direction=%q, want inbound", na.Connection.Direction)
	}
}

func TestFileEvents_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "file_events.json")
	ev, err := FileEvents(row)
	if err != nil {
		t.Fatalf("FileEvents: %v", err)
	}
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.ActivityID != ocsf.FileActivityUpdate {
		t.Errorf("activity_id=%d, want Update", fa.ActivityID)
	}
	if fa.File.Path != "/etc/passwd" {
		t.Errorf("file.path=%q", fa.File.Path)
	}
	if fa.File.HashesSHA256 != "abc123" {
		t.Errorf("sha256 missing")
	}
}

func TestFileEvents_RenameProducesRenameTo(t *testing.T) {
	row := Row{"target_path": "/tmp/new", "action": "MOVED_TO"}
	ev, err := FileEvents(row)
	if err != nil {
		t.Fatalf("FileEvents: %v", err)
	}
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.ActivityID != ocsf.FileActivityRename {
		t.Errorf("activity_id=%d, want Rename", fa.ActivityID)
	}
	if fa.RenameTo == nil || fa.RenameTo.Path != "/tmp/new" {
		t.Errorf("rename_to missing")
	}
}

func TestListeningPorts_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "listening_ports.json")
	ev, err := ListeningPorts(row)
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	na := ev.(*ocsf.NetworkActivity)
	if na.ActivityID != ocsf.NetActivityListen {
		t.Errorf("activity_id=%d, want Listen", na.ActivityID)
	}
	if na.SrcEndpoint.Port != 22 {
		t.Errorf("port=%d, want 22", na.SrcEndpoint.Port)
	}
	if na.Connection.Protocol != "tcp" {
		t.Errorf("protocol=%q", na.Connection.Protocol)
	}
}

func TestListeningPorts_UDPMaps(t *testing.T) {
	row := Row{"protocol": "17", "address": "0.0.0.0", "port": "53", "pid": "1"}
	ev, _ := ListeningPorts(row)
	na := ev.(*ocsf.NetworkActivity)
	if na.Connection.Protocol != "udp" {
		t.Errorf("protocol=%q, want udp", na.Connection.Protocol)
	}
}

func TestKernelModules_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "kernel_modules.json")
	ev, err := KernelModules(row)
	if err != nil {
		t.Fatalf("KernelModules: %v", err)
	}
	ka := ev.(*ocsf.KernelActivity)
	if ka.Kernel.Name != "nf_conntrack" {
		t.Errorf("name=%q", ka.Kernel.Name)
	}
	if ka.Kernel.Type != "Module" {
		t.Errorf("type=%q", ka.Kernel.Type)
	}
	if ka.Severity != ocsf.SeverityInformational {
		t.Errorf("Live should map to Informational, got %d", ka.Severity)
	}
}

func TestKernelModules_NonLiveBumpsSeverity(t *testing.T) {
	row := Row{"name": "x", "status": "Loading"}
	ev, _ := KernelModules(row)
	ka := ev.(*ocsf.KernelActivity)
	if ka.Severity != ocsf.SeverityLow {
		t.Errorf("non-Live should be SeverityLow, got %d", ka.Severity)
	}
}

func TestSSHKeys_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "ssh_keys.json")
	ev, err := SSHKeys(row)
	if err != nil {
		t.Fatalf("SSHKeys: %v", err)
	}
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.File.Path != "/home/alice/.ssh/id_ed25519" {
		t.Errorf("path wrong: %q", fa.File.Path)
	}
	if fa.File.Type != "ssh_private_key" {
		t.Errorf("type=%q", fa.File.Type)
	}
	if fa.Severity != ocsf.SeverityLow {
		t.Errorf("unencrypted should be Low, got %d", fa.Severity)
	}
}

func TestAuthorizedKeys_FixtureRoundtrip(t *testing.T) {
	row := loadFixture(t, "authorized_keys.json")
	ev, err := AuthorizedKeys(row)
	if err != nil {
		t.Fatalf("AuthorizedKeys: %v", err)
	}
	fa := ev.(*ocsf.FileSystemActivity)
	if fa.File.Path != "/root/.ssh/authorized_keys" {
		t.Errorf("path=%q", fa.File.Path)
	}
	if fa.File.Type != "ssh-ed25519" {
		t.Errorf("type=%q, want ssh-ed25519", fa.File.Type)
	}
}
