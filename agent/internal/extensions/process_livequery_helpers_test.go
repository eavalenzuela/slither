//go:build linux

package extensions

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
)

func newCountersForTest() *telemetry.Counters { return telemetry.NewCounters() }
func newOcsfChan() chan ocsf.Event            { return make(chan ocsf.Event, 16) }
func testDevice() ocsf.Device {
	return ocsf.Device{HostID: "test-host", Hostname: "test"}
}

// stubLiveQueryBinary builds a tiny extension binary that:
//  1. sends Hello with OCSF_EMIT + LIVE_QUERY_RESPOND,
//  2. reads one AgentToExtension envelope (the LiveQueryRequest),
//  3. replies with two LiveQueryRow + one LiveQueryComplete,
//  4. exits cleanly so the supervisor sees EOF.
func stubLiveQueryBinary(t *testing.T) string {
	t.Helper()
	src := `package main

import (
	"os"

	"github.com/t3rmit3/slither/pkg/extsdk"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

func main() {
	wire := os.NewFile(3, "wire")
	if wire == nil { os.Exit(2) }

	_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_Hello{Hello: &pb.Hello{
			Name:    "stub",
			Version: "v0",
			Capabilities: []pb.Capability{
				pb.Capability_CAPABILITY_OCSF_EMIT,
				pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND,
			},
		}},
	})

	msg, err := extsdk.ReadAgentToExtension(wire)
	if err != nil { os.Exit(3) }
	req := msg.GetLiveQueryRequest()
	if req == nil { os.Exit(4) }

	for i := 0; i < 2; i++ {
		_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_LiveQueryRow{LiveQueryRow: &pb.LiveQueryRow{
				QueryId: req.QueryId,
				Columns: []string{"col"},
				Values:  []string{"val"},
			}},
		})
	}
	_ = extsdk.WriteExtensionToAgent(wire, &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_LiveQueryComplete{LiveQueryComplete: &pb.LiveQueryComplete{
			QueryId:  req.QueryId,
			RowCount: 2,
		}},
	})
	_ = wire.Close()
}
`
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	bin := filepath.Join(dir, "stub-livequery")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", bin, srcFile)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile stub: %v\n%s", err, out)
	}
	return bin
}

func liveQueryConfig(bin string) config.Extension {
	return config.Extension{
		Name:                  "stub",
		BinaryPath:            bin,
		Capabilities:          []string{"ocsf_emit", "live_query_respond"},
		SignatureVerification: "disabled",
	}
}
