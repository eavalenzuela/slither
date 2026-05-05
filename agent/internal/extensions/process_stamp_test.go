package extensions

import (
	"encoding/json"
	"testing"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// stampAndDecode is exercised end-to-end in TestProcess_EmitsStampedEventsThroughChannel
// for the process_activity case; this test exercises the per-class
// stamp paths cheaply (no socketpair, no spawn) so additions to the
// switch (e.g. kernel_activity in #109) are covered without adding
// minutes to the build.

func makeProcess() *Process {
	telem := telemetry.NewCounters()
	out := make(chan ocsf.Event, 4)
	return NewProcess(
		config.Extension{Name: "osquery"},
		DisabledVerifier{},
		ocsf.Device{HostID: "host-1", Hostname: "vm-1"},
		telem,
		out,
	)
}

func TestStampAndDecode_KernelActivity(t *testing.T) {
	p := makeProcess()
	payload, _ := json.Marshal(&ocsf.KernelActivity{
		ClassUID:   ocsf.ClassKernelActivity,
		ActivityID: ocsf.KernelActivityCreate,
		Kernel:     ocsf.KernelObject{Name: "nf_conntrack", Type: "Module"},
	})
	ev := p.stampAndDecode(&pb.OCSFEvent{
		ClassId: pb.OcsfClassId_OCSF_CLASS_ID_KERNEL_ACTIVITY,
		Payload: payload,
	})
	ka, ok := ev.(*ocsf.KernelActivity)
	if !ok {
		t.Fatalf("expected *KernelActivity, got %T", ev)
	}
	if ka.Device.HostID != "host-1" {
		t.Errorf("device not stamped: %+v", ka.Device)
	}
	if ka.Time == 0 {
		t.Error("time not stamped")
	}
	if ka.Metadata.Product.Name != "osquery (extension)" {
		t.Errorf("metadata.product.name=%q", ka.Metadata.Product.Name)
	}
	if ka.Kernel.Name != "nf_conntrack" {
		t.Errorf("kernel.name preserved? got %q", ka.Kernel.Name)
	}
}

func TestStampAndDecode_UnsupportedClassDrops(t *testing.T) {
	p := makeProcess()
	ev := p.stampAndDecode(&pb.OCSFEvent{
		ClassId: pb.OcsfClassId_OCSF_CLASS_ID_AUTHENTICATION,
		Payload: []byte(`{}`),
	})
	if ev != nil {
		t.Errorf("expected nil for unsupported class, got %T", ev)
	}
}
