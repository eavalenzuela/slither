//go:build integration

package ch_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/ch"
)

// TestCH_KernelActivityRoundTrip pins kernelRow.bind's column order
// against migration 00008 with one tainted module load and one
// rejected load, then checks the class is searchable with a readable
// summary.
func TestCH_KernelActivityRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	host := uuid.New()
	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize: 100, FlushInterval: 100 * time.Millisecond, BusBuffer: 64,
	})

	loaded := makeKernelEnvelope(t, host, ocsf.KernelActivity{
		Metadata:   ocsf.Metadata{EventCode: "module_load"},
		ActivityID: ocsf.KernelActivityCreate,
		Kernel:     ocsf.KernelObject{Name: "rk", Type: "Module", SystemCall: "init_module", Taints: []string{"out_of_tree", "unsigned_module"}},
		Status:     "Success", StatusID: 1,
		Actor: ocsf.Actor{Process: ocsf.Process{PID: 500, Name: "insmod", Cmdline: "insmod /tmp/rk.ko"}},
	})
	rejected := makeKernelEnvelope(t, host, ocsf.KernelActivity{
		Metadata:   ocsf.Metadata{EventCode: "module_load_rejected"},
		ActivityID: ocsf.KernelActivityCreate,
		Kernel:     ocsf.KernelObject{Type: "Module", SystemCall: "init_module"},
		Status:     "Failure", StatusID: 2, StatusCode: "129", StatusDetail: "EKEYREJECTED",
		Actor: ocsf.Actor{Process: ocsf.Process{PID: 501, Name: "insmod", Cmdline: "insmod /tmp/evil.ko"}},
	})
	env.bus.Publish(loaded)
	env.bus.Publish(rejected)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_kernel_activity_1003 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := env.writer.LastFlushErr(); err != nil {
		t.Fatalf("flush error (column order vs migration 00008?): %v", err)
	}

	var (
		ktype, kname, syscall, taints, detail, cmdline string
		statusID                                       uint8
		code                                           int32
	)
	if err := env.store.SQL().QueryRowContext(ctx, `
		SELECT kernel_type, kernel_name, system_call, taints, status_id, status_code, status_detail, actor_cmdline
		FROM ocsf_kernel_activity_1003 WHERE event_id = ?`, rejected.GetEventId(),
	).Scan(&ktype, &kname, &syscall, &taints, &statusID, &code, &detail, &cmdline); err != nil {
		t.Fatalf("select rejected row: %v", err)
	}
	if ktype != "Module" || kname != "" || syscall != "init_module" || taints != "" || statusID != 2 || code != 129 || detail != "EKEYREJECTED" || cmdline != "insmod /tmp/evil.ko" {
		t.Errorf("flat columns = %s/%s/%s/%s/%d/%d/%s/%s", ktype, kname, syscall, taints, statusID, code, detail, cmdline)
	}

	rows, _, err := env.store.SearchEvents(ctx, ch.EventFilter{HostID: host.String(), ClassUIDs: []uint32{1003}}, ch.Cursor{}, 10)
	if err != nil {
		t.Fatalf("SearchEvents: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("SearchEvents returned %d rows, want 2", len(rows))
	}
	summaries := map[string]string{}
	for _, r := range rows {
		summaries[r.EventID] = r.Summary
	}
	if s := summaries[loaded.GetEventId()]; s != "module_load Module rk taints=out_of_tree,unsigned_module by insmod" {
		t.Errorf("loaded summary = %q", s)
	}
	if s := summaries[rejected.GetEventId()]; s != "module_load_rejected Module  by insmod EKEYREJECTED" {
		t.Errorf("rejected summary = %q", s)
	}

	cancelWriter()
	<-writerDone
}

func makeKernelEnvelope(t *testing.T, hostID uuid.UUID, ev ocsf.KernelActivity) *pb.Envelope {
	t.Helper()
	now := time.Now().UnixMilli()
	ev.Metadata.UID = uuid.NewString()
	ev.Metadata.OriginalT = now
	ev.ClassUID = ocsf.ClassKernelActivity
	ev.ClassName = ocsf.ClassKernelActivity.String()
	ev.Severity = ocsf.SeverityInformational
	ev.Time = ocsf.TimeOCSF(now)
	ev.Device = ocsf.Device{HostID: hostID.String()}
	if err := ev.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	payload, err := json.Marshal(&ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &pb.Envelope{
		EventId:     uuid.NewString(),
		HostId:      hostID.String(),
		ClassId:     pb.OcsfClassId_OCSF_CLASS_ID_KERNEL_ACTIVITY,
		ObservedAt:  timestamppb.Now(),
		CollectedAt: timestamppb.Now(),
		Payload:     payload,
	}
}
