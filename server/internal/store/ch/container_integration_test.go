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

// TestCH_ContainerLifecycleRoundTrip pins containerRow.bind's column
// order against migration 00009.
func TestCH_ContainerLifecycleRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	const cid = "21473fb59dd89a9b9cff0ad8a1ceb82168feb3fc0ea41055565c26bd634bb4bd"
	host := uuid.New()
	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize: 100, FlushInterval: 100 * time.Millisecond, BusBuffer: 64,
	})

	now := time.Now().UnixMilli()
	ev := ocsf.ContainerLifecycle{
		Metadata:   ocsf.Metadata{UID: uuid.NewString(), OriginalT: now, EventCode: "container_start"},
		ClassUID:   ocsf.ClassContainerLifecycle,
		ClassName:  ocsf.ClassContainerLifecycle.String(),
		ActivityID: ocsf.ContainerActivityStart,
		Severity:   ocsf.SeverityInformational,
		Time:       ocsf.TimeOCSF(now),
		Device:     ocsf.Device{HostID: host.String()},
		Actor:      ocsf.Actor{Process: ocsf.Process{PID: 301, Name: "sh", Cmdline: "sh -c app"}},
		Container:  ocsf.Container{UID: cid, Runtime: "docker", CgroupPath: "/system.slice/docker-" + cid + ".scope", CgroupID: 777},
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	payload, err := json.Marshal(&ev)
	if err != nil {
		t.Fatal(err)
	}
	envl := &pb.Envelope{
		EventId: uuid.NewString(), HostId: host.String(),
		ClassId:    pb.OcsfClassId_OCSF_CLASS_ID_CONTAINER_LIFECYCLE,
		ObservedAt: timestamppb.Now(), CollectedAt: timestamppb.Now(), Payload: payload,
	}
	env.bus.Publish(envl)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_container_lifecycle_6000 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := env.writer.LastFlushErr(); err != nil {
		t.Fatalf("flush error (column order vs migration 00009?): %v", err)
	}

	var gotCID, runtime, path, cmdline string
	var actorPID uint32
	if err := env.store.SQL().QueryRowContext(ctx, `
		SELECT container_id, runtime, cgroup_path, actor_pid, actor_cmdline
		FROM ocsf_container_lifecycle_6000 WHERE event_id = ?`, envl.GetEventId(),
	).Scan(&gotCID, &runtime, &path, &actorPID, &cmdline); err != nil {
		t.Fatalf("select: %v", err)
	}
	if gotCID != cid || runtime != "docker" || path != ev.Container.CgroupPath || actorPID != 301 || cmdline != "sh -c app" {
		t.Errorf("flat columns = %s/%s/%s/%d/%s", gotCID, runtime, path, actorPID, cmdline)
	}

	rows, _, err := env.store.SearchEvents(ctx, ch.EventFilter{HostID: host.String(), ClassUIDs: []uint32{6000}}, ch.Cursor{}, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("SearchEvents: %v rows=%d", err, len(rows))
	}
	if rows[0].Summary != "container_start docker 21473fb59dd8 by sh" {
		t.Errorf("summary = %q", rows[0].Summary)
	}

	cancelWriter()
	<-writerDone
}
