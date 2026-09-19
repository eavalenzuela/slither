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

// TestCH_AuthenticationRoundTrip is the only check that authRow.bind's
// column order matches migration 00007: publish one failed sshd
// credential check and one sudo session open, then read the flat
// columns back and confirm the class shows up in SearchEvents with a
// readable summary and in GetEventByID.
func TestCH_AuthenticationRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	host := uuid.New()
	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize:     100,
		FlushInterval: 100 * time.Millisecond,
		BusBuffer:     64,
	})

	failed := makeAuthEnvelope(t, host, ocsf.Authentication{
		Metadata:     ocsf.Metadata{EventCode: "auth_attempt"},
		ActivityID:   ocsf.AuthActivityLogon,
		User:         ocsf.User{Name: "alice"},
		Status:       "Failure",
		StatusID:     2,
		StatusCode:   "7",
		StatusDetail: "PAM_AUTH_ERR",
		LogonTypeID:  10,
		Service:      &ocsf.Service{Name: "sshd"},
		SrcEndpoint:  &ocsf.NetEndpoint{IP: "203.0.113.9"},
		Actor:        ocsf.Actor{Process: ocsf.Process{PID: 900, Name: "sshd"}},
	})
	opened := makeAuthEnvelope(t, host, ocsf.Authentication{
		Metadata:     ocsf.Metadata{EventCode: "session_open"},
		ActivityID:   ocsf.AuthActivityLogon,
		User:         ocsf.User{Name: "bob"},
		Status:       "Success",
		StatusID:     1,
		StatusCode:   "0",
		StatusDetail: "PAM_SUCCESS",
		LogonTypeID:  99,
		Service:      &ocsf.Service{Name: "sudo"},
		Actor:        ocsf.Actor{Process: ocsf.Process{PID: 77, Name: "sudo"}},
	})
	env.bus.Publish(failed)
	env.bus.Publish(opened)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_authentication_3002 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := env.writer.LastFlushErr(); err != nil {
		t.Fatalf("flush error (column order vs migration 00007?): %v", err)
	}

	var (
		service, user, srcIP, detail string
		statusID, logon              uint8
		code                         int32
		actorPID                     uint32
	)
	if err := env.store.SQL().QueryRowContext(ctx, `
		SELECT service, user_name, src_ip, status_id, status_code, status_detail, logon_type_id, actor_pid
		FROM ocsf_authentication_3002 WHERE event_id = ?`, failed.GetEventId(),
	).Scan(&service, &user, &srcIP, &statusID, &code, &detail, &logon, &actorPID); err != nil {
		t.Fatalf("select failed row: %v", err)
	}
	if service != "sshd" || user != "alice" || srcIP != "203.0.113.9" || statusID != 2 || code != 7 || detail != "PAM_AUTH_ERR" || logon != 10 || actorPID != 900 {
		t.Errorf("flat columns = %s/%s/%s/%d/%d/%s/%d/%d", service, user, srcIP, statusID, code, detail, logon, actorPID)
	}

	rows, _, err := env.store.SearchEvents(ctx, ch.EventFilter{
		HostID: host.String(), ClassUIDs: []uint32{3002},
	}, ch.Cursor{}, 10)
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
	if s := summaries[failed.GetEventId()]; s != "auth_attempt sshd user=alice from=203.0.113.9 PAM_AUTH_ERR" {
		t.Errorf("failed summary = %q", s)
	}
	if s := summaries[opened.GetEventId()]; s != "session_open sudo user=bob ok" {
		t.Errorf("opened summary = %q", s)
	}

	detailRow, err := env.store.GetEventByID(ctx, 3002, failed.GetEventId())
	if err != nil {
		t.Fatalf("GetEventByID: %v", err)
	}
	if detailRow.ClassUID != 3002 {
		t.Errorf("detail class = %d", detailRow.ClassUID)
	}

	cancelWriter()
	<-writerDone
}

func makeAuthEnvelope(t *testing.T, hostID uuid.UUID, ev ocsf.Authentication) *pb.Envelope {
	t.Helper()
	now := time.Now().UnixMilli()
	ev.Metadata.UID = uuid.NewString()
	ev.Metadata.OriginalT = now
	ev.ClassUID = ocsf.ClassAuthentication
	ev.ClassName = ocsf.ClassAuthentication.String()
	ev.Severity = ocsf.SeverityInformational
	ev.Time = ocsf.TimeOCSF(now)
	ev.Device = ocsf.Device{HostID: hostID.String()}
	ev.AuthProto = "pam"
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
		ClassId:     pb.OcsfClassId_OCSF_CLASS_ID_AUTHENTICATION,
		ObservedAt:  timestamppb.Now(),
		CollectedAt: timestamppb.Now(),
		Payload:     payload,
	}
}
