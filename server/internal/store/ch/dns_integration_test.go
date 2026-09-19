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

// TestCH_DnsActivityRoundTrip pins dnsRow.bind's column order against
// migration 00010 with one response carrying two answers.
func TestCH_DnsActivityRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	env := setupCH(ctx, t)
	defer env.cleanup()

	host := uuid.New()
	cancelWriter, writerDone := startWriter(t, env, ch.WriterOptions{
		BatchSize: 100, FlushInterval: 100 * time.Millisecond, BusBuffer: 64,
	})

	now := time.Now().UnixMilli()
	ev := ocsf.DnsActivity{
		Metadata:    ocsf.Metadata{UID: uuid.NewString(), OriginalT: now, EventCode: "dns_response"},
		ClassUID:    ocsf.ClassDnsActivity,
		ClassName:   ocsf.ClassDnsActivity.String(),
		ActivityID:  ocsf.DnsActivityResponse,
		Severity:    ocsf.SeverityInformational,
		Time:        ocsf.TimeOCSF(now),
		Device:      ocsf.Device{HostID: host.String()},
		Actor:       ocsf.Actor{Process: ocsf.Process{PID: 700, Name: "curl"}},
		Query:       ocsf.DnsQuery{Name: "www.example.com", Type: "A", Class: "IN"},
		Answers:     []ocsf.DnsAnswer{{Type: "CNAME", RData: "edge.example.net"}, {Type: "A", RData: "203.0.113.9"}},
		RCode:       "NOERROR",
		SrcEndpoint: &ocsf.NetEndpoint{IP: "127.0.0.53", Port: 53},
		DstEndpoint: &ocsf.NetEndpoint{IP: "10.0.0.5", Port: 41000},
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
		ClassId:    pb.OcsfClassId_OCSF_CLASS_ID_DNS_ACTIVITY,
		ObservedAt: timestamppb.Now(), CollectedAt: timestamppb.Now(), Payload: payload,
	}
	env.bus.Publish(envl)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var got uint64
		if err := env.store.SQL().QueryRowContext(ctx,
			`SELECT count() FROM ocsf_dns_activity_4003 WHERE host_id = ?`, host).Scan(&got); err != nil {
			t.Fatalf("count: %v", err)
		}
		if got == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := env.writer.LastFlushErr(); err != nil {
		t.Fatalf("flush error (column order vs migration 00010?): %v", err)
	}

	var name, qtype, rcode, answers, dstIP string
	var dstPort uint16
	if err := env.store.SQL().QueryRowContext(ctx, `
		SELECT query_name, query_type, rcode, answers, dst_ip, dst_port
		FROM ocsf_dns_activity_4003 WHERE event_id = ?`, envl.GetEventId(),
	).Scan(&name, &qtype, &rcode, &answers, &dstIP, &dstPort); err != nil {
		t.Fatalf("select: %v", err)
	}
	if name != "www.example.com" || qtype != "A" || rcode != "NOERROR" || answers != "edge.example.net,203.0.113.9" || dstIP != "10.0.0.5" || dstPort != 41000 {
		t.Errorf("flat columns = %s/%s/%s/%s/%s/%d", name, qtype, rcode, answers, dstIP, dstPort)
	}

	rows, _, err := env.store.SearchEvents(ctx, ch.EventFilter{HostID: host.String(), ClassUIDs: []uint32{4003}}, ch.Cursor{}, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("SearchEvents: %v rows=%d", err, len(rows))
	}
	if rows[0].Summary != "dns_response A www.example.com NOERROR -> edge.example.net,203.0.113.9 by curl" {
		t.Errorf("summary = %q", rows[0].Summary)
	}

	cancelWriter()
	<-writerDone
}
