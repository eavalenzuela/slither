package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/extensions/osquery/internal/mappers"
	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

type fakeClient struct {
	mu        sync.Mutex
	queries   []string
	rowsByTbl map[string][]Row
	err       error
}

func (f *fakeClient) QueryRows(ctx context.Context, sql string) ([]Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, sql)
	if f.err != nil {
		return nil, f.err
	}
	for tbl, rows := range f.rowsByTbl {
		if strings.Contains(sql, "FROM "+tbl) {
			return rows, nil
		}
	}
	return nil, nil
}

func (f *fakeClient) Close() error { return nil }

func recordingSender() (Sender, *[]*pb.ExtensionToAgent) {
	var mu sync.Mutex
	var got []*pb.ExtensionToAgent
	return func(env *pb.ExtensionToAgent) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, env)
		return nil
	}, &got
}

func TestPump_ProcessEvent_RoundtripsThroughMapperAndEnvelope(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"process_events": {
				{"pid": "100", "path": "/usr/bin/sshd", "cmdline": "sshd -D", "syscall": "execve", "time": "1714502400"},
			},
		},
	}
	send, got := recordingSender()

	tables := []TableSpec{{
		Name:    "process_events",
		SQL:     "SELECT * FROM process_events WHERE time > {since}",
		ClassID: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		Mapper:  mappers.ProcessEvents,
	}}
	pump := NewPump(fake, tables, time.Hour, send)
	pump.tick(context.Background())

	if len(*got) != 1 {
		t.Fatalf("expected 1 envelope, got %d", len(*got))
	}
	ev := (*got)[0].GetOcsfEvent()
	if ev == nil {
		t.Fatalf("envelope payload is not OCSFEvent: %T", (*got)[0].Payload)
		return
	}
	if ev.ClassId != pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY {
		t.Errorf("class_id=%v", ev.ClassId)
	}
	var pa ocsf.ProcessActivity
	if err := json.Unmarshal(ev.Payload, &pa); err != nil {
		t.Fatalf("payload not OCSF process_activity json: %v", err)
	}
	if pa.Process.PID != 100 {
		t.Errorf("pid=%d", pa.Process.PID)
	}
	if pa.ActivityID != ocsf.ProcessActivityLaunch {
		t.Errorf("activity=%d", pa.ActivityID)
	}
}

func TestPump_AdvancesCursorOnEventTables(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"process_events": {
				{"pid": "1", "syscall": "execve", "time": "100"},
				{"pid": "2", "syscall": "execve", "time": "200"},
			},
		},
	}
	send, _ := recordingSender()
	tables := []TableSpec{{
		Name:    "process_events",
		SQL:     "SELECT * FROM process_events WHERE time > {since}",
		ClassID: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		Mapper:  mappers.ProcessEvents,
	}}
	pump := NewPump(fake, tables, time.Hour, send)
	pump.tick(context.Background())
	pump.tick(context.Background())

	// Two ticks → two QueryRows calls; second must use cursor=200.
	if len(fake.queries) != 2 {
		t.Fatalf("expected 2 queries, got %d: %v", len(fake.queries), fake.queries)
	}
	if !strings.Contains(fake.queries[0], "time > 0") {
		t.Errorf("first query cursor wrong: %s", fake.queries[0])
	}
	if !strings.Contains(fake.queries[1], "time > 200") {
		t.Errorf("second query cursor wrong: %s", fake.queries[1])
	}
}

func TestPump_InventoryTableSkipsCursorSubstitution(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"listening_ports": {
				{"port": "22", "protocol": "6", "address": "0.0.0.0", "pid": "1"},
			},
		},
	}
	send, got := recordingSender()
	tables := []TableSpec{{
		Name:    "listening_ports",
		SQL:     "SELECT * FROM listening_ports",
		ClassID: pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY,
		Mapper:  mappers.ListeningPorts,
	}}
	pump := NewPump(fake, tables, time.Hour, send)
	pump.tick(context.Background())

	if !strings.HasSuffix(fake.queries[0], "FROM listening_ports") {
		t.Errorf("inventory query should have no cursor: %s", fake.queries[0])
	}
	if len(*got) != 1 {
		t.Fatalf("expected 1 envelope, got %d", len(*got))
	}
}

func TestPump_ClientUnavailableLogsAndContinues(t *testing.T) {
	fake := &fakeClient{err: ErrClientUnavailable}
	send, got := recordingSender()
	pump := NewPump(fake, DefaultTables(), time.Hour, send)
	pump.tick(context.Background()) // must not panic, must produce no envelopes
	if len(*got) != 0 {
		t.Errorf("unavailable client should produce no envelopes, got %d", len(*got))
	}
}

func TestPump_HandleAgentMessage_LiveQueryStreamsRowsAndComplete(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"listening_ports": {
				{"port": "22", "address": "0.0.0.0"},
				{"port": "443", "address": "0.0.0.0"},
			},
		},
	}
	send, got := recordingSender()
	pump := NewPump(fake, nil, time.Hour, send)
	msg := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_LiveQueryRequest{
			LiveQueryRequest: &pb.LiveQueryRequest{
				QueryId:     "q1",
				Sql:         "SELECT * FROM listening_ports",
				MaxRows:     10,
				TimeoutSecs: 5,
			},
		},
	}
	if err := pump.HandleAgentMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleAgentMessage: %v", err)
	}
	// 2 rows + 1 complete = 3 envelopes
	if len(*got) != 3 {
		t.Fatalf("expected 3 envelopes (2 rows + 1 complete), got %d", len(*got))
	}
	complete := (*got)[2].GetLiveQueryComplete()
	if complete == nil {
		t.Fatal("expected last envelope to be LiveQueryComplete")
		return
	}
	if complete.RowCount != 2 {
		t.Errorf("complete.row_count=%d, want 2", complete.RowCount)
	}
	if complete.Error != "" {
		t.Errorf("complete.error=%q, want empty", complete.Error)
	}
	row0 := (*got)[0].GetLiveQueryRow()
	if row0 == nil || row0.QueryId != "q1" {
		t.Errorf("row 0 wrong: %+v", row0)
	}
}

func TestPump_HandleAgentMessage_LiveQueryRowCapTruncates(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"listening_ports": {
				{"port": "1"},
				{"port": "2"},
				{"port": "3"},
			},
		},
	}
	send, got := recordingSender()
	pump := NewPump(fake, nil, time.Hour, send)
	msg := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_LiveQueryRequest{
			LiveQueryRequest: &pb.LiveQueryRequest{
				QueryId: "q1",
				Sql:     "SELECT * FROM listening_ports",
				MaxRows: 2,
			},
		},
	}
	if err := pump.HandleAgentMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleAgentMessage: %v", err)
	}
	// 2 rows (capped) + 1 complete = 3 envelopes
	if len(*got) != 3 {
		t.Fatalf("expected 3 envelopes (2 rows + complete), got %d", len(*got))
	}
	complete := (*got)[2].GetLiveQueryComplete()
	if complete == nil {
		t.Fatal("expected LiveQueryComplete")
		return
	}
	if complete.RowCount != 2 {
		t.Errorf("row_count=%d, want 2 (cap)", complete.RowCount)
	}
}

func TestPump_HandleAgentMessage_LiveQueryClientError(t *testing.T) {
	fake := &fakeClient{err: errors.New("osqueryi died")}
	send, got := recordingSender()
	pump := NewPump(fake, nil, time.Hour, send)
	msg := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_LiveQueryRequest{
			LiveQueryRequest: &pb.LiveQueryRequest{QueryId: "q1", Sql: "SELECT 1"},
		},
	}
	_ = pump.HandleAgentMessage(context.Background(), msg)
	if len(*got) != 1 {
		t.Fatalf("expected 1 envelope (terminal complete), got %d", len(*got))
	}
	complete := (*got)[0].GetLiveQueryComplete()
	if complete == nil {
		t.Fatal("expected LiveQueryComplete")
		return
	}
	if !strings.Contains(complete.Error, "osqueryi died") {
		t.Errorf("expected client error in Error, got %q", complete.Error)
	}
}

func TestPump_HandleAgentMessage_SnapshotRefuses(t *testing.T) {
	send, got := recordingSender()
	pump := NewPump(&fakeClient{}, nil, time.Hour, send)
	msg := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_SnapshotRequest{
			SnapshotRequest: &pb.SnapshotRequest{SnapshotId: "s1"},
		},
	}
	if err := pump.HandleAgentMessage(context.Background(), msg); err != nil {
		t.Fatalf("HandleAgentMessage: %v", err)
	}
	complete := (*got)[0].GetSnapshotComplete()
	if complete == nil {
		t.Fatal("expected SnapshotComplete")
		return
	}
	if !strings.Contains(complete.Error, "not declared") {
		t.Errorf("expected refusal text, got %q", complete.Error)
	}
}

func TestPump_MapperErrorDoesNotAbortTick(t *testing.T) {
	fake := &fakeClient{
		rowsByTbl: map[string][]Row{
			"process_events": {
				{"syscall": "execve"}, // missing pid → mapper errors
				{"pid": "200", "syscall": "execve", "time": "10"},
			},
		},
	}
	send, got := recordingSender()
	tables := []TableSpec{{
		Name:    "process_events",
		SQL:     "SELECT * FROM process_events WHERE time > {since}",
		ClassID: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
		Mapper:  mappers.ProcessEvents,
	}}
	pump := NewPump(fake, tables, time.Hour, send)
	pump.tick(context.Background())
	if len(*got) != 1 {
		t.Errorf("expected 1 envelope (one row mapped, one row failed), got %d", len(*got))
	}
}

func TestPump_RunRespectsContextCancellation(t *testing.T) {
	fake := &fakeClient{}
	send, _ := recordingSender()
	pump := NewPump(fake, DefaultTables(), 10*time.Millisecond, send)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pump.Run(ctx) }()
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit on cancel")
	}
}

func TestSendHello_DeclaresExpectedCapabilities(t *testing.T) {
	send, got := recordingSender()
	if err := SendHello(send, "v0.1.0"); err != nil {
		t.Fatalf("SendHello: %v", err)
	}
	hello := (*got)[0].GetHello()
	if hello == nil {
		t.Fatal("first envelope is not Hello")
		return
	}
	if hello.Name != "osquery" {
		t.Errorf("name=%q", hello.Name)
	}
	if hello.Version != "v0.1.0" {
		t.Errorf("version=%q", hello.Version)
	}
	caps := map[pb.Capability]bool{}
	for _, c := range hello.Capabilities {
		caps[c] = true
	}
	if !caps[pb.Capability_CAPABILITY_OCSF_EMIT] {
		t.Error("missing CAPABILITY_OCSF_EMIT")
	}
	if !caps[pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND] {
		t.Error("missing CAPABILITY_LIVE_QUERY_RESPOND")
	}
	if caps[pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE] {
		t.Error("must not declare SNAPSHOT_PROVIDE in Phase 6 #109")
	}
}
