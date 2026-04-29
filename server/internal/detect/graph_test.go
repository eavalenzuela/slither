package detect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
)

type stubLookup struct {
	events  map[string]ch.EventNode
	procs   map[uint32]ch.EventNode
	queries int
}

func (s *stubLookup) GetEventNode(_ context.Context, eventID string) (ch.EventNode, error) {
	s.queries++
	if n, ok := s.events[eventID]; ok {
		return n, nil
	}
	return ch.EventNode{}, ch.ErrEventNotFound
}

func (s *stubLookup) LookupProcessByPID(_ context.Context, _ string, pid uint32, _ time.Time, _ time.Duration) (ch.EventNode, error) {
	s.queries++
	if n, ok := s.procs[pid]; ok {
		return n, nil
	}
	return ch.EventNode{}, ch.ErrEventNotFound
}

func TestFlowGraphBuilder_BuildEmptyEvents(t *testing.T) {
	t.Parallel()
	b := &FlowGraphBuilder{Lookup: &stubLookup{}}
	src, err := b.Build(context.Background(), "alert-1", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if src != "" {
		t.Fatalf("expected empty source for empty events, got %q", src)
	}
}

func TestFlowGraphBuilder_RendersProcessFileNetAlert(t *testing.T) {
	t.Parallel()
	now := time.Now()
	host := "00000000-0000-0000-0000-000000000001"

	procEvent := ch.EventNode{
		EventID: "11111111-1111-1111-1111-111111111111", HostID: host, ClassUID: 1007,
		ObservedAt: now, PID: 100, ParentPID: 1, ExecPath: "/bin/bash", ProcName: "bash",
	}
	fileEvent := ch.EventNode{
		EventID: "22222222-2222-2222-2222-222222222222", HostID: host, ClassUID: 1001,
		ObservedAt: now.Add(time.Second), FilePath: "/etc/passwd", ActorPID: 100,
	}
	netEvent := ch.EventNode{
		EventID: "33333333-3333-3333-3333-333333333333", HostID: host, ClassUID: 4001,
		ObservedAt: now.Add(2 * time.Second), Protocol: "tcp", SrcIP: "10.0.0.1", SrcPort: 4242,
		DstIP: "203.0.113.5", DstPort: 4444, ActorPID: 100,
	}
	alertEvent := ch.EventNode{
		EventID: "44444444-4444-4444-4444-444444444444", HostID: host, ClassUID: 2004,
		ObservedAt: now.Add(3 * time.Second), RuleUID: "rev-shell-001", RuleName: "Reverse shell",
	}

	parentProc := ch.EventNode{
		EventID: "55555555-5555-5555-5555-555555555555", HostID: host, ClassUID: 1007,
		ObservedAt: now.Add(-time.Second), PID: 1, ExecPath: "/sbin/init", ProcName: "init",
	}

	stub := &stubLookup{
		events: map[string]ch.EventNode{
			procEvent.EventID:  procEvent,
			fileEvent.EventID:  fileEvent,
			netEvent.EventID:   netEvent,
			alertEvent.EventID: alertEvent,
		},
		procs: map[uint32]ch.EventNode{
			100: procEvent,
			1:   parentProc,
		},
	}

	b := &FlowGraphBuilder{Lookup: stub, MaxNodes: 32}
	src, err := b.Build(context.Background(), "alert-1",
		[]string{procEvent.EventID, fileEvent.EventID, netEvent.EventID, alertEvent.EventID})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, want := range []string{
		"# Slither alert flow graph for alert-1",
		"shape: rectangle",
		"shape: page",
		"shape: cylinder",
		"shape: diamond",
		"/bin/bash",
		"/etc/passwd",
		"10.0.0.1:4242 -> 203.0.113.5:4444",
		"Reverse shell",
		"/sbin/init",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("rendered source missing %q\n--- source ---\n%s", want, src)
		}
	}
}

func TestFlowGraphBuilder_MissingEventsFallToSentinel(t *testing.T) {
	t.Parallel()
	stub := &stubLookup{events: map[string]ch.EventNode{}}
	b := &FlowGraphBuilder{Lookup: stub}
	src, err := b.Build(context.Background(), "alert-x", []string{"deadbeef-0000-0000-0000-000000000001"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(src, "event N/A") {
		t.Fatalf("expected sentinel placeholder, got %q", src)
	}
}

func TestFlowGraphBuilder_TruncatesAtMaxNodes(t *testing.T) {
	t.Parallel()
	stub := &stubLookup{events: map[string]ch.EventNode{}}
	for i := 0; i < 10; i++ {
		id := strings.Repeat("1", 8) + "-" + strings.Repeat("a", 4) + "-" + strings.Repeat("b", 4) + "-" + strings.Repeat("c", 4) + "-" + strings.Repeat("d", 12)
		// Make each id unique by tweaking the leading char
		uid := string(rune('a'+i)) + id[1:]
		stub.events[uid] = ch.EventNode{
			EventID: uid, ClassUID: 1007, PID: uint32(100 + i),
		}
	}
	keys := make([]string, 0, len(stub.events))
	for k := range stub.events {
		keys = append(keys, k)
	}
	b := &FlowGraphBuilder{Lookup: stub, MaxNodes: 4}
	src, err := b.Build(context.Background(), "alert-y", keys)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(src, "truncated") {
		t.Fatalf("expected truncation marker, got %q", src)
	}
}

func TestFlowGraphBuilder_NilLookupFails(t *testing.T) {
	t.Parallel()
	b := &FlowGraphBuilder{}
	if _, err := b.Build(context.Background(), "a", []string{"x"}); err == nil {
		t.Fatal("expected error for nil lookup")
	}
}
