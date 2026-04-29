package detect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
)

type stubProcessTree struct {
	root     ch.EventNode
	rootErr  error
	children map[uint32][]ch.EventNode
}

func (s *stubProcessTree) LookupProcessByPID(_ context.Context, _ string, pid uint32, _ time.Time, _ time.Duration) (ch.EventNode, error) {
	if s.rootErr != nil {
		return ch.EventNode{}, s.rootErr
	}
	if pid == s.root.PID {
		return s.root, nil
	}
	return ch.EventNode{}, ch.ErrEventNotFound
}

func (s *stubProcessTree) ListProcessChildren(_ context.Context, _ string, parentPID uint32, _, _ time.Time, _ int) ([]ch.EventNode, error) {
	return s.children[parentPID], nil
}

func TestProcessTreeBuilder_RootMissingReturnsEmpty(t *testing.T) {
	t.Parallel()
	b := &ProcessTreeBuilder{Lookup: &stubProcessTree{rootErr: ch.ErrEventNotFound}}
	src, err := b.Build(context.Background(), "host-1", 100, 4, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if src != "" {
		t.Fatalf("expected empty source for missing root, got %q", src)
	}
}

func TestProcessTreeBuilder_RendersDepth4Tree(t *testing.T) {
	t.Parallel()

	root := ch.EventNode{
		EventID: "00000000-0000-0000-0000-000000000001", ClassUID: 1007,
		PID: 100, ProcName: "init", ExecPath: "/sbin/init",
	}
	c1 := ch.EventNode{EventID: "00000000-0000-0000-0000-000000000002", ClassUID: 1007, PID: 200, ProcName: "sshd", ExecPath: "/usr/sbin/sshd"}
	c2 := ch.EventNode{EventID: "00000000-0000-0000-0000-000000000003", ClassUID: 1007, PID: 201, ProcName: "cron", ExecPath: "/usr/sbin/cron"}
	g1 := ch.EventNode{EventID: "00000000-0000-0000-0000-000000000004", ClassUID: 1007, PID: 300, ProcName: "bash", ExecPath: "/bin/bash"}
	gg1 := ch.EventNode{EventID: "00000000-0000-0000-0000-000000000005", ClassUID: 1007, PID: 400, ProcName: "curl", ExecPath: "/usr/bin/curl"}
	ggg1 := ch.EventNode{EventID: "00000000-0000-0000-0000-000000000006", ClassUID: 1007, PID: 500, ProcName: "wget", ExecPath: "/usr/bin/wget"}

	stub := &stubProcessTree{
		root: root,
		children: map[uint32][]ch.EventNode{
			100: {c1, c2},
			200: {g1},
			300: {gg1},
			400: {ggg1},
		},
	}
	b := &ProcessTreeBuilder{Lookup: stub}
	// depth=3: root (d=0) → sshd (d=1) → bash (d=2) → curl (d=3).
	// wget at d=4 must NOT appear.
	src, err := b.Build(context.Background(), "host-1", 100, 3, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, want := range []string{
		"# Slither process tree host=host-1 root_pid=100 depth=3",
		"/sbin/init",
		"/usr/sbin/sshd",
		"/usr/sbin/cron",
		"/bin/bash",
		"/usr/bin/curl",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q in source\n--- source ---\n%s", want, src)
		}
	}
	if strings.Contains(src, "/usr/bin/wget") {
		t.Errorf("depth limit failed — wget at depth 4 leaked through:\n%s", src)
	}
}

func TestProcessTreeBuilder_TruncatesAtMaxNodes(t *testing.T) {
	t.Parallel()

	root := ch.EventNode{EventID: "r", ClassUID: 1007, PID: 1, ExecPath: "/sbin/init"}
	children := make([]ch.EventNode, 0, 20)
	for i := 0; i < 20; i++ {
		children = append(children, ch.EventNode{
			EventID:  string(rune('a' + i)),
			ClassUID: 1007,
			PID:      uint32(100 + i),
			ExecPath: "/bin/" + string(rune('a'+i)),
		})
	}
	stub := &stubProcessTree{
		root:     root,
		children: map[uint32][]ch.EventNode{1: children},
	}
	b := &ProcessTreeBuilder{Lookup: stub, MaxNodes: 5}
	src, err := b.Build(context.Background(), "host-1", 1, 2, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(src, "truncated") {
		t.Fatalf("expected truncation marker:\n%s", src)
	}
}

func TestProcessTreeBuilder_NilLookup(t *testing.T) {
	t.Parallel()
	b := &ProcessTreeBuilder{}
	if _, err := b.Build(context.Background(), "h", 1, 1, time.Now()); err == nil {
		t.Fatal("expected error for nil lookup")
	}
}

func TestProcessTreeCacheKey(t *testing.T) {
	t.Parallel()
	a := ProcessTreeCacheKey("00000000-0000-0000-0000-000000000001", 100, 4)
	b := ProcessTreeCacheKey("00000000-0000-0000-0000-000000000001", 100, 4)
	if a != b {
		t.Fatalf("cache key not deterministic")
	}
	c := ProcessTreeCacheKey("00000000-0000-0000-0000-000000000001", 100, 5)
	if a == c {
		t.Fatal("cache key did not vary with depth")
	}
	if !strings.HasPrefix(a, "pt_") {
		t.Fatalf("cache key missing pt_ namespace: %s", a)
	}
}
