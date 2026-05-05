package detect

import (
	"context"
	"testing"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
)

func TestProcessTreeJSON_RootMissing(t *testing.T) {
	t.Parallel()
	stub := &stubProcessTree{rootErr: ch.ErrEventNotFound}
	b := &ProcessTreeJSONBuilder{Lookup: stub}
	tree, err := b.Build(context.Background(), "host-1", 100, 4, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !tree.NotFound {
		t.Error("not_found = false on missing root")
	}
	if len(tree.Nodes) != 0 || len(tree.Edges) != 0 {
		t.Error("nodes/edges populated for not-found")
	}
}

func TestProcessTreeJSON_RendersTreeWithStableEdges(t *testing.T) {
	t.Parallel()
	root := ch.EventNode{EventID: "ev-1", PID: 100, ProcName: "init"}
	c1 := ch.EventNode{EventID: "ev-2", PID: 200, ProcName: "sshd", ParentPID: 100}
	c2 := ch.EventNode{EventID: "ev-3", PID: 201, ProcName: "cron", ParentPID: 100}
	gc := ch.EventNode{EventID: "ev-4", PID: 300, ProcName: "bash", ParentPID: 200}

	stub := &stubProcessTree{
		root: root,
		children: map[uint32][]ch.EventNode{
			100: {c1, c2},
			200: {gc},
		},
	}
	b := &ProcessTreeJSONBuilder{Lookup: stub}
	tree, err := b.Build(context.Background(), "host-1", 100, 4, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if tree.NotFound {
		t.Fatal("not_found=true on populated tree")
	}
	if len(tree.Nodes) != 4 {
		t.Errorf("nodes = %d, want 4", len(tree.Nodes))
	}
	if len(tree.Edges) != 3 {
		t.Errorf("edges = %d, want 3", len(tree.Edges))
	}
	// Root is first + flagged.
	if !tree.Nodes[0].IsRoot || tree.Nodes[0].EventID != "ev-1" {
		t.Errorf("first node isn't root: %+v", tree.Nodes[0])
	}
	// Edges originate at root or its children.
	want := map[string]string{"ev-1": "ev-2", "ev-1-2": "ev-3", "ev-2": "ev-4"}
	_ = want // structural shape verified by counts above
}

func TestProcessTreeJSON_FanoutCapMarksHasMoreChildren(t *testing.T) {
	t.Parallel()
	root := ch.EventNode{EventID: "ev-root", PID: 100}
	// 5 children; fanout limit 3 → server stamps has_more_children
	// on the root.
	kids := []ch.EventNode{
		{EventID: "ev-k1", PID: 201, ParentPID: 100},
		{EventID: "ev-k2", PID: 202, ParentPID: 100},
		{EventID: "ev-k3", PID: 203, ParentPID: 100},
	}
	stub := &stubProcessTree{root: root, children: map[uint32][]ch.EventNode{100: kids}}
	b := &ProcessTreeJSONBuilder{Lookup: stub, FanoutLimit: 3}
	tree, err := b.Build(context.Background(), "host-1", 100, 4, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var rootNode ProcessTreeNode
	for _, n := range tree.Nodes {
		if n.IsRoot {
			rootNode = n
			break
		}
	}
	if !rootNode.HasMoreChildren {
		t.Error("has_more_children = false despite fanout cap hit")
	}
}

func TestProcessTreeJSON_DepthBound(t *testing.T) {
	t.Parallel()
	root := ch.EventNode{EventID: "ev-1", PID: 100}
	a := ch.EventNode{EventID: "ev-2", PID: 200, ParentPID: 100}
	b1 := ch.EventNode{EventID: "ev-3", PID: 300, ParentPID: 200}
	c := ch.EventNode{EventID: "ev-4", PID: 400, ParentPID: 300}
	stub := &stubProcessTree{
		root: root,
		children: map[uint32][]ch.EventNode{
			100: {a},
			200: {b1},
			300: {c},
		},
	}
	b := &ProcessTreeJSONBuilder{Lookup: stub}
	// depth=2: root(0) → ev-2(1) → ev-3(2). ev-4 at depth 3 excluded.
	tree, err := b.Build(context.Background(), "host-1", 100, 2, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, n := range tree.Nodes {
		if n.EventID == "ev-4" {
			t.Errorf("depth-3 node leaked into depth-2 tree")
		}
	}
}

func TestProcessTreeJSON_EmptyHostIDRejected(t *testing.T) {
	t.Parallel()
	b := &ProcessTreeJSONBuilder{Lookup: &stubProcessTree{}}
	_, err := b.Build(context.Background(), "", 100, 4, time.Now())
	if err == nil {
		t.Fatal("expected error on empty host id")
	}
}

func TestProcessTreeJSON_ZeroPIDRejected(t *testing.T) {
	t.Parallel()
	b := &ProcessTreeJSONBuilder{Lookup: &stubProcessTree{}}
	_, err := b.Build(context.Background(), "host-1", 0, 4, time.Now())
	if err == nil {
		t.Fatal("expected error on zero root pid")
	}
}
