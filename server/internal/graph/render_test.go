package graph_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/t3rmit3/slither/server/internal/graph"
)

func TestRender_FiveNodeChain(t *testing.T) {
	t.Parallel()

	const src = `
a -> b
b -> c
c -> d
d -> e
`
	svg, err := graph.Render(context.Background(), src)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if len(svg) == 0 {
		t.Fatal("Render returned zero-length SVG")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(svg), []byte("<")) {
		t.Fatalf("output does not look like SVG: %.80q", svg)
	}
	for _, want := range []string{"<svg", "</svg>"} {
		if !strings.Contains(string(svg), want) {
			t.Errorf("SVG missing %q marker", want)
		}
	}
	for _, node := range []string{"a", "b", "c", "d", "e"} {
		if !strings.Contains(string(svg), ">"+node+"<") {
			t.Errorf("SVG missing label for node %q", node)
		}
	}
}

func TestRender_EmptySource(t *testing.T) {
	t.Parallel()

	if _, err := graph.Render(context.Background(), ""); err == nil {
		t.Fatal("Render(\"\") expected error, got nil")
	}
}

func TestRender_BadSource(t *testing.T) {
	t.Parallel()

	if _, err := graph.Render(context.Background(), "((("); err == nil {
		t.Fatal("Render(garbage) expected compile error, got nil")
	}
}
