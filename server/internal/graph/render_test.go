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

// TestRender_FlowGraphShape mirrors the source the alert flow-graph
// builder (#64) emits — labelled nodes with shape directives and a
// few edges. Catches D2 grammar drift that a simple `a -> b` smoke
// test would miss.
func TestRender_FlowGraphShape(t *testing.T) {
	t.Parallel()

	const src = `n_55: {label: "proc pid=1\n/sbin/init"; shape: rectangle}
n_11: {label: "proc pid=100\n/bin/bash"; shape: rectangle}
n_22: {label: "file\n/etc/passwd"; shape: page}
n_33: {label: "net tcp\n10.0.0.1:4242 -> 203.0.113.5:4444"; shape: cylinder}
n_44: {label: "alert\nReverse shell"; shape: diamond}
n_55 -> n_11
n_11 -> n_22
n_11 -> n_33
n_11 -> n_44
`
	svg, err := graph.Render(context.Background(), src)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(string(svg), "<svg") {
		t.Fatalf("output missing <svg> tag")
	}
}
