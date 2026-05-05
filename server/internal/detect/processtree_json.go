// Phase 6 #114 — JSON projection of a process tree for the live
// explorer on the alert-detail page.
//
// Distinct from process_tree.go's D2-render path: this builder emits
// nodes + edges as Go structs the handler marshals into the JSON
// payload the client SVG renderer consumes. Reuses the same
// ProcessTreeLookup interface so #65's stub still satisfies tests.
//
// Tree shape: nodes carry pid, parent_pid, exec_path, process_name,
// cmdline, observed_at; edges are (parent_event_id, child_event_id).
// The client lazy-loads expansions by re-calling the endpoint with
// the clicked PID as the new root_pid.

package detect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
)

// ProcessTreeNode is one process node in the JSON projection. The
// client renders these as SVG rectangles.
type ProcessTreeNode struct {
	EventID    string    `json:"event_id"`
	PID        uint32    `json:"pid"`
	ParentPID  uint32    `json:"parent_pid,omitempty"`
	ExecPath   string    `json:"exec_path,omitempty"`
	ProcName   string    `json:"process_name,omitempty"`
	Cmdline    string    `json:"cmdline,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	// HasMoreChildren signals the per-level fan-out cap clipped this
	// node's child list. The client renders an "expand more" sentinel
	// the operator can click to issue a fresh request with a higher
	// fanout. v1 only stamps this flag — there is no interactive raise
	// in Phase 6.
	HasMoreChildren bool `json:"has_more_children,omitempty"`
	// IsRoot marks the node the request was rooted at. Lets the
	// client highlight it visually without re-deriving from the
	// position in the array.
	IsRoot bool `json:"is_root,omitempty"`
}

// ProcessTreeEdge is one parent→child link.
type ProcessTreeEdge struct {
	From string `json:"from"` // parent event_id
	To   string `json:"to"`   // child event_id
}

// ProcessTreeJSON is the full payload the JSON endpoint returns.
type ProcessTreeJSON struct {
	HostID       string            `json:"host_id"`
	RootPID      uint32            `json:"root_pid"`
	Depth        int               `json:"depth"`
	Nodes        []ProcessTreeNode `json:"nodes"`
	Edges        []ProcessTreeEdge `json:"edges"`
	TruncatedAt  int               `json:"truncated_at,omitempty"`
	NotFound     bool              `json:"not_found,omitempty"`
	BuildLatency string            `json:"build_latency_ms,omitempty"`
}

// ProcessTreeJSONBuilder is the JSON sibling of ProcessTreeBuilder.
// Distinct type so handler tests can stub it independently of the SVG
// builder.
type ProcessTreeJSONBuilder struct {
	Lookup ProcessTreeLookup

	MaxDepth    int
	MaxNodes    int
	FanoutLimit int
	Lookback    time.Duration
}

// Build returns the JSON projection rooted at (hostID, rootPID) walked
// to depth. observedBefore anchors the tree to a specific point in
// time; zero falls back to time.Now().
//
// Empty tree + NotFound=true when the root PID is not in CH for the
// host within the lookback window.
func (b *ProcessTreeJSONBuilder) Build(
	ctx context.Context,
	hostID string,
	rootPID uint32,
	depth int,
	observedBefore time.Time,
) (ProcessTreeJSON, error) {
	if b == nil || b.Lookup == nil {
		return ProcessTreeJSON{}, errors.New("detect.ProcessTreeJSONBuilder: nil lookup")
	}
	if hostID == "" {
		return ProcessTreeJSON{}, errors.New("detect.ProcessTreeJSONBuilder: empty host id")
	}
	if rootPID == 0 {
		return ProcessTreeJSON{}, errors.New("detect.ProcessTreeJSONBuilder: zero root pid")
	}

	maxDepth := depth
	if maxDepth <= 0 {
		maxDepth = b.MaxDepth
	}
	if maxDepth <= 0 {
		maxDepth = 4
	}
	maxNodes := b.MaxNodes
	if maxNodes <= 0 {
		maxNodes = 256
	}
	fanout := b.FanoutLimit
	if fanout <= 0 {
		fanout = 64
	}
	lookback := b.Lookback
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	if observedBefore.IsZero() {
		observedBefore = time.Now()
	}
	observedAfter := observedBefore.Add(-lookback)

	t0 := time.Now()
	root, err := b.Lookup.LookupProcessByPID(ctx, hostID, rootPID, observedBefore, lookback)
	if err != nil {
		if errors.Is(err, ch.ErrEventNotFound) {
			return ProcessTreeJSON{
				HostID: hostID, RootPID: rootPID, Depth: maxDepth, NotFound: true,
			}, nil
		}
		return ProcessTreeJSON{}, fmt.Errorf("detect.ProcessTreeJSONBuilder.Build: root: %w", err)
	}

	out := ProcessTreeJSON{HostID: hostID, RootPID: rootPID, Depth: maxDepth}
	rootNode := nodeFromCH(root)
	rootNode.IsRoot = true
	out.Nodes = append(out.Nodes, rootNode)

	type frontier struct {
		eventID string
		pid     uint32
		depth   int
	}
	queue := []frontier{{eventID: root.EventID, pid: root.PID, depth: 0}}
	truncated := 0

	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]

		if head.depth >= maxDepth {
			continue
		}
		if len(out.Nodes) >= maxNodes {
			truncated++
			continue
		}

		children, err := b.Lookup.ListProcessChildren(ctx,
			hostID, head.pid, observedAfter, observedBefore, fanout)
		if err != nil {
			return ProcessTreeJSON{}, fmt.Errorf("detect.ProcessTreeJSONBuilder.Build: children of pid %d: %w", head.pid, err)
		}
		// Stable order so two requests for the same window return
		// byte-stable JSON the cache can key on.
		sort.SliceStable(children, func(i, j int) bool {
			if children[i].ObservedAt.Equal(children[j].ObservedAt) {
				return children[i].PID < children[j].PID
			}
			return children[i].ObservedAt.Before(children[j].ObservedAt)
		})

		// fanout-limit detection: if CH returned exactly the limit, mark
		// the node as having more children. This is a coarse signal —
		// hitting limit exactly with no further children is a false
		// positive — but the client only uses it to render a sentinel,
		// so the worst-case UX is one stale "expand more" tag.
		if len(children) >= fanout {
			markHasMoreChildren(out.Nodes, head.eventID)
		}

		for _, c := range children {
			if len(out.Nodes) >= maxNodes {
				truncated += len(children) - (len(out.Nodes) - 1)
				break
			}
			out.Nodes = append(out.Nodes, nodeFromCH(c))
			out.Edges = append(out.Edges, ProcessTreeEdge{From: head.eventID, To: c.EventID})
			if head.depth+1 < maxDepth {
				queue = append(queue, frontier{eventID: c.EventID, pid: c.PID, depth: head.depth + 1})
			}
		}
	}

	if truncated > 0 {
		out.TruncatedAt = truncated
	}
	out.BuildLatency = fmt.Sprintf("%d", time.Since(t0).Milliseconds())
	return out, nil
}

func nodeFromCH(n ch.EventNode) ProcessTreeNode {
	return ProcessTreeNode{
		EventID:    n.EventID,
		PID:        n.PID,
		ParentPID:  n.ParentPID,
		ExecPath:   n.ExecPath,
		ProcName:   n.ProcName,
		Cmdline:    n.Cmdline,
		ObservedAt: n.ObservedAt,
	}
}

// markHasMoreChildren stamps the cap-hit signal on a node by event_id.
// O(N) walk on the small node slice — N is bounded by MaxNodes (256
// default) so a linear scan is fine.
func markHasMoreChildren(nodes []ProcessTreeNode, eventID string) {
	for i := range nodes {
		if nodes[i].EventID == eventID {
			nodes[i].HasMoreChildren = true
			return
		}
	}
}
