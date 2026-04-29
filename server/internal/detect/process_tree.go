package detect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/t3rmit3/slither/server/internal/store/ch"
)

// ProcessTreeLookup is the narrow CH surface the process-tree builder
// needs. *ch.Store satisfies it; tests stub it without spinning up
// ClickHouse.
type ProcessTreeLookup interface {
	LookupProcessByPID(
		ctx context.Context,
		hostID string,
		pid uint32,
		observedBefore time.Time,
		lookback time.Duration,
	) (ch.EventNode, error)
	ListProcessChildren(
		ctx context.Context,
		hostID string,
		parentPID uint32,
		observedAfter, observedBefore time.Time,
		limit int,
	) ([]ch.EventNode, error)
}

// ProcessTreeBuilder renders a depth-bounded process tree rooted at
// (host_id, root_pid) into D2 source. Reuses graph.Cache via opaque
// keys at the handler layer.
type ProcessTreeBuilder struct {
	Lookup ProcessTreeLookup

	// MaxDepth is the maximum hop count from root to leaf. Zero falls
	// back to 4 (the default the docs cite).
	MaxDepth int

	// MaxNodes hard-caps total tree size so a fork-bomb-shaped subtree
	// can't run the SVG renderer out of patience. Zero falls back to
	// 256.
	MaxNodes int

	// FanoutLimit caps direct children per parent at each level. Zero
	// falls back to 64.
	FanoutLimit int

	// Lookback bounds how far back from observedBefore the root + child
	// queries scan. Zero falls back to 24h — long enough for
	// long-running daemons without scanning the entire CH retention.
	Lookback time.Duration
}

// Build returns D2 source for the process tree rooted at (hostID,
// rootPID) walked to depth.  observedBefore lets the caller anchor the
// tree to a specific point in time (e.g., when investigating a past
// incident); zero falls back to time.Now().
//
// Returns "" + nil error when the root PID is not in CH for the host
// — the caller renders a "not found" placeholder rather than a 500.
func (b *ProcessTreeBuilder) Build(
	ctx context.Context,
	hostID string,
	rootPID uint32,
	depth int,
	observedBefore time.Time,
) (string, error) {
	if b == nil || b.Lookup == nil {
		return "", errors.New("detect.ProcessTreeBuilder: nil lookup")
	}
	if hostID == "" {
		return "", errors.New("detect.ProcessTreeBuilder: empty host id")
	}
	if rootPID == 0 {
		return "", errors.New("detect.ProcessTreeBuilder: zero root pid")
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

	root, err := b.Lookup.LookupProcessByPID(ctx, hostID, rootPID, observedBefore, lookback)
	if err != nil {
		if errors.Is(err, ch.ErrEventNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("detect.ProcessTreeBuilder.Build: root lookup: %w", err)
	}

	g := newDigraph()
	rootID := g.add(root)

	type frontier struct {
		nodeID string
		node   ch.EventNode
		depth  int
	}
	queue := []frontier{{nodeID: rootID, node: root, depth: 0}}
	truncated := 0

	for len(queue) > 0 {
		head := queue[0]
		queue = queue[1:]

		if head.depth >= maxDepth {
			continue
		}
		if g.size() >= maxNodes {
			truncated++
			continue
		}

		children, err := b.Lookup.ListProcessChildren(ctx,
			hostID, head.node.PID,
			observedAfter, observedBefore, fanout)
		if err != nil {
			return "", fmt.Errorf("detect.ProcessTreeBuilder.Build: children of pid %d: %w", head.node.PID, err)
		}
		// Sort children for deterministic output regardless of CH's
		// internal row order.
		sort.SliceStable(children, func(i, j int) bool {
			if children[i].ObservedAt.Equal(children[j].ObservedAt) {
				return children[i].PID < children[j].PID
			}
			return children[i].ObservedAt.Before(children[j].ObservedAt)
		})

		for _, c := range children {
			if g.size() >= maxNodes {
				truncated += len(children) - g.size() + maxNodes
				if truncated < 1 {
					truncated = 1
				}
				break
			}
			childID := g.add(c)
			g.connect(head.nodeID, childID)
			if head.depth+1 < maxDepth {
				queue = append(queue, frontier{nodeID: childID, node: c, depth: head.depth + 1})
			}
		}
	}
	if truncated > 0 {
		g.markTruncated(truncated)
	}

	return g.renderProcessTree(hostID, rootPID, maxDepth), nil
}

// ProcessTreeCacheKey is the opaque key the handler stores under in
// graph.Cache. Distinct namespace from alert flow-graph keys.
func ProcessTreeCacheKey(hostID string, rootPID uint32, depth int) string {
	return fmt.Sprintf("pt_%s_%d_%d", strings.ReplaceAll(hostID, "-", ""), rootPID, depth)
}

func (g *digraph) renderProcessTree(hostID string, rootPID uint32, maxDepth int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Slither process tree host=%s root_pid=%d depth=%d\n", hostID, rootPID, maxDepth)
	for _, id := range g.nodeIDs {
		n := g.nodeAttrs[id]
		writeNodeShape(&b, id, n)
	}
	if g.truncated > 0 {
		fmt.Fprintf(&b, "truncated: {label: %q; shape: cloud}\n",
			fmt.Sprintf("+%d more (truncated)", g.truncated))
	}
	for _, e := range g.edges {
		fmt.Fprintf(&b, "%s -> %s\n", e[0], e[1])
	}
	return b.String()
}
