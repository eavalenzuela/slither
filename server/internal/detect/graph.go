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

// EventLookup is the narrow CH surface the flow-graph builder needs.
// Defined as an interface so tests can stub it without spinning up
// ClickHouse. *ch.Store satisfies it.
type EventLookup interface {
	GetEventNode(ctx context.Context, eventID string) (ch.EventNode, error)
	LookupProcessByPID(
		ctx context.Context,
		hostID string,
		pid uint32,
		observedBefore time.Time,
		lookback time.Duration,
	) (ch.EventNode, error)
}

// FlowGraphBuilder turns an alert's event_ids into a D2 source string.
//
// Strategy (v1, scoped per Phase 3 #64):
//
//   - Seed: every uuid in alert.event_ids; class auto-detected via
//     EventLookup.GetEventNode. Missing uuids are skipped so a
//     CH-retention drop doesn't fail the whole render.
//   - Edge expansion: for each process node, look up the parent
//     process by parent_pid; for each file/net node, look up the
//     actor process by actor_pid. The lookup chases at most one hop
//     so the graph stays bounded; a deeper process tree is the job
//     of the dedicated /hosts/{id}/process-tree page (#65).
//   - Node cap: MaxNodes hard ceiling (default 32). Once hit, further
//     expansion stops; existing nodes still render. The cap shows up
//     as a "+N more" sentinel node when expansion was truncated.
type FlowGraphBuilder struct {
	Lookup EventLookup

	// MaxNodes caps total nodes in the rendered graph (including
	// expansion). Zero falls back to 32.
	MaxNodes int

	// ActorLookback bounds how far back from an event's observed_at a
	// PID lookup will scan when chasing actor / parent processes.
	// Zero falls back to one hour — long enough to cover daemons that
	// have been running for a while without scanning the entire
	// retention window.
	ActorLookback time.Duration
}

// Build walks the event chain and returns D2 source. Empty event_ids
// returns "" with a nil error so the caller can decide whether to show
// a placeholder or hide the graph block entirely.
func (b *FlowGraphBuilder) Build(ctx context.Context, alertID string, eventIDs []string) (string, error) {
	if b == nil || b.Lookup == nil {
		return "", errors.New("detect.FlowGraphBuilder: nil lookup")
	}
	if alertID == "" {
		return "", errors.New("detect.FlowGraphBuilder: empty alert id")
	}
	if len(eventIDs) == 0 {
		return "", nil
	}

	maxNodes := b.MaxNodes
	if maxNodes <= 0 {
		maxNodes = 32
	}
	lookback := b.ActorLookback
	if lookback <= 0 {
		lookback = time.Hour
	}

	g := newDigraph()

	// Seed nodes. Sort the input event_ids so the graph (and its
	// resulting hash key) is deterministic regardless of the order
	// the alert row stored them.
	seed := append([]string(nil), eventIDs...)
	sort.Strings(seed)

	type pending struct {
		node ch.EventNode
	}
	var processQueue []pending

	for _, eid := range seed {
		if g.size() >= maxNodes {
			g.markTruncated(len(seed) - len(g.nodes()))
			break
		}
		node, err := b.Lookup.GetEventNode(ctx, eid)
		if err != nil {
			if errors.Is(err, ch.ErrEventNotFound) {
				g.add(missingNode(eid))
				continue
			}
			return "", fmt.Errorf("detect.FlowGraphBuilder.Build: lookup %s: %w", eid, err)
		}
		id := g.add(node)
		// Detection findings get a distinct rank so the alert sink is
		// visually obvious; everything else stays in the default rank.
		_ = id
		processQueue = append(processQueue, pending{node: node})
	}

	// Expand causality. Process events get parent-process edges;
	// file/net events get actor-process edges. Stop when MaxNodes
	// hits.
	for _, p := range processQueue {
		if g.size() >= maxNodes {
			g.markTruncated(0)
			break
		}
		actor, ok, err := b.actorFor(ctx, p.node, lookback)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		actorID := g.add(actor)
		g.connect(actorID, nodeID(p.node))
	}

	return g.render(alertID), nil
}

// actorFor returns the process node that should be the parent of the
// passed node, if one exists in the lookback window.
func (b *FlowGraphBuilder) actorFor(ctx context.Context, n ch.EventNode, lookback time.Duration) (ch.EventNode, bool, error) {
	var pid uint32
	switch n.ClassUID {
	case 1007:
		pid = n.ParentPID
	case 1001, 4001:
		pid = n.ActorPID
	default:
		return ch.EventNode{}, false, nil
	}
	if pid == 0 {
		return ch.EventNode{}, false, nil
	}

	actor, err := b.Lookup.LookupProcessByPID(ctx, n.HostID, pid, n.ObservedAt, lookback)
	if err != nil {
		if errors.Is(err, ch.ErrEventNotFound) {
			return ch.EventNode{}, false, nil
		}
		return ch.EventNode{}, false, fmt.Errorf("detect.FlowGraphBuilder.actorFor: %w", err)
	}
	// Don't add a self-loop when the parent lookup races against the
	// same row (the node IS its own parent_pid match in the rare case
	// where the kernel reused the PID at the same instant).
	if actor.EventID == n.EventID {
		return ch.EventNode{}, false, nil
	}
	return actor, true, nil
}

// digraph buffers nodes + directed edges in insertion order so the D2
// output is deterministic.
type digraph struct {
	nodeIDs   []string                // insertion-ordered node ids
	nodeAttrs map[string]ch.EventNode // id -> source row (zero for missing/sentinel)
	missing   map[string]struct{}     // ids inserted as "event N/A"
	edges     [][2]string             // directed: from -> to
	truncated int                     // count when expansion was capped
}

func newDigraph() *digraph {
	return &digraph{
		nodeAttrs: make(map[string]ch.EventNode),
		missing:   make(map[string]struct{}),
	}
}

func (g *digraph) size() int { return len(g.nodeIDs) }

func (g *digraph) nodes() []string { return g.nodeIDs }

func (g *digraph) add(n ch.EventNode) string {
	id := nodeID(n)
	if _, ok := g.nodeAttrs[id]; ok {
		return id
	}
	if _, ok := g.missing[id]; ok {
		return id
	}
	g.nodeIDs = append(g.nodeIDs, id)
	g.nodeAttrs[id] = n
	return id
}

func (g *digraph) markTruncated(extra int) {
	if extra > 0 {
		g.truncated += extra
	} else {
		g.truncated++
	}
}

func (g *digraph) connect(from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	for _, e := range g.edges {
		if e[0] == from && e[1] == to {
			return
		}
	}
	g.edges = append(g.edges, [2]string{from, to})
}

func missingNode(eventID string) ch.EventNode {
	return ch.EventNode{
		EventID:  eventID,
		ClassUID: 0,
	}
}

func nodeID(n ch.EventNode) string {
	if n.EventID != "" {
		return "n_" + sanitizeID(n.EventID)
	}
	return "n_unknown"
}

// render returns a D2 source string. Determinism: nodes render in the
// order they were added; edges in the order they were inserted.
func (g *digraph) render(alertID string) string {
	var b strings.Builder
	b.WriteString("# Slither alert flow graph for ")
	b.WriteString(alertID)
	b.WriteString("\n")

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

func writeNodeShape(b *strings.Builder, id string, n ch.EventNode) {
	label, shape := nodeLabelShape(n)
	fmt.Fprintf(b, "%s: {label: %q; shape: %s}\n", id, label, shape)
}

func nodeLabelShape(n ch.EventNode) (label, shape string) {
	switch n.ClassUID {
	case 1007:
		label = fmt.Sprintf("proc pid=%d\\n%s", n.PID, truncateLabel(n.ExecPath, 64))
		if n.ProcName != "" && n.ExecPath == "" {
			label = fmt.Sprintf("proc pid=%d\\n%s", n.PID, n.ProcName)
		}
		shape = "rectangle"
	case 1001:
		label = fmt.Sprintf("file\\n%s", truncateLabel(n.FilePath, 64))
		shape = "page"
	case 4001:
		label = fmt.Sprintf("net %s\\n%s:%d -> %s:%d",
			n.Protocol, n.SrcIP, n.SrcPort, n.DstIP, n.DstPort)
		shape = "cylinder"
	case 2004:
		label = fmt.Sprintf("alert\\n%s", n.RuleUID)
		if n.RuleName != "" {
			label = fmt.Sprintf("alert\\n%s\\n(%s)", n.RuleName, n.RuleUID)
		}
		shape = "diamond"
	default:
		label = fmt.Sprintf("event N/A\\n%s", truncateLabel(n.EventID, 32))
		shape = "circle"
	}
	return label, shape
}

func truncateLabel(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// sanitizeID strips characters that would be unsafe in a D2 identifier.
// Event ids are UUIDs (hex + dashes) so we just replace dashes with
// underscores; everything else is left as-is to keep the id stable.
func sanitizeID(eventID string) string {
	return strings.ReplaceAll(eventID, "-", "_")
}
