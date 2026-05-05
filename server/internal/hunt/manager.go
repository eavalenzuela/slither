// Package hunt owns the Phase 6 #110 live-query hunt orchestrator.
//
// The Manager sits between the operator (console POST /hunt) and the
// agent's gRPC Session stream. Lifecycle of one hunt:
//
//  1. Dispatch() inserts a hunts row in status=dispatching, fans the
//     resulting *pb.HuntQuery onto every per-host subscription channel
//     matching the host_filter, then bumps target_host_count + flips
//     status to running. A timer goroutine fires SetHuntTimedOut after
//     timeout_secs unless the hunt has already completed naturally.
//  2. Per-host SessionService send goroutines pull HuntQuery off their
//     subscription channel and stream.Send it to the agent.
//  3. Agent runs the query through its extension supervisor and emits
//     ClientMessage.HuntResult chunks (rows + final complete).
//  4. SessionService.handle dispatches HuntResult to OnResult, which
//     buffers rows into ClickHouse hunt_results and bumps
//     completed_host_count when complete arrives. The pg helper flips
//     status to completed when completed_host_count reaches
//     target_host_count.
//
// The host filter is intentionally simple — substring match on hosts.id
// or hosts.hostname. Anything fancier (label expressions, host-group
// membership) is a Phase 7 concern.
package hunt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/store/ch"
	"github.com/t3rmit3/slither/server/internal/store/pg"
)

// queueDepth bounds the per-host pending hunt channel. Hunts are
// operator-driven and bursts are small; 16 covers the dispatch storm
// shape an analyst running a multi-stage threat-hunting workflow can
// realistically produce.
const queueDepth = 16

// HostLister is the read-side dependency Dispatch uses to compute the
// fan-out target list. *pg.Store satisfies it via
// ListHostsForHuntFilter.
type HostLister interface {
	ListHostsForHuntFilter(ctx context.Context, filter string) ([]pg.HuntHostRef, error)
}

// Hub fans hunt queries to per-host subscription channels and ingests
// per-host results back into ClickHouse + Postgres.
type Hub struct {
	pg    *pg.Store
	ch    *ch.Store
	hosts HostLister

	mu     sync.Mutex
	queues map[string]chan *pb.HuntQuery // host_id → pending hunt channel
}

// NewHub constructs a Hub. pg + ch + hosts are required.
func NewHub(pgStore *pg.Store, chStore *ch.Store, hosts HostLister) *Hub {
	if pgStore == nil {
		panic("hunt.NewHub: nil pg store")
	}
	if chStore == nil {
		panic("hunt.NewHub: nil ch store")
	}
	if hosts == nil {
		panic("hunt.NewHub: nil host lister")
	}
	return &Hub{
		pg:     pgStore,
		ch:     chStore,
		hosts:  hosts,
		queues: make(map[string]chan *pb.HuntQuery),
	}
}

// DispatchInput is the input to Hub.Dispatch — the console form maps
// directly onto these fields.
type DispatchInput struct {
	OperatorID     string // user uuid; required
	Backend        string // "osquery" today
	Query          string // backend-specific text; required
	HostFilter     string // empty == every connected host
	TimeoutSecs    int    // 0 → 60s default
	MaxRowsPerHost int    // 0 → 10000 default
}

// ErrNoMatchingHosts is returned when the host filter resolves to zero
// hosts. The hunt row is still inserted in status=completed with
// target=0 so the audit trail captures the empty fan-out.
var ErrNoMatchingHosts = errors.New("hunt.Hub.Dispatch: host filter matched zero hosts")

// Dispatch persists the hunt row, fans HuntQuery to subscribed hosts,
// flips status to running, and schedules the timeout transition.
func (h *Hub) Dispatch(ctx context.Context, in DispatchInput) (pg.HuntRow, error) {
	if in.OperatorID == "" {
		return pg.HuntRow{}, errors.New("hunt.Hub.Dispatch: operator_id required")
	}
	if in.Query == "" {
		return pg.HuntRow{}, errors.New("hunt.Hub.Dispatch: query required")
	}
	if in.Backend == "" {
		in.Backend = "osquery"
	}
	if in.TimeoutSecs <= 0 {
		in.TimeoutSecs = 60
	}
	if in.MaxRowsPerHost <= 0 {
		in.MaxRowsPerHost = 10000
	}

	row, err := h.pg.InsertHunt(ctx, pg.HuntInsert{
		DispatchedBy:   in.OperatorID,
		Backend:        in.Backend,
		Query:          in.Query,
		HostFilter:     in.HostFilter,
		TimeoutSecs:    in.TimeoutSecs,
		MaxRowsPerHost: in.MaxRowsPerHost,
	})
	if err != nil {
		return pg.HuntRow{}, fmt.Errorf("hunt.Hub.Dispatch: insert: %w", err)
	}

	hosts, err := h.hosts.ListHostsForHuntFilter(ctx, in.HostFilter)
	if err != nil {
		return row, fmt.Errorf("hunt.Hub.Dispatch: list hosts: %w", err)
	}

	q := &pb.HuntQuery{
		ControlId:   row.ID,
		OperatorId:  in.OperatorID,
		Backend:     pb.HuntBackend_HUNT_BACKEND_OSQUERY,
		Query:       in.Query,
		Deadline:    timestamppb.New(time.Now().Add(time.Duration(in.TimeoutSecs) * time.Second)),
		MaxRows:     uint32(in.MaxRowsPerHost),
		TimeoutSecs: uint32(in.TimeoutSecs),
	}

	delivered := 0
	for _, host := range hosts {
		if h.enqueue(host.ID, q) {
			delivered++
		} else {
			slog.Warn("hunt: dispatch dropped (host not subscribed or queue full)",
				"hunt_id", row.ID, "host_id", host.ID)
		}
	}

	if err := h.pg.SetHuntDispatched(ctx, row.ID, delivered); err != nil {
		return row, fmt.Errorf("hunt.Hub.Dispatch: SetHuntDispatched: %w", err)
	}
	row.TargetHostCount = delivered
	row.Status = pg.HuntStatusRunning

	if delivered == 0 {
		// Empty fan-out: flip immediately to completed. The pg helper
		// already does this when completed_host_count reaches
		// target_host_count, but only via IncHuntCompleted; nudge the
		// row directly here.
		_ = h.pg.SetHuntTimedOut(ctx, row.ID) // re-uses timed_out semantically — no host actually responded
		return row, ErrNoMatchingHosts
	}

	// Schedule the timeout. Deliberately fire-and-forget on a
	// background context so per-request cancellation doesn't cancel
	// the timer — the timer must outlive the request that started it
	// (gosec G118 acknowledged + intentional).
	go h.runTimeout(row.ID, time.Duration(in.TimeoutSecs)*time.Second) //nolint:gosec,contextcheck // intentional background timer; outlives request ctx

	return row, nil
}

// runTimeout flips the hunt to timed_out after d, no-op if it has
// already completed. Runs on a goroutine spawned by Dispatch.
func (h *Hub) runTimeout(huntID string, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	<-timer.C
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.pg.SetHuntTimedOut(ctx, huntID); err != nil {
		slog.Warn("hunt: timeout transition failed", "hunt_id", huntID, "err", err)
	}
}

// Subscribe is called by the SessionService send goroutine on Session
// open. Returns the per-host channel + an unsubscribe function. The
// previous channel for a duplicate Subscribe is closed so the previous
// session's send loop exits cleanly.
func (h *Hub) Subscribe(hostID string) (queries <-chan *pb.HuntQuery, unsubscribe func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old, ok := h.queues[hostID]; ok {
		close(old)
	}
	q := make(chan *pb.HuntQuery, queueDepth)
	h.queues[hostID] = q
	return q, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if cur, ok := h.queues[hostID]; ok && cur == q {
			close(cur)
			delete(h.queues, hostID)
		}
	}
}

// OnResult ingests one HuntResult chunk emitted by an agent. Inserts
// rows into ClickHouse hunt_results; on the final (complete) chunk,
// bumps completed_host_count.
func (h *Hub) OnResult(ctx context.Context, hostID string, result *pb.HuntResult) error {
	if result == nil {
		return errors.New("hunt.Hub.OnResult: nil result")
	}
	queryID := result.GetControlId()
	if queryID == "" {
		return errors.New("hunt.Hub.OnResult: empty control_id")
	}
	if _, err := uuid.Parse(queryID); err != nil {
		return fmt.Errorf("hunt.Hub.OnResult: control_id not a uuid: %w", err)
	}

	if rows := result.GetRows(); len(rows) > 0 {
		cols := make([][]string, 0, len(rows))
		vals := make([][]string, 0, len(rows))
		for _, r := range rows {
			cols = append(cols, r.GetColumns())
			vals = append(vals, r.GetValues())
		}
		if err := h.ch.InsertHuntResults(ctx, queryID, hostID, cols, vals); err != nil {
			return fmt.Errorf("hunt.Hub.OnResult: insert rows: %w", err)
		}
	}

	if complete := result.GetComplete(); complete != nil {
		if err := h.pg.IncHuntCompleted(ctx, queryID); err != nil {
			return fmt.Errorf("hunt.Hub.OnResult: inc completed: %w", err)
		}
		slog.Info("hunt: host completed",
			"hunt_id", queryID, "host_id", hostID,
			"row_count", complete.GetRowCount(),
			"err", complete.GetError())
	}
	return nil
}

// enqueue tries to push q onto the per-host channel. Returns false
// when the host has no active subscriber or the channel is full. Both
// cases result in target_host_count not being incremented for that
// host — the hunt simply skips the unreachable agent.
func (h *Hub) enqueue(hostID string, q *pb.HuntQuery) bool {
	h.mu.Lock()
	queue, ok := h.queues[hostID]
	h.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case queue <- q:
		return true
	default:
		return false
	}
}

// MatchHostFilter mirrors the SQL filter in pg.ListHostsForHuntFilter
// for tests + in-process use. Empty filter matches every host;
// non-empty matches if id OR hostname contains the filter substring
// case-insensitively.
func MatchHostFilter(filter string, host pg.HuntHostRef) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	return strings.Contains(strings.ToLower(host.ID), f) ||
		strings.Contains(strings.ToLower(host.Hostname), f)
}
