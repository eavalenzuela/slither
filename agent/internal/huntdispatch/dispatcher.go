// Package huntdispatch is the agent-side glue between server-pushed
// HuntQuery and the extension supervisor's LIVE_QUERY_RESPOND-capable
// extension. Phase 6 #110.
//
// The dispatcher owns no I/O of its own — it borrows the supervisor's
// DispatchLiveQuery + the gRPC sink's HuntResults channel and runs
// one goroutine per hunt. Per-host row cap and timeout are enforced
// here rather than the bridge so a buggy extension can't exceed
// either.
package huntdispatch

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/t3rmit3/slither/agent/internal/extensions"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// chunkRows is how many rows the dispatcher batches into one
// HuntResult before pushing onto the sink's channel. Tuned for ~64 KiB
// per chunk at typical osquery row sizes; larger chunks save gRPC
// per-message overhead at the cost of latency-on-first-row.
const chunkRows = 256

// LiveQueryProvider is the supervisor's DispatchLiveQuery surface.
// extensions.Manager satisfies it.
type LiveQueryProvider interface {
	DispatchLiveQuery(ctx context.Context, req *pb.LiveQueryRequest) (<-chan *pb.ExtensionToAgent, error)
}

// Dispatcher coordinates one hunt per goroutine. Submit is non-
// blocking (the Recv loop on the gRPC sink calls it).
type Dispatcher struct {
	provider LiveQueryProvider
	results  chan<- *pb.HuntResult
}

// New builds a dispatcher. provider + results are required.
func New(provider LiveQueryProvider, results chan<- *pb.HuntResult) *Dispatcher {
	if provider == nil {
		panic("huntdispatch.New: nil provider")
	}
	if results == nil {
		panic("huntdispatch.New: nil results channel")
	}
	return &Dispatcher{provider: provider, results: results}
}

// Submit kicks off a hunt on a fresh goroutine. Errors at this layer
// are surfaced as a HuntResult with complete.error set so the server
// always receives a terminal message and the hunt row's
// completed_host_count advances.
func (d *Dispatcher) Submit(ctx context.Context, q *pb.HuntQuery) {
	if q == nil || q.GetControlId() == "" {
		return
	}
	go d.run(ctx, q)
}

func (d *Dispatcher) run(ctx context.Context, q *pb.HuntQuery) {
	timeout := time.Duration(q.GetTimeoutSecs()) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxRows := q.GetMaxRows()
	if maxRows == 0 {
		maxRows = 10000
	}

	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req := &pb.LiveQueryRequest{
		QueryId:     q.GetControlId(),
		Sql:         q.GetQuery(),
		MaxRows:     maxRows,
		TimeoutSecs: q.GetTimeoutSecs(),
	}
	resultCh, err := d.provider.DispatchLiveQuery(hctx, req)
	if err != nil {
		d.shipFinalError(q.GetControlId(), 0, dispatchError(err))
		return
	}

	var (
		buf    []*pb.HuntResultRow
		count  uint64
		capped bool
	)
	for {
		select {
		case <-hctx.Done():
			d.flushChunk(q.GetControlId(), buf)
			d.shipFinalError(q.GetControlId(), count, "timeout")
			return
		case env, ok := <-resultCh:
			if !ok {
				// Channel closed without Complete — extension cycle
				// torn down. Treat as a failure.
				d.flushChunk(q.GetControlId(), buf)
				d.shipFinalError(q.GetControlId(), count, "extension teardown")
				return
			}
			switch payload := env.Payload.(type) {
			case *pb.ExtensionToAgent_LiveQueryRow:
				if count >= uint64(maxRows) {
					capped = true
					continue
				}
				buf = append(buf, &pb.HuntResultRow{
					Columns: payload.LiveQueryRow.GetColumns(),
					Values:  payload.LiveQueryRow.GetValues(),
				})
				count++
				if len(buf) >= chunkRows {
					d.flushChunk(q.GetControlId(), buf)
					buf = nil
				}
			case *pb.ExtensionToAgent_LiveQueryComplete:
				d.flushChunk(q.GetControlId(), buf)
				errMsg := payload.LiveQueryComplete.GetError()
				if capped && errMsg == "" {
					errMsg = capTruncationMessage(maxRows)
				}
				d.shipFinalError(q.GetControlId(), count, errMsg)
				return
			}
		}
	}
}

func (d *Dispatcher) flushChunk(queryID string, rows []*pb.HuntResultRow) {
	if len(rows) == 0 {
		return
	}
	d.send(&pb.HuntResult{ControlId: queryID, Rows: rows})
}

// shipFinalError emits one terminal HuntResult carrying complete +
// optional error. Always followed by no further messages for the
// queryID.
func (d *Dispatcher) shipFinalError(queryID string, rowCount uint64, errMsg string) {
	d.send(&pb.HuntResult{
		ControlId: queryID,
		Complete: &pb.HuntResultComplete{
			RowCount: rowCount,
			Error:    errMsg,
		},
	})
}

func (d *Dispatcher) send(hr *pb.HuntResult) {
	select {
	case d.results <- hr:
	default:
		// Channel saturated. Drop on the floor + log; the Recv loop
		// on the sink will eventually drain. The server will surface
		// "no result" as a stuck hunt; operators see it on the list.
		slog.Warn("hunt: result drop (sink saturated)",
			"hunt_id", hr.GetControlId(),
			"rows", len(hr.GetRows()))
	}
}

// dispatchError maps the supervisor's well-known errors into operator-
// visible strings. The exit gate (#121) reads these in the console's
// hunt detail page.
func dispatchError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, extensions.ErrNoLiveQueryProvider) {
		return "no extension declares live_query_respond"
	}
	if errors.Is(err, extensions.ErrExtensionUnavailable) {
		return "extension not currently spawned"
	}
	if errors.Is(err, extensions.ErrCapabilityViolation) {
		return "extension does not declare live_query_respond"
	}
	return err.Error()
}

func capTruncationMessage(rowCap uint32) string {
	return "row cap exceeded; truncated at " + strconv.FormatUint(uint64(rowCap), 10)
}
