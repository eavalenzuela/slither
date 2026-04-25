package ch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// WriterOptions configures the bus-subscriber writer. Zero-valued fields
// fall back to the defaults documented in ADR-0031.
type WriterOptions struct {
	// SubscriberName is how the writer registers on the bus. Defaults to
	// "ch_writer". Distinct names let multiple writers coexist (e.g. a
	// dev tail subscriber alongside the production batched writer).
	SubscriberName string

	// BusBuffer is the depth of the bus-side subscription channel. Drops
	// happen at this boundary when the writer can't keep up. Defaults to
	// BatchSize so a single full flush is the worst-case backlog.
	BusBuffer int

	// BatchSize is the row count that triggers a flush regardless of
	// elapsed time. Defaults to 10_000 (ADR-0031).
	BatchSize int

	// FlushInterval is the maximum time a row may sit in a buffer before
	// the writer flushes its class. Defaults to 2s.
	FlushInterval time.Duration
}

// Writer subscribes to ingest.Bus, accumulates per-class row buffers,
// and flushes batches to ClickHouse. One Writer instance owns one
// goroutine — Run blocks until ctx is cancelled or the bus closes.
type Writer struct {
	store *Store
	bus   *ingest.Bus
	telem *telemetry.Counters
	opts  WriterOptions

	sub     <-chan *pb.Envelope
	buffers map[pb.OcsfClassId]*classBuffer

	// lastFlushErr is set whenever a flush() call returns an error.
	// Tests check this to surface CH errors that would otherwise be
	// silently counted as IncDropSubscriber. Production callers may
	// wire a logger via SetFlushErrorHandler.
	lastFlushErr      error
	flushErrorHandler func(error)
}

// classBuffer holds the pending rows for one OCSF class table. The
// concrete row type is class-specific (procRow, fileRow, ...).
type classBuffer struct {
	tableName string
	rows      []chRow
}

// chRow is implemented by every per-class row type. bind appends the
// row's values onto the prepared batch in the column order declared by
// the migration.
type chRow interface {
	bind(batch driver.Batch) error
}

// NewWriter constructs a Writer. store + bus + telem are required.
func NewWriter(store *Store, bus *ingest.Bus, telem *telemetry.Counters, opts WriterOptions) *Writer {
	if store == nil {
		panic("ch.NewWriter: nil store")
	}
	if bus == nil {
		panic("ch.NewWriter: nil bus")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	if opts.SubscriberName == "" {
		opts.SubscriberName = "ch_writer"
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 10_000
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}
	if opts.BusBuffer <= 0 {
		opts.BusBuffer = opts.BatchSize
	}
	return &Writer{
		store: store,
		bus:   bus,
		telem: telem,
		opts:  opts,
		// Subscribe synchronously so callers that publish on the bus
		// immediately after NewWriter cannot race the writer goroutine's
		// startup. Bus.Publish is a no-op for unsubscribed names; without
		// the synchronous subscription early events would be silently lost.
		sub: bus.Subscribe(opts.SubscriberName, opts.BusBuffer),
		buffers: map[pb.OcsfClassId]*classBuffer{
			pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY:     {tableName: "ocsf_process_activity_1007"},
			pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY: {tableName: "ocsf_file_system_activity_1001"},
			pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY:     {tableName: "ocsf_network_activity_4001"},
			pb.OcsfClassId_OCSF_CLASS_ID_DETECTION_FINDING:    {tableName: "ocsf_detection_finding_2004"},
		},
	}
}

// Run drains the pre-registered bus subscription until ctx is cancelled.
// Always flushes pending buffers on the way out.
func (w *Writer) Run(ctx context.Context) error {
	defer w.bus.Unsubscribe(w.opts.SubscriberName)

	tick := time.NewTicker(w.opts.FlushInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			// Flush on shutdown uses a fresh context so the final batch
			// is not cancelled by the same ctx that just woke us up. A
			// 5s budget bounds the worst-case shutdown delay.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			w.flushAll(shutdownCtx) //nolint:contextcheck // intentional fresh ctx for shutdown drain
			cancel()
			return ctx.Err()
		case env, ok := <-w.sub:
			if !ok {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				w.flushAll(shutdownCtx) //nolint:contextcheck // intentional fresh ctx for shutdown drain
				cancel()
				return nil
			}
			w.ingest(ctx, env)
		case <-tick.C:
			w.flushAll(ctx)
		}
	}
}

// ingest decodes one envelope into a per-class row and appends it to the
// matching buffer. Decode failures are counted as subscriber drops — a
// malformed event from a trusted agent shouldn't kill the pipeline.
func (w *Writer) ingest(ctx context.Context, env *pb.Envelope) {
	if env == nil {
		return
	}
	buf, ok := w.buffers[env.GetClassId()]
	if !ok {
		// Unknown class — Phase 1 only emits the four classes above;
		// other class_uids will land with their own table in Phase 3+.
		w.telem.IncDropSubscriber()
		return
	}
	row, err := decode(env)
	if err != nil {
		w.telem.IncDropSubscriber()
		return
	}
	buf.rows = append(buf.rows, row)
	if len(buf.rows) >= w.opts.BatchSize {
		w.flush(ctx, env.GetClassId(), buf)
	}
}

// flushAll flushes every non-empty buffer.
func (w *Writer) flushAll(ctx context.Context) {
	for class, buf := range w.buffers {
		if len(buf.rows) == 0 {
			continue
		}
		w.flush(ctx, class, buf)
	}
}

// flush sends buf.rows to ClickHouse and resets the buffer regardless
// of outcome. Insert errors increment the subscriber-drop counter so
// operators see the loss; the slice is intentionally cleared even on
// failure to prevent unbounded buffer growth when CH is unhealthy.
func (w *Writer) flush(ctx context.Context, class pb.OcsfClassId, buf *classBuffer) {
	if len(buf.rows) == 0 {
		return
	}
	rows := buf.rows
	buf.rows = nil

	// The writer already batches, so we don't need server-side
	// async_insert pooling — a synchronous INSERT INTO ... VALUES
	// commits a 10k-row batch in a single round trip. ADR-0031 noted
	// async_insert as a future option for multi-replica deployments;
	// dropping it here keeps read-your-writes semantics deterministic.
	stmt := fmt.Sprintf("INSERT INTO %s", buf.tableName)
	batch, err := w.store.conn.PrepareBatch(ctx, stmt)
	if err != nil {
		w.recordFlushErr(fmt.Errorf("prepare %s: %w", buf.tableName, err))
		for range rows {
			w.telem.IncDropSubscriber()
		}
		_ = class
		return
	}
	for _, r := range rows {
		if err := r.bind(batch); err != nil {
			w.recordFlushErr(fmt.Errorf("bind %s: %w", buf.tableName, err))
			w.telem.IncDropSubscriber()
		}
	}
	if err := batch.Send(); err != nil {
		w.recordFlushErr(fmt.Errorf("send %s: %w", buf.tableName, err))
		for range rows {
			w.telem.IncDropSubscriber()
		}
		return
	}
	w.telem.IncBatchesFlushed()
}

// LastFlushErr returns the most recent flush error or nil. Helper for
// tests; production callers should prefer SetFlushErrorHandler.
func (w *Writer) LastFlushErr() error { return w.lastFlushErr }

// SetFlushErrorHandler installs a callback fired on every flush error.
// Default is no-op. Safe to call only before Run.
func (w *Writer) SetFlushErrorHandler(fn func(error)) { w.flushErrorHandler = fn }

func (w *Writer) recordFlushErr(err error) {
	w.lastFlushErr = err
	if w.flushErrorHandler != nil {
		w.flushErrorHandler(err)
	}
}

// --- decoders ---

// decode picks the right per-class decoder for env.class_id.
func decode(env *pb.Envelope) (chRow, error) {
	switch env.GetClassId() {
	case pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY:
		return decodeProcess(env)
	case pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY:
		return decodeFile(env)
	case pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY:
		return decodeNet(env)
	case pb.OcsfClassId_OCSF_CLASS_ID_DETECTION_FINDING:
		return decodeFinding(env)
	}
	return nil, fmt.Errorf("ch: unsupported class_id %v", env.GetClassId())
}

func decodeProcess(env *pb.Envelope) (chRow, error) {
	var ev ocsf.ProcessActivity
	if err := json.Unmarshal(env.GetPayload(), &ev); err != nil {
		return nil, err
	}
	row := procRow{shared: sharedFromEnvelope(env)}
	row.activityID = uint8(ev.ActivityID)
	row.pid = ev.Process.PID
	if ev.Process.Parent != nil {
		row.parentPID = ev.Process.Parent.PID
	}
	row.processName = ev.Process.Name
	if ev.Process.File != nil {
		row.execPath = ev.Process.File.Path
	}
	row.cmdline = ev.Process.Cmdline
	if ev.Process.User != nil {
		row.userName = ev.Process.User.Name
	}
	row.exitCode = ev.ExitCode
	return row, nil
}

func decodeFile(env *pb.Envelope) (chRow, error) {
	var ev ocsf.FileSystemActivity
	if err := json.Unmarshal(env.GetPayload(), &ev); err != nil {
		return nil, err
	}
	row := fileRow{shared: sharedFromEnvelope(env)}
	row.activityID = uint8(ev.ActivityID)
	row.filePath = ev.File.Path
	row.fileName = ev.File.Name
	row.fileHash = ev.File.HashesSHA256
	row.actorPID = ev.Actor.Process.PID
	row.actorName = ev.Actor.Process.Name
	return row, nil
}

func decodeNet(env *pb.Envelope) (chRow, error) {
	var ev ocsf.NetworkActivity
	if err := json.Unmarshal(env.GetPayload(), &ev); err != nil {
		return nil, err
	}
	row := netRow{shared: sharedFromEnvelope(env)}
	row.activityID = uint8(ev.ActivityID)
	row.protocol = ev.Connection.Protocol
	row.srcIP = ev.SrcEndpoint.IP
	row.srcPort = ev.SrcEndpoint.Port
	row.dstIP = ev.DstEndpoint.IP
	row.dstPort = ev.DstEndpoint.Port
	row.actorPID = ev.Actor.Process.PID
	row.actorName = ev.Actor.Process.Name
	return row, nil
}

func decodeFinding(env *pb.Envelope) (chRow, error) {
	var ev ocsf.DetectionFinding
	if err := json.Unmarshal(env.GetPayload(), &ev); err != nil {
		return nil, err
	}
	row := findingRow{shared: sharedFromEnvelope(env)}
	row.activityID = uint8(ev.ActivityID)
	row.ruleUID = ev.RuleInfo.UID
	row.ruleName = ev.RuleInfo.Name
	row.findingUID = ev.Finding.UID
	row.findingStatus = ev.Finding.Status
	row.triggeringEventIDs = make([]uuid.UUID, 0, len(ev.TriggeringEventIDs))
	for _, s := range ev.TriggeringEventIDs {
		if u, err := uuid.Parse(s); err == nil {
			row.triggeringEventIDs = append(row.triggeringEventIDs, u)
		}
	}
	for _, m := range ev.MitreATTACK {
		if m.Technique.UID != "" {
			row.mitreTechniques = append(row.mitreTechniques, m.Technique.UID)
		}
	}
	return row, nil
}

// --- shared row scaffolding ---

type sharedRow struct {
	eventID     uuid.UUID
	hostID      uuid.UUID
	observedAt  time.Time
	collectedAt time.Time
	classUID    uint32
	severityID  uint8
	raw         string
}

func sharedFromEnvelope(env *pb.Envelope) sharedRow {
	row := sharedRow{
		classUID: uint32(env.GetClassId()),
		raw:      string(env.GetPayload()),
	}
	if u, err := uuid.Parse(env.GetEventId()); err == nil {
		row.eventID = u
	}
	if u, err := uuid.Parse(env.GetHostId()); err == nil {
		row.hostID = u
	}
	if t := env.GetObservedAt(); t != nil {
		row.observedAt = t.AsTime()
	}
	if t := env.GetCollectedAt(); t != nil {
		row.collectedAt = t.AsTime()
	}
	row.severityID = severityFromPayload(env.GetPayload())
	return row
}

// severityFromPayload pulls severity_id out of the OCSF JSON without
// fully decoding the event. Falls back to 0 (informational) if missing.
func severityFromPayload(payload []byte) uint8 {
	var probe struct {
		Severity uint8 `json:"severity_id"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return 0
	}
	return probe.Severity
}

// --- per-class rows ---

type procRow struct {
	shared      sharedRow
	activityID  uint8
	pid         uint32
	parentPID   uint32
	processName string
	execPath    string
	cmdline     string
	userName    string
	exitCode    *int32
}

func (r procRow) bind(batch driver.Batch) error {
	return batch.Append(
		r.shared.eventID, r.shared.hostID, r.shared.observedAt, r.shared.collectedAt,
		r.shared.classUID, r.shared.severityID,
		r.activityID, r.pid, r.parentPID, r.processName, r.execPath, r.cmdline, r.userName, r.exitCode,
		r.shared.raw,
	)
}

type fileRow struct {
	shared     sharedRow
	activityID uint8
	filePath   string
	fileName   string
	fileHash   string
	actorPID   uint32
	actorName  string
}

func (r fileRow) bind(batch driver.Batch) error {
	return batch.Append(
		r.shared.eventID, r.shared.hostID, r.shared.observedAt, r.shared.collectedAt,
		r.shared.classUID, r.shared.severityID,
		r.activityID, r.filePath, r.fileName, r.fileHash, r.actorPID, r.actorName,
		r.shared.raw,
	)
}

type netRow struct {
	shared     sharedRow
	activityID uint8
	protocol   string
	srcIP      string
	srcPort    uint16
	dstIP      string
	dstPort    uint16
	actorPID   uint32
	actorName  string
}

func (r netRow) bind(batch driver.Batch) error {
	return batch.Append(
		r.shared.eventID, r.shared.hostID, r.shared.observedAt, r.shared.collectedAt,
		r.shared.classUID, r.shared.severityID,
		r.activityID, r.protocol, r.srcIP, r.srcPort, r.dstIP, r.dstPort, r.actorPID, r.actorName,
		r.shared.raw,
	)
}

type findingRow struct {
	shared             sharedRow
	activityID         uint8
	ruleUID            string
	ruleName           string
	findingUID         string
	findingStatus      string
	triggeringEventIDs []uuid.UUID
	mitreTechniques    []string
}

func (r findingRow) bind(batch driver.Batch) error {
	if r.triggeringEventIDs == nil {
		r.triggeringEventIDs = []uuid.UUID{}
	}
	if r.mitreTechniques == nil {
		r.mitreTechniques = []string{}
	}
	return batch.Append(
		r.shared.eventID, r.shared.hostID, r.shared.observedAt, r.shared.collectedAt,
		r.shared.classUID, r.shared.severityID,
		r.activityID, r.ruleUID, r.ruleName, r.findingUID, r.findingStatus,
		r.triggeringEventIDs, r.mitreTechniques,
		r.shared.raw,
	)
}

// keep errors imported even if a future refactor strips a path.
var _ = errors.Is
