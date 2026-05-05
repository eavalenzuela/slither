package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/t3rmit3/slither/extensions/osquery/internal/mappers"
	"github.com/t3rmit3/slither/pkg/extsdk"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// TableSpec describes one curated osquery table polled by the bridge.
type TableSpec struct {
	// Name is the operator-visible label (matches the SQL FROM clause).
	Name string
	// SQL is the query the bridge runs each tick. Authors include the
	// "{since}" placeholder for event tables — pump substitutes the
	// per-table cursor value before dispatching.
	SQL string
	// ClassID is the OCSF class the mapper produces.
	ClassID pb.OcsfClassId
	// Mapper converts each Row into one OCSF event.
	Mapper mappers.Mapper
}

// DefaultTables returns the curated set wired in #109.
func DefaultTables() []TableSpec {
	return []TableSpec{
		{
			Name:    "process_events",
			SQL:     "SELECT pid, path, cmdline, parent, syscall, uid, time FROM process_events WHERE time > {since}",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY,
			Mapper:  mappers.ProcessEvents,
		},
		{
			Name:    "socket_events",
			SQL:     "SELECT action, pid, path, uid, family, protocol, local_address, remote_address, local_port, remote_port, time FROM socket_events WHERE time > {since}",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY,
			Mapper:  mappers.SocketEvents,
		},
		{
			Name:    "file_events",
			SQL:     "SELECT target_path, category, action, uid, mode, size, sha256, time FROM file_events WHERE time > {since}",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY,
			Mapper:  mappers.FileEvents,
		},
		{
			Name:    "listening_ports",
			SQL:     "SELECT pid, port, protocol, family, address, path FROM listening_ports",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY,
			Mapper:  mappers.ListeningPorts,
		},
		{
			Name:    "kernel_modules",
			SQL:     "SELECT name, size, used_by, status, address FROM kernel_modules",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_KERNEL_ACTIVITY,
			Mapper:  mappers.KernelModules,
		},
		{
			Name:    "ssh_keys",
			SQL:     "SELECT uid, path, encrypted FROM ssh_keys",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY,
			Mapper:  mappers.SSHKeys,
		},
		{
			Name:    "authorized_keys",
			SQL:     "SELECT uid, algorithm, key, key_file, comment FROM authorized_keys",
			ClassID: pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY,
			Mapper:  mappers.AuthorizedKeys,
		},
	}
}

// Sender is the bridge's outbound write closure. Production wires it
// to a mutex-guarded extsdk.WriteExtensionToAgent over the FD-3
// socket; tests stub a recorder.
type Sender func(*pb.ExtensionToAgent) error

// Pump owns the polling loop. Per tick it walks every TableSpec,
// fetches rows from the Client, runs each through the mapper, and
// writes the resulting OCSF event up the wire as
// ExtensionToAgent_OcsfEvent.
type Pump struct {
	client   Client
	tables   []TableSpec
	interval time.Duration
	send     Sender

	cursorMu       sync.Mutex
	perTableCursor map[string]int64
}

// NewPump builds a polling loop. interval defaults to 10s when zero.
func NewPump(client Client, tables []TableSpec, interval time.Duration, send Sender) *Pump {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &Pump{
		client:         client,
		tables:         tables,
		interval:       interval,
		send:           send,
		perTableCursor: make(map[string]int64),
	}
}

// Run blocks until ctx is cancelled, ticking every interval. Runs one
// tick immediately so first-event latency doesn't gate startup.
func (p *Pump) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			p.tick(ctx)
		}
	}
}

func (p *Pump) tick(ctx context.Context) {
	for _, ts := range p.tables {
		if err := p.pollTable(ctx, ts); err != nil {
			if errors.Is(err, ErrClientUnavailable) {
				slog.Warn("osquery: client unavailable", "table", ts.Name)
				continue
			}
			slog.Warn("osquery: poll error", "table", ts.Name, "err", err)
		}
	}
}

func (p *Pump) pollTable(ctx context.Context, ts TableSpec) error {
	sql := p.substituteCursor(ts)
	rows, err := p.client.QueryRows(ctx, sql)
	if err != nil {
		return err
	}
	maxTime := int64(0)
	for _, row := range rows {
		ev, mapErr := ts.Mapper(mappers.Row(row))
		if mapErr != nil {
			slog.Warn("osquery: mapper error", "table", ts.Name, "err", mapErr)
			continue
		}
		if ev == nil {
			continue
		}
		payload, jerr := json.Marshal(ev)
		if jerr != nil {
			slog.Warn("osquery: marshal error", "table", ts.Name, "err", jerr)
			continue
		}
		envelope := &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_OcsfEvent{
				OcsfEvent: &pb.OCSFEvent{
					ClassId: ts.ClassID,
					Payload: payload,
				},
			},
		}
		if sendErr := p.send(envelope); sendErr != nil {
			return fmt.Errorf("send %s: %w", ts.Name, sendErr)
		}
		if ts.advancesCursor() {
			if t, perr := strconv.ParseInt(strings.TrimSpace(row["time"]), 10, 64); perr == nil && t > maxTime {
				maxTime = t
			}
		}
	}
	if maxTime > 0 {
		p.cursorMu.Lock()
		if maxTime > p.perTableCursor[ts.Name] {
			p.perTableCursor[ts.Name] = maxTime
		}
		p.cursorMu.Unlock()
	}
	return nil
}

func (p *Pump) substituteCursor(ts TableSpec) string {
	if !ts.advancesCursor() {
		return ts.SQL
	}
	p.cursorMu.Lock()
	cursor := p.perTableCursor[ts.Name]
	p.cursorMu.Unlock()
	return strings.Replace(ts.SQL, "{since}", strconv.FormatInt(cursor, 10), 1)
}

func (ts TableSpec) advancesCursor() bool {
	return strings.Contains(ts.SQL, "{since}")
}

// HandleAgentMessage processes one AgentToExtension envelope. Phase 6
// #109 stubs both LiveQueryRequest and SnapshotRequest with a
// terminal "not implemented" complete so the server's hunt /
// snapshot machinery doesn't stall waiting forever. Real handling
// lands in #110 (live-query) and a Phase 7 snapshot extension.
func (p *Pump) HandleAgentMessage(ctx context.Context, msg *pb.AgentToExtension) error {
	switch payload := msg.Payload.(type) {
	case *pb.AgentToExtension_LiveQueryRequest:
		req := payload.LiveQueryRequest
		complete := &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_LiveQueryComplete{
				LiveQueryComplete: &pb.LiveQueryComplete{
					QueryId:  req.QueryId,
					RowCount: 0,
					Error:    "live-query handler pending (#110)",
				},
			},
		}
		return p.send(complete)
	case *pb.AgentToExtension_SnapshotRequest:
		req := payload.SnapshotRequest
		complete := &pb.ExtensionToAgent{
			Payload: &pb.ExtensionToAgent_SnapshotComplete{
				SnapshotComplete: &pb.SnapshotComplete{
					SnapshotId: req.SnapshotId,
					Error:      "snapshot capability not declared by osquery bridge",
				},
			},
		}
		return p.send(complete)
	}
	return nil
}

// SendHello composes the osquery bridge's Hello and writes it as the
// first envelope on the freshly-accepted FD-3 socket. Capabilities
// default to OCSF_EMIT + LIVE_QUERY_RESPOND per IMPLEMENTATION.md
// §8.1 #109.
func SendHello(send Sender, version string) error {
	hello := &pb.ExtensionToAgent{
		Payload: &pb.ExtensionToAgent_Hello{
			Hello: &pb.Hello{
				Name:    "osquery",
				Version: version,
				Capabilities: []pb.Capability{
					pb.Capability_CAPABILITY_OCSF_EMIT,
					pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND,
				},
			},
		},
	}
	return send(hello)
}

// Receiver pulls one AgentToExtension envelope off the wire. Returned
// alongside Sender by LockedSender so the caller's inbound goroutine
// can dispatch agent → extension messages.
type Receiver func() (*pb.AgentToExtension, error)

// LockedSender returns a Sender that serialises writes through
// pkg/extsdk's framing helper, plus a paired Receiver that unwraps
// incoming AgentToExtension envelopes. Both share the caller-supplied
// io.ReadWriter (in production: an *os.File around FD 3) under one
// mutex so concurrent emits + ack writes don't interleave a partial
// frame.
func LockedSender(rw io.ReadWriter) (Sender, Receiver) {
	var writeMu sync.Mutex
	send := func(env *pb.ExtensionToAgent) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return extsdk.WriteExtensionToAgent(rw, env)
	}
	read := func() (*pb.AgentToExtension, error) {
		// Reads need no mutex — there's only one Recv goroutine.
		return extsdk.ReadAgentToExtension(rw)
	}
	return send, read
}
