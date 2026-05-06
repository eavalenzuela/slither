package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/t3rmit3/slither/agent/internal/config"
	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/extsdk"
	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// helloTimeout bounds the post-spawn handshake. An extension that
// doesn't send a Hello within this window is killed and the supervisor
// restarts with backoff.
const helloTimeout = 10 * time.Second

// minBackoff + maxBackoff bound the supervisor's restart cadence.
// Mirrors the gRPC sink's reconnect schedule (#35) — same shape, same
// ±25% jitter.
const (
	minBackoff = 1 * time.Second
	maxBackoff = 60 * time.Second
)

// Process is the supervisor for one extension binary. The Run loop
// spawns, handshakes, and reads events forever; on exit (clean or
// crash), it sleeps for the next backoff interval and respawns.
//
// Process owns the unix-socket pair, the *exec.Cmd, the Channel, and
// one inbound + one outbound goroutine per spawn cycle. Stdout and
// stderr from the extension are *not* the wire — those are scraped
// for log lines that show up under slog `ext=<name>` keys. The wire
// is a dedicated socket FD (extra file descriptor 3) the agent passes
// at exec time.
type Process struct {
	cfg      config.Extension
	verifier SignatureVerifier
	device   ocsf.Device
	telem    *telemetry.Counters
	out      chan<- ocsf.Event

	// declaredCaps is populated post-Hello as the intersection of
	// what the extension declared and the operator's allow list.
	declaredCaps []pb.Capability

	mu      sync.Mutex
	current *exec.Cmd
	// sendCh is the per-cycle outbound queue — non-runOnce goroutines
	// (DispatchLiveQuery from the gRPC sink) push AgentToExtension
	// envelopes here; the runOnce goroutine's writer half reads and
	// calls channel.Send. Nil while no extension is connected; a
	// closed sendCh means the cycle ended and dispatchers must
	// fast-fail.
	sendCh chan *pb.AgentToExtension

	// liveQueries tracks per-query result channels for outstanding
	// LiveQueryRequest dispatches. The Recv loop fans LiveQueryRow +
	// LiveQueryComplete into the channel keyed by query_id; on
	// Complete the entry is deleted and the channel closed. Cycle
	// teardown closes every outstanding channel.
	liveQueriesMu sync.Mutex
	liveQueries   map[string]chan *pb.ExtensionToAgent

	// snapshots tracks per-snapshot reassembly state for outstanding
	// SnapshotRequest dispatches. The Recv loop pushes SnapshotChunk +
	// SnapshotComplete envelopes into the channel keyed by
	// snapshot_id. Cycle teardown closes every outstanding channel
	// without delivering a Complete — callers see the closed channel
	// and treat it as a Failed dispatch (Phase 6 #111).
	snapshotsMu sync.Mutex
	snapshots   map[string]chan *pb.ExtensionToAgent
}

// NewProcess assembles a supervisor instance. out receives stamped
// OCSF events; closing out is the manager's job (Process never
// closes it).
func NewProcess(cfg config.Extension, verifier SignatureVerifier, device ocsf.Device, telem *telemetry.Counters, out chan<- ocsf.Event) *Process {
	return &Process{
		cfg:         cfg,
		verifier:    verifier,
		device:      device,
		telem:       telem,
		out:         out,
		liveQueries: make(map[string]chan *pb.ExtensionToAgent),
		snapshots:   make(map[string]chan *pb.ExtensionToAgent),
	}
}

// HasCapability reports whether this extension declared want on Hello
// and the operator authorised it (i.e. it survived intersection).
// Returns false during the pre-Hello window.
func (p *Process) HasCapability(want pb.Capability) bool {
	for _, c := range p.declaredCaps {
		if c == want {
			return true
		}
	}
	return false
}

// Run blocks until ctx is cancelled, supervising the extension across
// crash/restart cycles. Per-cycle errors log but never bubble — the
// supervisor's job is to keep the extension running, not to fail the
// agent if one extension misbehaves.
func (p *Process) Run(ctx context.Context) error {
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := p.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err != nil {
			slog.Warn("ext: cycle ended with error",
				"ext", p.cfg.Name,
				"err", err)
			p.telem.IncExtRestart()
		} else {
			// Clean exit (extension closed the socket and exited 0)
			// still counts as a restart — the supervisor's contract
			// is "always running".
			p.telem.IncExtRestart()
		}

		// Sleep with jittered backoff. Cap-and-jitter symmetric to the
		// gRPC sink's reconnect schedule.
		jitter := time.Duration((rand.Float64()*0.5 - 0.25) * float64(backoff)) //nolint:gosec // G404: restart backoff jitter; predictability is not exploitable. See SECURITY.md "Risk dispositioning".
		sleep := backoff + jitter
		if sleep < minBackoff {
			sleep = minBackoff
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runOnce performs one full lifecycle: verify, spawn, handshake, read
// to EOF. Returns nil on clean shutdown of the extension; non-nil on
// any error (signature failure, capability violation, IO error,
// premature death).
func (p *Process) runOnce(ctx context.Context) error {
	if err := p.verifier.Verify(ctx, p.cfg.BinaryPath); err != nil {
		p.telem.IncExtSignatureFailure()
		return fmt.Errorf("verify: %w", err)
	}

	// Socketpair gives us two ends of an AF_UNIX SOCK_STREAM
	// connection; one stays with the agent, the other is passed as
	// FD 3 to the extension. The extension reads/writes on FD 3 to
	// talk to the supervisor.
	agentConn, extFile, err := socketpair()
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	defer agentConn.Close()

	cmd := exec.CommandContext(ctx, p.cfg.BinaryPath) //nolint:gosec // G204: BinaryPath is operator-controlled via agent config; cosign verify (line 164) gates execution; argv has no shell interpretation. See SECURITY.md "Risk dispositioning".
	cmd.ExtraFiles = []*os.File{extFile}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		_ = extFile.Close()
		return fmt.Errorf("start: %w", err)
	}
	// extFile belongs to the child after exec; close our copy so EOF
	// propagates correctly when the child exits.
	_ = extFile.Close()

	// Set the child's RLIMIT_AS via prlimit(2) — applies to the
	// just-started PID only, leaving the supervisor's heap unbounded.
	// The pre-fix implementation called setrlimit on the supervisor
	// itself, which OOM-killed the agent once its own heap grew past
	// the limit (Phase 6 #121 follow-up #1). Best-effort: a non-root
	// edge case where the call returns EPERM logs but doesn't fail
	// the spawn — the extension runs without a memory bound, which
	// matches the v1 contract (RSSLimitMiB is best-effort).
	if err := applyChildRSSLimit(cmd.Process.Pid, int64(p.cfg.RSSLimitMiB)<<20); err != nil {
		slog.Warn("ext: rss limit not applied",
			"ext", p.cfg.Name,
			"pid", cmd.Process.Pid,
			"err", err)
	}

	p.mu.Lock()
	p.current = cmd
	p.mu.Unlock()

	// Drain stdout/stderr into slog. Best-effort; bounded by the
	// extension's own write rate.
	go drainToLog(stdout, "ext.stdout", p.cfg.Name)
	go drainToLog(stderr, "ext.stderr", p.cfg.Name)

	// Phase 1: handshake. Read Hello within helloTimeout.
	helloCtx, helloCancel := context.WithTimeout(ctx, helloTimeout)
	defer helloCancel()

	// Read Hello over a temporary channel that respects the timeout.
	type helloResult struct {
		hello *pb.Hello
		err   error
	}
	helloCh := make(chan helloResult, 1)
	go func() {
		// Use the unguarded codec for the Hello — the gate isn't set
		// up yet (Hello is what configures it).
		h, err := readHello(agentConn)
		helloCh <- helloResult{h, err}
	}()

	var hello *pb.Hello
	select {
	case <-helloCtx.Done():
		killAndWait(cmd)
		return fmt.Errorf("hello: timeout after %s", helloTimeout)
	case res := <-helloCh:
		if res.err != nil {
			killAndWait(cmd)
			return fmt.Errorf("hello: %w", res.err)
		}
		hello = res.hello
	}

	// Intersect declared caps with operator allow list.
	allowed := capabilitySet(p.cfg.Capabilities)
	intersection := make([]pb.Capability, 0, len(hello.Capabilities))
	for _, c := range hello.Capabilities {
		if _, ok := allowed[c]; ok {
			intersection = append(intersection, c)
			continue
		}
		// Declared a capability the operator did not authorise. Fatal
		// to the connection; bring the extension down so the operator
		// has to reconfigure to grant it (rather than silently letting
		// the extension run with reduced capabilities — that would
		// surprise both operator and extension author).
		p.telem.IncExtCapabilityViolation()
		killAndWait(cmd)
		return fmt.Errorf("hello: extension declared %s but operator did not authorise it",
			CapabilityToString(c))
	}
	p.declaredCaps = intersection

	slog.Info("ext: spawned",
		"ext", p.cfg.Name,
		"version", hello.Version,
		"capabilities", capabilityNames(intersection))
	p.telem.IncExtSpawned()

	channel := NewChannel(agentConn, agentConn, intersection)

	// Phase 6 #110: a per-cycle outbound queue lets non-runOnce
	// goroutines push AgentToExtension envelopes (live-query dispatch
	// from the gRPC sink). One writer goroutine owns channel.Send —
	// matches gRPC's non-concurrent-Send pattern in #75.
	p.mu.Lock()
	p.sendCh = make(chan *pb.AgentToExtension, 16)
	sendCh := p.sendCh
	p.mu.Unlock()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case env, ok := <-sendCh:
				if !ok {
					return
				}
				if err := channel.Send(env); err != nil {
					// Send failure tears down the connection. Recv will
					// observe the resulting EOF / error and exit too.
					slog.Warn("ext: send failed", "ext", p.cfg.Name, "err", err)
					return
				}
			}
		}
	}()

	// On exit (any path), fail every outstanding live-query so the
	// dispatcher's caller doesn't block forever.
	defer func() {
		p.mu.Lock()
		ch := p.sendCh
		p.sendCh = nil
		p.mu.Unlock()
		if ch != nil {
			close(ch)
		}
		<-writerDone
		p.failAllPendingQueries()
		p.failAllPendingSnapshots()
	}()

	// Phase 2: read events forever. Live-query replies (#110) route
	// through liveQueries; snapshot replies (#111) drop on the floor
	// for now.
	for {
		if err := ctx.Err(); err != nil {
			killAndWait(cmd)
			return err
		}
		msg, err := channel.Recv()
		if err != nil {
			if errors.Is(err, ErrCapabilityViolation) {
				p.telem.IncExtCapabilityViolation()
				killAndWait(cmd)
				return err
			}
			if errors.Is(err, io.EOF) {
				_ = cmd.Wait()
				return nil
			}
			killAndWait(cmd)
			return fmt.Errorf("recv: %w", err)
		}

		switch payload := msg.Payload.(type) {
		case *pb.ExtensionToAgent_Hello:
			// Second Hello on an established connection — protocol
			// violation, tear down.
			killAndWait(cmd)
			return errors.New("recv: second Hello on established connection")
		case *pb.ExtensionToAgent_OcsfEvent:
			if ev := p.stampAndDecode(payload.OcsfEvent); ev != nil {
				select {
				case <-ctx.Done():
					killAndWait(cmd)
					return ctx.Err()
				case p.out <- ev:
					p.telem.IncExtEventEmitted()
				}
			}
		case *pb.ExtensionToAgent_LiveQueryRow:
			p.routeLiveQueryReply(payload.LiveQueryRow.GetQueryId(), msg, false)
		case *pb.ExtensionToAgent_LiveQueryComplete:
			p.routeLiveQueryReply(payload.LiveQueryComplete.GetQueryId(), msg, true)
		case *pb.ExtensionToAgent_SnapshotChunk:
			p.routeSnapshotReply(payload.SnapshotChunk.GetSnapshotId(), msg, false)
		case *pb.ExtensionToAgent_SnapshotComplete:
			p.routeSnapshotReply(payload.SnapshotComplete.GetSnapshotId(), msg, true)
		}
	}
}

// routeLiveQueryReply forwards a Row/Complete envelope to the per-query
// result channel registered by DispatchLiveQuery. complete=true closes
// + deletes the entry. Unknown query_ids are dropped + logged — the
// dispatcher may have torn down (e.g. timeout) before the extension's
// response landed.
func (p *Process) routeLiveQueryReply(queryID string, msg *pb.ExtensionToAgent, complete bool) {
	if queryID == "" {
		slog.Warn("ext: live-query reply with empty query_id", "ext", p.cfg.Name)
		return
	}
	p.liveQueriesMu.Lock()
	ch, ok := p.liveQueries[queryID]
	if complete && ok {
		delete(p.liveQueries, queryID)
	}
	p.liveQueriesMu.Unlock()
	if !ok {
		slog.Debug("ext: live-query reply for unknown query_id",
			"ext", p.cfg.Name, "query_id", queryID, "complete", complete)
		return
	}
	// Best-effort send; drop on a wedged consumer rather than block
	// the supervisor's Recv loop. The dispatcher's reader is sized to
	// max_rows+1 so this only fires on slow consumers.
	select {
	case ch <- msg:
	default:
		slog.Warn("ext: live-query result channel full; dropping",
			"ext", p.cfg.Name, "query_id", queryID)
	}
	if complete {
		close(ch)
	}
}

// failAllPendingQueries closes every outstanding live-query channel
// without delivering a Complete — callers see a closed channel and
// must treat it as an extension teardown.
func (p *Process) failAllPendingQueries() {
	p.liveQueriesMu.Lock()
	defer p.liveQueriesMu.Unlock()
	for id, ch := range p.liveQueries {
		close(ch)
		delete(p.liveQueries, id)
	}
}

// DispatchLiveQuery sends a LiveQueryRequest to the extension and
// returns a result channel that receives every LiveQueryRow followed
// by exactly one LiveQueryComplete envelope, then closes. Closes
// without a Complete iff the extension's cycle ended unexpectedly.
//
// Returns ErrExtensionUnavailable when no cycle is active or
// ErrCapabilityViolation when the extension didn't declare
// LIVE_QUERY_RESPOND.
func (p *Process) DispatchLiveQuery(ctx context.Context, req *pb.LiveQueryRequest) (<-chan *pb.ExtensionToAgent, error) {
	if req == nil || req.GetQueryId() == "" {
		return nil, errors.New("ext: DispatchLiveQuery: query_id required")
	}
	if !p.HasCapability(pb.Capability_CAPABILITY_LIVE_QUERY_RESPOND) {
		return nil, ErrCapabilityViolation
	}
	p.mu.Lock()
	send := p.sendCh
	p.mu.Unlock()
	if send == nil {
		return nil, ErrExtensionUnavailable
	}
	// Result chan capacity = max_rows + 1 (rows + complete) so the
	// supervisor's routeLiveQueryReply never wedges. Capped at a sane
	// upper bound — extensions that try to overflow are throttled by
	// the agent's row-cap enforcement before getting here.
	chCap := int(req.GetMaxRows()) + 1
	if chCap <= 0 || chCap > 65536 {
		chCap = 65536
	}
	resultCh := make(chan *pb.ExtensionToAgent, chCap)
	p.liveQueriesMu.Lock()
	if _, dup := p.liveQueries[req.GetQueryId()]; dup {
		p.liveQueriesMu.Unlock()
		close(resultCh)
		return nil, fmt.Errorf("ext: DispatchLiveQuery: duplicate query_id %s", req.GetQueryId())
	}
	p.liveQueries[req.GetQueryId()] = resultCh
	p.liveQueriesMu.Unlock()

	envelope := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_LiveQueryRequest{LiveQueryRequest: req},
	}
	select {
	case <-ctx.Done():
		p.cancelLiveQuery(req.GetQueryId())
		return nil, ctx.Err()
	case send <- envelope:
		return resultCh, nil
	}
}

// cancelLiveQuery removes a per-query result channel. Used when
// DispatchLiveQuery fails before the request lands on the wire.
func (p *Process) cancelLiveQuery(queryID string) {
	p.liveQueriesMu.Lock()
	defer p.liveQueriesMu.Unlock()
	if ch, ok := p.liveQueries[queryID]; ok {
		close(ch)
		delete(p.liveQueries, queryID)
	}
}

// routeSnapshotReply forwards a Chunk/Complete envelope to the per-
// snapshot result channel registered by DispatchSnapshot. complete=true
// closes + deletes the entry. Unknown snapshot_ids are dropped + logged
// — the dispatcher may have torn down (e.g. timeout) before the
// extension's response landed.
func (p *Process) routeSnapshotReply(snapshotID string, msg *pb.ExtensionToAgent, complete bool) {
	if snapshotID == "" {
		slog.Warn("ext: snapshot reply with empty snapshot_id", "ext", p.cfg.Name)
		return
	}
	p.snapshotsMu.Lock()
	ch, ok := p.snapshots[snapshotID]
	if complete && ok {
		delete(p.snapshots, snapshotID)
	}
	p.snapshotsMu.Unlock()
	if !ok {
		slog.Debug("ext: snapshot reply for unknown snapshot_id",
			"ext", p.cfg.Name, "snapshot_id", snapshotID, "complete", complete)
		return
	}
	// Best-effort send; drop on a wedged consumer rather than block
	// the supervisor's Recv loop. The dispatcher's reader is sized
	// large enough for a typical reassembly.
	select {
	case ch <- msg:
	default:
		slog.Warn("ext: snapshot result channel full; dropping",
			"ext", p.cfg.Name, "snapshot_id", snapshotID)
	}
	if complete {
		close(ch)
	}
}

// failAllPendingSnapshots closes every outstanding snapshot reassembly
// channel without delivering a Complete — callers see a closed channel
// and treat it as a Failed dispatch.
func (p *Process) failAllPendingSnapshots() {
	p.snapshotsMu.Lock()
	defer p.snapshotsMu.Unlock()
	for id, ch := range p.snapshots {
		close(ch)
		delete(p.snapshots, id)
	}
}

// snapshotChanCap bounds the per-snapshot reassembly channel capacity.
// Sized for a typical forensic blob (a few thousand 4 KiB chunks +
// one Complete). An extension that streams more than this caps out and
// the supervisor drops chunks; the dispatcher's rolling-SHA verifier
// catches the discontinuity and the snapshot fails cleanly.
const snapshotChanCap = 8192

// DispatchSnapshot sends a SnapshotRequest to the extension and
// returns a result channel that receives every SnapshotChunk followed
// by exactly one SnapshotComplete envelope, then closes. Closes
// without a Complete iff the extension's cycle ended unexpectedly.
//
// Returns ErrExtensionUnavailable when no cycle is active or
// ErrCapabilityViolation when the extension didn't declare
// CAPABILITY_SNAPSHOT_PROVIDE. Phase 6 #111.
func (p *Process) DispatchSnapshot(ctx context.Context, req *pb.SnapshotRequest) (<-chan *pb.ExtensionToAgent, error) {
	if req == nil || req.GetSnapshotId() == "" {
		return nil, errors.New("ext: DispatchSnapshot: snapshot_id required")
	}
	if !p.HasCapability(pb.Capability_CAPABILITY_SNAPSHOT_PROVIDE) {
		return nil, ErrCapabilityViolation
	}
	p.mu.Lock()
	send := p.sendCh
	p.mu.Unlock()
	if send == nil {
		return nil, ErrExtensionUnavailable
	}
	resultCh := make(chan *pb.ExtensionToAgent, snapshotChanCap)
	p.snapshotsMu.Lock()
	if _, dup := p.snapshots[req.GetSnapshotId()]; dup {
		p.snapshotsMu.Unlock()
		close(resultCh)
		return nil, fmt.Errorf("ext: DispatchSnapshot: duplicate snapshot_id %s", req.GetSnapshotId())
	}
	p.snapshots[req.GetSnapshotId()] = resultCh
	p.snapshotsMu.Unlock()

	envelope := &pb.AgentToExtension{
		Payload: &pb.AgentToExtension_SnapshotRequest{SnapshotRequest: req},
	}
	select {
	case <-ctx.Done():
		p.cancelSnapshot(req.GetSnapshotId())
		return nil, ctx.Err()
	case send <- envelope:
		return resultCh, nil
	}
}

// cancelSnapshot removes a per-snapshot result channel. Used when
// DispatchSnapshot fails before the request lands on the wire.
func (p *Process) cancelSnapshot(snapshotID string) {
	p.snapshotsMu.Lock()
	defer p.snapshotsMu.Unlock()
	if ch, ok := p.snapshots[snapshotID]; ok {
		close(ch)
		delete(p.snapshots, snapshotID)
	}
}

// ErrExtensionUnavailable is returned by DispatchLiveQuery and
// DispatchSnapshot when no extension cycle is currently active.
var ErrExtensionUnavailable = errors.New("ext: extension not currently spawned")

// stampAndDecode parses the extension's OCSF JSON payload, stamps the
// agent's device identity + the current wall-clock, and returns the
// concrete ocsf.Event type. Unknown class IDs and unparseable
// payloads log + drop rather than killing the connection — a single
// malformed event from a buggy extension shouldn't tear down the
// whole supervisor.
func (p *Process) stampAndDecode(emitted *pb.OCSFEvent) ocsf.Event {
	now := time.Now()
	switch emitted.ClassId {
	case pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY:
		var ev ocsf.ProcessActivity
		if err := json.Unmarshal(emitted.Payload, &ev); err != nil {
			slog.Warn("ext: ocsf decode failed", "ext", p.cfg.Name, "class", "process_activity", "err", err)
			return nil
		}
		ev.Device = p.device
		ev.Time = ocsf.TimeOCSF(now.UnixMilli())
		if ev.ClassUID == 0 {
			ev.ClassUID = ocsf.ClassProcessActivity
		}
		ev.Metadata.Product.Name = p.cfg.Name + " (extension)"
		return &ev
	case pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY:
		var ev ocsf.FileSystemActivity
		if err := json.Unmarshal(emitted.Payload, &ev); err != nil {
			slog.Warn("ext: ocsf decode failed", "ext", p.cfg.Name, "class", "file_system_activity", "err", err)
			return nil
		}
		ev.Device = p.device
		ev.Time = ocsf.TimeOCSF(now.UnixMilli())
		if ev.ClassUID == 0 {
			ev.ClassUID = ocsf.ClassFileSystemActivity
		}
		ev.Metadata.Product.Name = p.cfg.Name + " (extension)"
		return &ev
	case pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY:
		var ev ocsf.NetworkActivity
		if err := json.Unmarshal(emitted.Payload, &ev); err != nil {
			slog.Warn("ext: ocsf decode failed", "ext", p.cfg.Name, "class", "network_activity", "err", err)
			return nil
		}
		ev.Device = p.device
		ev.Time = ocsf.TimeOCSF(now.UnixMilli())
		if ev.ClassUID == 0 {
			ev.ClassUID = ocsf.ClassNetworkActivity
		}
		ev.Metadata.Product.Name = p.cfg.Name + " (extension)"
		return &ev
	case pb.OcsfClassId_OCSF_CLASS_ID_KERNEL_ACTIVITY:
		// Phase 6 #109 — added when the osquery bridge began emitting
		// kernel_modules events. Pre-#109 extensions never emitted this
		// class; no compat concern.
		var ev ocsf.KernelActivity
		if err := json.Unmarshal(emitted.Payload, &ev); err != nil {
			slog.Warn("ext: ocsf decode failed", "ext", p.cfg.Name, "class", "kernel_activity", "err", err)
			return nil
		}
		ev.Device = p.device
		ev.Time = ocsf.TimeOCSF(now.UnixMilli())
		if ev.ClassUID == 0 {
			ev.ClassUID = ocsf.ClassKernelActivity
		}
		ev.Metadata.Product.Name = p.cfg.Name + " (extension)"
		return &ev
	}
	slog.Warn("ext: dropping ocsf event with unsupported class",
		"ext", p.cfg.Name,
		"class_id", emitted.ClassId)
	return nil
}

func killAndWait(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func drainToLog(r io.Reader, kind, name string) {
	if r == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			slog.Info(kind, "ext", name, "line", string(buf[:n]))
		}
		if err != nil {
			return
		}
	}
}

func capabilitySet(strs []string) map[pb.Capability]struct{} {
	out := make(map[pb.Capability]struct{}, len(strs))
	for _, s := range strs {
		if c := CapabilityFromString(s); c != pb.Capability_CAPABILITY_UNSPECIFIED {
			out[c] = struct{}{}
		}
	}
	return out
}

func capabilityNames(caps []pb.Capability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = CapabilityToString(c)
	}
	return out
}

// readHello reads the first ExtensionToAgent envelope on a fresh
// connection and returns the Hello payload. Any other payload kind
// is a protocol violation; the supervisor will tear down on error.
func readHello(r io.Reader) (*pb.Hello, error) {
	msg, err := extsdk.ReadExtensionToAgent(r)
	if err != nil {
		return nil, err
	}
	hello := msg.GetHello()
	if hello == nil {
		return nil, fmt.Errorf("first envelope must be Hello, got %T", msg.Payload)
	}
	return hello, nil
}
