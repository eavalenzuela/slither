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
}

// NewProcess assembles a supervisor instance. out receives stamped
// OCSF events; closing out is the manager's job (Process never
// closes it).
func NewProcess(cfg config.Extension, verifier SignatureVerifier, device ocsf.Device, telem *telemetry.Counters, out chan<- ocsf.Event) *Process {
	return &Process{
		cfg:      cfg,
		verifier: verifier,
		device:   device,
		telem:    telem,
		out:      out,
	}
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
		jitter := time.Duration((rand.Float64()*0.5 - 0.25) * float64(backoff))
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

	cmd := exec.CommandContext(ctx, p.cfg.BinaryPath)
	cmd.ExtraFiles = []*os.File{extFile}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	applyRSSLimit(cmd, int64(p.cfg.RSSLimitMiB)<<20)

	if err := cmd.Start(); err != nil {
		_ = extFile.Close()
		return fmt.Errorf("start: %w", err)
	}
	// extFile belongs to the child after exec; close our copy so EOF
	// propagates correctly when the child exits.
	_ = extFile.Close()

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

	// Phase 2: read events forever. Live-query + snapshot dispatch
	// (#110/#111) wires onto the same channel via a future Send path;
	// for #107 we only consume.
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
			// Live-query / snapshot replies have no consumer in
			// #107 — they're plumbed in #110 / #111.
		}
	}
}

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
