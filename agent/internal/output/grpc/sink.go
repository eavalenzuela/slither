// Package grpc implements the agent's gRPC Session-stream output sink.
//
// Phase 2 §4.1 task #35: the agent opens a long-lived bidi stream to the
// server, marshals each ocsf.Event into an Envelope carried inside a
// ClientMessage, and sends Heartbeats at a configured cadence. Network
// blips close the stream; the sink sleeps with jittered exponential
// backoff (1s → 60s) and re-opens. Events are buffered in a bounded
// channel between Sink.Run's ingest path and the sender goroutine;
// when the buffer is full the oldest pending event is dropped to match
// the "newest is most useful" invariant the rest of the agent observes.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/t3rmit3/slither/agent/internal/telemetry"
	"github.com/t3rmit3/slither/pkg/ocsf"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Options configures the sink. Filled in by app.Run from config.Output.GRPC.
type Options struct {
	ServerAddr        string
	CAPath            string
	CertPath          string
	KeyPath           string
	HostIDPath        string
	HeartbeatInterval time.Duration
	BufferSize        int
	AgentVersion      string // stamped on every Envelope

	// Dialer is an optional gRPC dial-options list. Tests inject
	// bufconn-backed dial options here; production leaves it nil and
	// the sink builds TLS + a standard dialer.
	DialOptions []grpc.DialOption

	// OnRuleSet, when non-nil, is called for every server-pushed
	// RuleSet (Phase 2 §4.1 #39). Production wires this to
	// ruleengine.Engine.ReplaceRules; tests inject a recorder.
	OnRuleSet func(*pb.RuleSet)

	// OnResponseRequest, when non-nil, is called for every
	// server-pushed ResponseRequest (Phase 4 #77). Production
	// wires this to respond.Executor.Submit; tests inject a
	// recorder. The callback must be non-blocking — the sink's
	// recv goroutine cannot stall on a wedged executor.
	OnResponseRequest func(*pb.ResponseRequest)

	// OnHostPolicy, when non-nil, is called for every server-pushed
	// HostPolicy (Phase 4 #84). Production wires this to the agent's
	// auto-respond cache (atomic.Pointer behind a PolicyProvider).
	// Must be non-blocking.
	OnHostPolicy func(*pb.HostPolicy)
}

// Sink is the gRPC Session-stream output. Implements
// agent/internal/output.Sink (satisfied structurally; there is no
// interface import to avoid a package cycle).
type Sink struct {
	opts  Options
	telem *telemetry.Counters

	hostID string
	buf    chan *pb.Envelope

	// diags carries DiagReport messages queued by EmitDiag. Capacity
	// stays small (Phase 3 #57): a single ruleset apply emits one
	// report at most, and rule pushes are debounced server-side. Drop
	// when full rather than blocking — diagnostics losing one report
	// is preferable to the rule-apply path stalling.
	diags chan *pb.DiagReport

	// results carries ResponseResult messages emitted by the agent's
	// executor (Phase 4 #77). Capacity matches the executor's worker
	// pool so a burst of in-flight handlers can each push without
	// blocking; if the channel saturates the executor counts a
	// response_exec_result_dropped via telemetry.
	results chan *pb.ResponseResult
}

// New constructs a Sink. Reads host_id from disk up-front — a sink
// can't stamp events without one, and degrading to an empty host_id
// silently would produce unattributable events the server would
// probably reject.
func New(opts Options, telem *telemetry.Counters) (*Sink, error) {
	if opts.ServerAddr == "" {
		return nil, fmt.Errorf("grpc sink: server_addr required")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = 30 * time.Second
	}

	hostID, err := readHostID(opts.HostIDPath)
	if err != nil {
		return nil, fmt.Errorf("grpc sink: %w", err)
	}

	return &Sink{
		opts:    opts,
		telem:   telem,
		hostID:  hostID,
		buf:     make(chan *pb.Envelope, opts.BufferSize),
		diags:   make(chan *pb.DiagReport, 8),
		results: make(chan *pb.ResponseResult, 16),
	}, nil
}

// Results returns the executor → sink pipe. Phase 4 #77 wires this
// into respond.New so handlers push their ResponseResult here; the
// session goroutine fans onto stream.Send under the same gRPC
// non-concurrent-send contract that #75 codified for the server side.
func (s *Sink) Results() chan<- *pb.ResponseResult { return s.results }

// EmitDiag queues a DiagReport with the given warnings to be sent on
// the next Session iteration. Phase 3 #57: applyRuleSetTo calls this
// when rule refusals (state_window_too_large, ast_version_unsupported,
// …) occur so the server's session log can show what got rejected
// without operators scraping agent stderr. Drops on full — operational
// tradeoff documented on the diags channel.
func (s *Sink) EmitDiag(warnings []string) {
	if len(warnings) == 0 {
		return
	}
	report := &pb.DiagReport{
		HostId:   s.hostID,
		Warnings: append([]string(nil), warnings...),
	}
	select {
	case s.diags <- report:
	default:
		// Diag channel saturated. The next ruleset push will surface
		// any persistent refusal anyway, so dropping is fine.
	}
}

// Run is the Sink contract: block draining in until ctx is cancelled.
// Internally two concurrent paths run:
//
//   - ingest: reads ocsf.Event from in, marshals to Envelope, pushes
//     into s.buf (drop-oldest on full).
//   - session: maintains one gRPC ClientConn; opens a Session stream;
//     sends events + periodic heartbeats; on any network error closes
//     the stream and reconnects with jittered exponential backoff.
func (s *Sink) Run(ctx context.Context, in <-chan ocsf.Event) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ingestDone := make(chan struct{})
	go func() {
		defer close(ingestDone)
		s.ingest(ctx, in)
	}()

	err := s.session(ctx)
	<-ingestDone
	return err
}

// ingest drains `in`, converts each event to an Envelope and pushes it
// into the bounded buffer. Backpressure policy is drop-oldest: the
// upstream (engine.out → sink) is not blocked by a flapping server.
func (s *Sink) ingest(ctx context.Context, in <-chan ocsf.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			env, err := s.encode(ev)
			if err != nil {
				// Cannot encode — very unlikely with well-formed OCSF.
				// Treat as a dropped event rather than failing the sink.
				s.telem.IncDropOutput()
				continue
			}
			s.push(env)
		}
	}
}

// push pushes env into s.buf. On full: drop the oldest queued envelope
// (per §4.1 #35 drop-oldest policy), then retry the send. Both selects
// are non-blocking; in the pathological case we fail to enqueue and
// count the drop, keeping upstream unblocked.
func (s *Sink) push(env *pb.Envelope) {
	select {
	case s.buf <- env:
		return
	default:
	}
	// Full — drop oldest.
	select {
	case <-s.buf:
		s.telem.IncDropOutput()
	default:
	}
	select {
	case s.buf <- env:
	default:
		// Lost the race with another dropper / sender. Count this
		// envelope as dropped too.
		s.telem.IncDropOutput()
	}
}

// session opens a ClientConn, then loops opening Session streams and
// running runSession against each. Returns on ctx cancellation; any
// other error triggers a backoff + retry.
func (s *Sink) session(ctx context.Context) error {
	dialOpts, err := s.dialOptions()
	if err != nil {
		return fmt.Errorf("grpc sink: dial options: %w", err)
	}
	conn, err := grpc.NewClient(s.opts.ServerAddr, dialOpts...)
	if err != nil {
		return fmt.Errorf("grpc sink: new client: %w", err)
	}
	defer conn.Close()
	client := pb.NewAgentServiceClient(conn)

	backoff := initialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		runErr := s.runSession(ctx, client)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.telem.IncOutputReconnect()
		_ = runErr // exposed via OutputReconnects counter; avoid stderr noise in tests
		if sleepErr := sleepWithJitter(ctx, backoff); sleepErr != nil {
			return sleepErr
		}
		backoff = nextBackoff(backoff)
	}
}

// runSession opens one Session stream and runs it until any error or
// ctx cancellation. All stream ops (SendMsg, heartbeats) happen on one
// goroutine — gRPC stream SendMsg is NOT concurrency-safe.
func (s *Sink) runSession(ctx context.Context, client pb.AgentServiceClient) error {
	stream, err := client.Session(ctx)
	if err != nil {
		return err
	}
	// Server may send control messages back (RuleSet today, hunt
	// queries + response requests in later phases). A receive goroutine
	// keeps the half-stream drained and dispatches RuleSet to the
	// configured callback (#39 wires Engine.ReplaceRules).
	recvErr := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			s.handleServerMessage(msg)
		}
	}()

	hb := time.NewTicker(s.opts.HeartbeatInterval)
	defer hb.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return ctx.Err()
		case err := <-recvErr:
			return err
		case env := <-s.buf:
			if err := stream.Send(&pb.ClientMessage{
				Kind: &pb.ClientMessage_Event{Event: env},
			}); err != nil {
				return err
			}
		case diag := <-s.diags:
			if err := stream.Send(&pb.ClientMessage{
				Kind: &pb.ClientMessage_Diag{Diag: diag},
			}); err != nil {
				return err
			}
		case res := <-s.results:
			if err := stream.Send(&pb.ClientMessage{
				Kind: &pb.ClientMessage_ResponseResult{ResponseResult: res},
			}); err != nil {
				return err
			}
		case <-hb.C:
			if err := stream.Send(&pb.ClientMessage{
				Kind: &pb.ClientMessage_Heartbeat{
					Heartbeat: &pb.Heartbeat{
						HostId: s.hostID,
						SentAt: timestamppb.Now(),
					},
				},
			}); err != nil {
				return err
			}
			s.telem.IncHeartbeatSent()
		}
	}
}

// handleServerMessage dispatches one ServerMessage. RuleSet pushes
// fan into OnRuleSet; ResponseRequest into OnResponseRequest;
// HostPolicy into OnHostPolicy (Phase 4 #84). HuntQuery is Phase 6.
func (s *Sink) handleServerMessage(msg *pb.ServerMessage) {
	if msg == nil {
		return
	}
	switch k := msg.GetKind().(type) {
	case *pb.ServerMessage_RuleSet:
		if s.opts.OnRuleSet != nil && k.RuleSet != nil {
			s.opts.OnRuleSet(k.RuleSet)
		}
	case *pb.ServerMessage_ResponseRequest:
		if s.opts.OnResponseRequest != nil && k.ResponseRequest != nil {
			s.opts.OnResponseRequest(k.ResponseRequest)
		}
	case *pb.ServerMessage_HostPolicy:
		if s.opts.OnHostPolicy != nil && k.HostPolicy != nil {
			s.opts.OnHostPolicy(k.HostPolicy)
		}
	}
}

// encode builds an Envelope for ev. Payload is canonical JSON (matching
// ADR-0017's wire format decision for OCSF payloads).
func (s *Sink) encode(ev ocsf.Event) (*pb.Envelope, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	// OCSF events don't carry a pre-normalised observed_at — the
	// Metadata.OriginalT (OCSF `original_time`, unix milliseconds) is
	// the closest thing. If missing, use collected_at and let the
	// server's skew dashboard flag it.
	md := envMetadata(ev)
	observed := timestamppb.New(time.UnixMilli(md.OriginalT))
	if md.OriginalT == 0 {
		observed = timestamppb.Now()
	}
	return &pb.Envelope{
		EventId:      md.UID,
		HostId:       s.hostID,
		AgentVersion: s.opts.AgentVersion,
		ClassId:      classIDToProto(ev.ClassID()),
		ObservedAt:   observed,
		CollectedAt:  timestamppb.Now(),
		Payload:      payload,
		Priority:     pb.Priority_PRIORITY_EVENT,
	}, nil
}

// envMetadata extracts the OCSF Metadata block from an event via
// reflection-free access. Every concrete OCSF event type embeds a
// Metadata field; we avoid a heavyweight interface by marshalling +
// re-unmarshalling the outer metadata only.
func envMetadata(ev ocsf.Event) ocsf.Metadata {
	b, err := json.Marshal(ev)
	if err != nil {
		return ocsf.Metadata{}
	}
	var wrap struct {
		Metadata ocsf.Metadata `json:"metadata"`
	}
	_ = json.Unmarshal(b, &wrap)
	return wrap.Metadata
}

func classIDToProto(c ocsf.ClassID) pb.OcsfClassId {
	switch c {
	case ocsf.ClassFileSystemActivity:
		return pb.OcsfClassId_OCSF_CLASS_ID_FILE_SYSTEM_ACTIVITY
	case ocsf.ClassKernelActivity:
		return pb.OcsfClassId_OCSF_CLASS_ID_KERNEL_ACTIVITY
	case ocsf.ClassProcessActivity:
		return pb.OcsfClassId_OCSF_CLASS_ID_PROCESS_ACTIVITY
	case ocsf.ClassDetectionFinding:
		return pb.OcsfClassId_OCSF_CLASS_ID_DETECTION_FINDING
	case ocsf.ClassAuthentication:
		return pb.OcsfClassId_OCSF_CLASS_ID_AUTHENTICATION
	case ocsf.ClassNetworkActivity:
		return pb.OcsfClassId_OCSF_CLASS_ID_NETWORK_ACTIVITY
	case ocsf.ClassDnsActivity:
		return pb.OcsfClassId_OCSF_CLASS_ID_DNS_ACTIVITY
	case ocsf.ClassContainerLifecycle:
		return pb.OcsfClassId_OCSF_CLASS_ID_CONTAINER_LIFECYCLE
	}
	return pb.OcsfClassId_OCSF_CLASS_ID_UNSPECIFIED
}

// dialOptions returns the gRPC dial options. Tests inject their own
// (bufconn + insecure) via Options.DialOptions; when left nil we build
// mTLS from the configured cert paths.
func (s *Sink) dialOptions() ([]grpc.DialOption, error) {
	if len(s.opts.DialOptions) > 0 {
		return s.opts.DialOptions, nil
	}
	cert, err := tls.LoadX509KeyPair(s.opts.CertPath, s.opts.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	caPEM, err := os.ReadFile(s.opts.CAPath) //nolint:gosec // operator-supplied
	if err != nil {
		return nil, fmt.Errorf("ca read: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates in %s", s.opts.CAPath)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	})
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}, nil
}

func readHostID(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return "", fmt.Errorf("read host_id %q: %w", path, err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", fmt.Errorf("host_id file %q is empty", path)
	}
	return id, nil
}

// --- backoff ---

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 60 * time.Second
	jitterFrac     = 0.25 // ±25%
)

func nextBackoff(cur time.Duration) time.Duration {
	n := cur * 2
	if n > maxBackoff {
		return maxBackoff
	}
	return n
}

// sleepWithJitter sleeps base ± 25%, respecting ctx.
func sleepWithJitter(ctx context.Context, base time.Duration) error {
	j := jitter(base)
	t := time.NewTimer(j)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	spread := float64(base) * jitterFrac
	//nolint:gosec // non-crypto jitter; math/rand is fine
	delta := (rand.Float64()*2 - 1) * spread
	return base + time.Duration(delta)
}

// ensure errors.Is lookups remain usable even after heavy wrapping.
var _ = errors.Is
