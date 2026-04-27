// Phase 2 §4.1 task #37 (events) + #39 (rule push): AgentService.Session
// on the mTLS listener. Authenticated by the listener's
// tls.RequireAndVerifyClientCert; the handler reads the host_id from
// the verified peer cert's Subject.CN rather than trusting the wire
// fields, then demuxes ClientMessage kinds onto the ingest bus and the
// Postgres host-state writer. The send half subscribes to a control.Hub
// (when non-nil) and pushes RuleSet ServerMessages on every update;
// initial RuleSet is delivered synchronously by the hub at Subscribe.

package grpcserv

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// RuleHub is the dependency the Session handler needs from the control
// package. Defining a local interface avoids a server→control import
// cycle once #41 wires the console which also talks to the hub.
type RuleHub interface {
	Subscribe(name string) <-chan *pb.RuleSet
	Unsubscribe(name string)
}

// SessionService implements AgentService.Session. It embeds
// UnimplementedAgentServiceServer so it satisfies AgentServiceServer
// with Enroll left unimplemented — the two halves of AgentService run
// on different listeners (Enroll on the unauthenticated enrollment
// listener, Session on the mTLS listener) and each listener registers
// only its half.
type SessionService struct {
	pb.UnimplementedAgentServiceServer

	Store   *pg.Store
	Bus     *ingest.Bus
	Telem   *telemetry.Counters
	RuleHub RuleHub // optional; nil disables rule push

	// PeerHostIDExtractor is overridable for tests that route through
	// bufconn without real client certs. Production leaves it nil and
	// the handler reads the verified peer cert's Subject.CN.
	PeerHostIDExtractor func(ctx context.Context) (string, error)
}

// NewSessionService constructs a Session handler. Store, Bus, and Telem
// are required.
func NewSessionService(store *pg.Store, bus *ingest.Bus, telem *telemetry.Counters) *SessionService {
	if store == nil {
		panic("grpcserv.NewSessionService: nil store")
	}
	if bus == nil {
		panic("grpcserv.NewSessionService: nil bus")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &SessionService{Store: store, Bus: bus, Telem: telem}
}

// Session is the bidirectional agent stream. Authenticate once from the
// peer cert, then loop reading ClientMessage until the agent closes the
// stream or the context is cancelled. The send half stays open so #39
// can push RuleSet messages without a new round trip.
func (s *SessionService) Session(stream pb.AgentService_SessionServer) error {
	ctx := stream.Context()

	hostID, err := s.authenticate(ctx)
	if err != nil {
		s.Telem.IncAuthnFailure()
		return err
	}

	exists, err := s.Store.HostExists(ctx, hostID)
	if err != nil {
		s.Telem.IncAuthnFailure()
		return status.Errorf(codes.Internal, "host lookup: %v", err)
	}
	if !exists {
		s.Telem.IncAuthnFailure()
		return status.Errorf(codes.Unauthenticated, "host %s not enrolled or revoked", hostID)
	}

	s.Telem.SessionOpened()
	defer s.Telem.SessionClosed()

	// Send half: a single goroutine owns stream.Send. gRPC stream.Send
	// is NOT concurrent-safe, which is why we do not call it from the
	// Recv goroutine even on heartbeat/ack paths. The send goroutine
	// only exits when its context is done; the Recv loop drives that
	// by cancelling sendCtx on its own return.
	sendCtx, cancelSend := context.WithCancel(ctx)
	var sendWG sync.WaitGroup
	if s.RuleHub != nil {
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			s.runSendLoop(sendCtx, hostID, stream)
		}()
	}
	defer func() {
		cancelSend()
		sendWG.Wait()
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		s.handle(ctx, hostID, msg)
	}
}

// runSendLoop subscribes to the rule hub for this session and pushes
// every RuleSet it receives on the stream. Exits when sendCtx is done
// or stream.Send returns an error (broken transport — Recv will see it
// next read and tear down).
func (s *SessionService) runSendLoop(sendCtx context.Context, hostID string, stream pb.AgentService_SessionServer) {
	subName := "session:" + hostID
	updates := s.RuleHub.Subscribe(subName)
	defer s.RuleHub.Unsubscribe(subName)

	for {
		select {
		case <-sendCtx.Done():
			return
		case rs, ok := <-updates:
			if !ok {
				return
			}
			if rs == nil {
				continue
			}
			if err := stream.Send(&pb.ServerMessage{
				Kind: &pb.ServerMessage_RuleSet{RuleSet: rs},
			}); err != nil {
				return
			}
			s.Telem.IncRulesetsPushed()
			s.Telem.IncSubscriberPublish(subName)
			slog.Debug("hub: subscriber received",
				"subscriber", subName,
				"version", rs.GetVersion(),
				"rule_count", len(rs.GetRules()))
		}
	}
}

// handle dispatches one ClientMessage. Per-event problems (a single bad
// envelope, a heartbeat for a host whose row vanished) are swallowed
// and counted so one misbehaving message can't kill an otherwise-healthy
// session — only stream-level errors (read in Session itself) tear down.
func (s *SessionService) handle(ctx context.Context, hostID string, msg *pb.ClientMessage) {
	switch k := msg.GetKind().(type) {
	case *pb.ClientMessage_Event:
		s.publishEvent(hostID, k.Event)
	case *pb.ClientMessage_Heartbeat:
		if hb := k.Heartbeat; hb != nil {
			s.applyHeartbeat(ctx, hostID)
		}
	case *pb.ClientMessage_Ack:
		// RuleSet acks consumed by future hub work; observational today.
	case *pb.ClientMessage_Diag:
		// Phase 3 #57: DiagReport.warnings carry agent-side rule
		// refusals (`rule:<id>:<reason>`) per ADR-0032. Log each at
		// WARN so operators reading `journalctl -u slither-server`
		// see the failed predicates without scraping agent stderr.
		s.logDiagReport(hostID, k.Diag)
	case nil:
		// Empty oneof — protocol violation, but tolerate it.
	default:
		// Unknown kind — proto evolution scenario; ignore.
		_ = k
	}
}

// publishEvent stamps the trusted host_id over whatever the agent
// claimed and pushes onto the bus. Stamping (not just verifying)
// follows the §3.2 trust model: the wire host_id is advisory.
func (s *SessionService) publishEvent(hostID string, env *pb.Envelope) {
	if env == nil {
		return
	}
	env.HostId = hostID
	s.Telem.IncEventsReceived()
	s.Bus.Publish(env)
}

// logDiagReport surfaces an agent's per-warning refusal vocabulary.
// Each warning is the wire-level `rule:<rule_id>:<reason>` shape from
// ADR-0032; we parse it back into structured slog fields so log
// shippers can group on rule_id or reason without regex on the
// message. Malformed warnings (anything not matching the expected
// shape) log raw — better noisy than silent.
func (s *SessionService) logDiagReport(hostID string, diag *pb.DiagReport) {
	if diag == nil {
		return
	}
	for _, w := range diag.GetWarnings() {
		ruleID, reason, ok := parseRuleWarning(w)
		if !ok {
			slog.Warn("agent diag warning",
				"host_id", hostID, "warning", w)
			continue
		}
		slog.Warn("agent rule refusal",
			"host_id", hostID,
			"rule_id", ruleID,
			"reason", reason)
	}
}

// parseRuleWarning splits "rule:<id>:<reason>" into its parts. The id
// itself is opaque (Sigma uids contain colons-not-but-letters-and-
// dashes today, but a lenient parser future-proofs that). We anchor on
// the leading "rule:" prefix and split off the trailing reason on the
// last ":" so a UID containing colons would still parse cleanly.
func parseRuleWarning(w string) (ruleID, reason string, ok bool) {
	if !strings.HasPrefix(w, "rule:") {
		return "", "", false
	}
	body := strings.TrimPrefix(w, "rule:")
	idx := strings.LastIndex(body, ":")
	if idx < 0 {
		return "", "", false
	}
	return body[:idx], body[idx+1:], true
}

// applyHeartbeat bumps hosts.last_seen. A missing row here is logged
// (via authn-failure counter) but does not tear down the stream — the
// Session itself was already authn'd; a heartbeat for a since-revoked
// host should be tracked separately so revocation work in #44 has
// visibility.
func (s *SessionService) applyHeartbeat(ctx context.Context, hostID string) {
	s.Telem.IncHeartbeat()
	if err := s.Store.UpdateHostLastSeen(ctx, hostID); err != nil && !errors.Is(err, pg.ErrHostNotFound) {
		// Real DB error; counted as authn failure so it surfaces in the
		// same dashboard as cert/CN problems. Do not return — the agent
		// will retry on next heartbeat.
		s.Telem.IncAuthnFailure()
	}
}

// authenticate extracts the host_id from the verified peer cert.
// Returns Unauthenticated if there is no peer cert or the CN is
// missing/blank — the listener should already enforce a verified
// client cert, but defence-in-depth here guards against handler
// misconfiguration.
func (s *SessionService) authenticate(ctx context.Context) (string, error) {
	if s.PeerHostIDExtractor != nil {
		id, err := s.PeerHostIDExtractor(ctx)
		if err != nil {
			return "", status.Errorf(codes.Unauthenticated, "%v", err)
		}
		if id == "" {
			return "", status.Error(codes.Unauthenticated, "empty host_id from peer extractor")
		}
		return id, nil
	}

	p, ok := peer.FromContext(ctx)
	if !ok || p == nil || p.AuthInfo == nil {
		return "", status.Error(codes.Unauthenticated, "no peer auth info")
	}
	tlsInfo, ok := peerTLSInfo(p)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "non-TLS peer on Session listener")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "no verified client cert")
	}
	cn := strings.TrimSpace(tlsInfo.State.VerifiedChains[0][0].Subject.CommonName)
	if cn == "" {
		return "", status.Error(codes.Unauthenticated, "client cert has empty CN")
	}
	return cn, nil
}
