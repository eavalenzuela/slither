// Phase 2 §4.1 task #37: AgentService.Session on the mTLS listener.
// Authenticated by the listener's tls.RequireAndVerifyClientCert; the
// handler reads the host_id from the verified peer cert's Subject.CN
// rather than trusting the wire fields, then demuxes ClientMessage
// kinds onto the ingest bus and the Postgres host-state writer.
//
// ServerMessage send-side stays mute until #39 wires RuleSet
// distribution; the bidi stream is held open so future control pushes
// don't require an extra round trip.

package grpcserv

import (
	"context"
	"errors"
	"io"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/ingest"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// SessionService implements AgentService.Session. It embeds
// UnimplementedAgentServiceServer so it satisfies AgentServiceServer
// with Enroll left unimplemented — the two halves of AgentService run
// on different listeners (Enroll on the unauthenticated enrollment
// listener, Session on the mTLS listener) and each listener registers
// only its half.
type SessionService struct {
	pb.UnimplementedAgentServiceServer

	Store *pg.Store
	Bus   *ingest.Bus
	Telem *telemetry.Counters

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
	case *pb.ClientMessage_Ack, *pb.ClientMessage_Diag:
		// Ack and Diag are observational today. #39 wires RuleSet
		// acks; #44 (revocation/diag dashboard) consumes Diag.
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
