// Package grpcserv hosts the slither gRPC listeners and handlers.
//
// Phase 2 §4.1 task #34: AgentService.Enroll on the unauthenticated
// enrollment listener. Session handler lands in #37.
package grpcserv

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/mtls"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

// EnrollService implements AgentService.Enroll against a pg.Store + a
// loaded mtls.CA. It does NOT implement Session — that's wired by #37
// on the separately TLS-configured listener, and the two services
// deliberately run on different listeners so an enrollment endpoint
// can never accidentally serve Session RPCs.
type EnrollService struct {
	pb.UnimplementedAgentServiceServer

	Store *pg.Store
	CA    *mtls.CA
	Telem *telemetry.Counters
}

// NewEnrollService constructs the handler. Store + CA are required —
// the constructor treats nils as a program bug.
func NewEnrollService(store *pg.Store, ca *mtls.CA, telem *telemetry.Counters) *EnrollService {
	if store == nil {
		panic("grpcserv.NewEnrollService: nil store")
	}
	if ca == nil {
		panic("grpcserv.NewEnrollService: nil CA")
	}
	if telem == nil {
		telem = telemetry.NewCounters()
	}
	return &EnrollService{Store: store, CA: ca, Telem: telem}
}

// Enroll validates the request, atomically burns the enrollment token
// while inserting the hosts row (pg.ClaimEnrollmentToken), then signs
// the agent's CSR with the slither CA. Every outcome is audit-logged.
//
// Status codes follow the gRPC conventions:
//   - InvalidArgument: caller-side problems (empty fields, malformed CSR).
//   - FailedPrecondition: operational token problems — unknown token,
//     already used, expired. Keeps callers from retry-looping on a
//     bad token.
//   - Internal: anything the agent can't fix (DB down, signing error).
func (s *EnrollService) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	if req.GetEnrollmentToken() == "" {
		return nil, s.reject(ctx, codes.InvalidArgument, "missing enrollment_token", "empty_token", nil)
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, s.reject(ctx, codes.InvalidArgument, "missing csr_pem", "empty_csr", nil)
	}
	fp := req.GetFingerprint()
	if fp == nil {
		return nil, s.reject(ctx, codes.InvalidArgument, "missing fingerprint", "empty_fingerprint", nil)
	}

	// Pre-compute the cert serial so the hosts row can store it before
	// the cert is finalised — ClaimEnrollmentToken takes it as an
	// argument and the serial we issue here is the same one placed on
	// the cert below.
	serial, err := randomSerial128()
	if err != nil {
		return nil, s.reject(ctx, codes.Internal, "serial generation failed",
			"serial_error", map[string]any{"err": err.Error()})
	}

	result, err := s.Store.ClaimEnrollmentToken(
		ctx,
		pg.HashEnrollmentToken(req.GetEnrollmentToken()),
		pg.HostFingerprint{
			Hostname:      fp.GetHostname(),
			MachineID:     fp.GetMachineId(),
			OSName:        fp.GetOsName(),
			OSVersion:     fp.GetOsVersion(),
			KernelVersion: fp.GetKernelVersion(),
			Arch:          fp.GetArch(),
		},
		serial.Text(16),
	)
	switch {
	case errors.Is(err, pg.ErrTokenNotFound):
		return nil, s.reject(ctx, codes.FailedPrecondition,
			"enrollment token not recognised", "token_not_found", nil)
	case errors.Is(err, pg.ErrTokenUsed):
		return nil, s.reject(ctx, codes.FailedPrecondition,
			"enrollment token already used", "token_used", nil)
	case errors.Is(err, pg.ErrTokenExpired):
		return nil, s.reject(ctx, codes.FailedPrecondition,
			"enrollment token expired", "token_expired", nil)
	case err != nil:
		return nil, s.reject(ctx, codes.Internal, "enrollment claim failed",
			"claim_error", map[string]any{"err": err.Error()})
	}

	certPEM, err := s.CA.SignCSRWithSerial(req.GetCsrPem(), mtls.SignOptions{HostID: result.HostID}, serial)
	if err != nil {
		// The token has been burnt and the host row is in place — we
		// cannot un-burn cleanly without another tx. Log the situation
		// and fail Internal; an operator re-issues a new token.
		return nil, s.reject(ctx, codes.Internal, "CSR signing failed",
			"sign_error", map[string]any{
				"err":      err.Error(),
				"host_id":  result.HostID,
				"token_id": result.TokenID,
			})
	}

	s.Telem.IncEnrollSuccess()
	_ = s.Store.LogAudit(ctx, pg.AuditEntry{
		ActorType:  pg.ActorAgent,
		ActorID:    result.HostID,
		Action:     "enroll.success",
		TargetKind: "host",
		TargetID:   result.HostID,
		Detail: map[string]any{
			"token_id": result.TokenID,
			"hostname": fp.GetHostname(),
		},
	})

	return &pb.EnrollResponse{
		ClientCertPem: certPEM,
		CaCertPem:     s.CA.CertPEM(),
		HostId:        result.HostID,
	}, nil
}

// reject is the single failure path: increments the rejection counter,
// writes an audit row with the reason, and returns a typed gRPC error.
// Audit failures are logged to stderr (via pg.Store internals) but not
// surfaced — the agent needs to see the real rejection code.
func (s *EnrollService) reject(
	ctx context.Context,
	code codes.Code,
	publicMsg string,
	reason string,
	detail map[string]any,
) error {
	s.Telem.IncEnrollRejected()
	if detail == nil {
		detail = map[string]any{}
	}
	detail["reason"] = reason
	_ = s.Store.LogAudit(ctx, pg.AuditEntry{
		ActorType: pg.ActorAgent,
		Action:    "enroll.reject",
		Detail:    detail,
	})
	return status.Error(code, publicMsg)
}

// randomSerial128 generates the 128-bit positive serial we persist on
// hosts.cert_serial before signing, so a later revocation lookup keyed
// on that serial maps exactly to this host.
func randomSerial128() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		return nil, fmt.Errorf("serial is zero")
	}
	return n, nil
}
