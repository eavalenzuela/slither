//go:build integration

// End-to-end test for AgentService.Enroll using a real Postgres
// (testcontainers-go) and an in-process gRPC server + client. Verifies:
//   - Valid token → cert issued + host row + token burnt + audit row.
//   - Reused token → FailedPrecondition (with token_used reason).
//   - Expired token → FailedPrecondition (with token_expired reason).
//   - Missing token → FailedPrecondition (token_not_found).

package grpcserv_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/testcontainers/testcontainers-go"
	pgcontainer "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
	"github.com/t3rmit3/slither/server/internal/grpcserv"
	"github.com/t3rmit3/slither/server/internal/mtls"
	"github.com/t3rmit3/slither/server/internal/store/pg"
	"github.com/t3rmit3/slither/server/internal/telemetry"
)

func TestEnroll_HappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupEnv(ctx, t)
	defer env.cleanup()

	userID := env.seedUser(ctx, t, "admin", pg.RoleAdmin)
	plaintext := "token-happy"
	_, err := env.store.InsertEnrollmentToken(
		ctx, pg.HashEnrollmentToken(plaintext),
		userID, "agent-01", time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	csrPEM, _ := newCSR(t)
	resp, err := env.client.Enroll(ctx, &pb.EnrollRequest{
		EnrollmentToken: plaintext,
		CsrPem:          csrPEM,
		Fingerprint: &pb.HostFingerprint{
			Hostname:      "agent-01",
			MachineId:     "mid-01",
			OsName:        "debian",
			OsVersion:     "13",
			KernelVersion: "6.12.74",
			Arch:          "amd64",
		},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.GetHostId() == "" {
		t.Fatal("empty host_id in response")
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatal("no client cert returned")
	}
	if len(resp.GetCaCertPem()) == 0 {
		t.Fatal("no CA cert returned")
	}

	// The issued cert's Subject CN must equal host_id.
	block, _ := pem.Decode(resp.GetClientCertPem())
	if block == nil {
		t.Fatal("cannot decode client cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	if cert.Subject.CommonName != resp.GetHostId() {
		t.Errorf("Subject CN = %q, want %q", cert.Subject.CommonName, resp.GetHostId())
	}

	// Host row exists with matching cert_serial.
	var serial, hostname string
	if err := env.store.Pool().QueryRow(ctx,
		"SELECT cert_serial, hostname FROM hosts WHERE id = $1",
		resp.GetHostId()).Scan(&serial, &hostname); err != nil {
		t.Fatalf("select host row: %v", err)
	}
	if cert.SerialNumber.Text(16) != serial {
		t.Errorf("cert serial %q vs hosts.cert_serial %q", cert.SerialNumber.Text(16), serial)
	}
	if hostname != "agent-01" {
		t.Errorf("hostname = %q", hostname)
	}

	// Token is burnt.
	var usedAt *time.Time
	if err := env.store.Pool().QueryRow(ctx,
		"SELECT used_at FROM enrollment_tokens WHERE token_hash = $1",
		pg.HashEnrollmentToken(plaintext)).Scan(&usedAt); err != nil {
		t.Fatalf("select token: %v", err)
	}
	if usedAt == nil {
		t.Fatal("token.used_at still null after Enroll")
	}

	// Audit row written.
	var auditAction string
	if err := env.store.Pool().QueryRow(ctx,
		"SELECT action FROM audit_log WHERE actor_type = 'agent' ORDER BY created_at DESC LIMIT 1").
		Scan(&auditAction); err != nil {
		t.Fatalf("select audit: %v", err)
	}
	if auditAction != "enroll.success" {
		t.Errorf("audit action = %q", auditAction)
	}
}

func TestEnroll_ReusedToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupEnv(ctx, t)
	defer env.cleanup()

	userID := env.seedUser(ctx, t, "admin", pg.RoleAdmin)
	plaintext := "token-reused"
	_, err := env.store.InsertEnrollmentToken(
		ctx, pg.HashEnrollmentToken(plaintext),
		userID, "", time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}

	req := enrollRequest(t, plaintext, "agent-re")
	if _, err := env.client.Enroll(ctx, req); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	// Second attempt with same token.
	_, err = env.client.Enroll(ctx, enrollRequest(t, plaintext, "agent-re-2"))
	if err == nil {
		t.Fatal("second Enroll with same token should have failed")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition; msg=%q", st.Code(), st.Message())
	}
}

func TestEnroll_ExpiredToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupEnv(ctx, t)
	defer env.cleanup()

	userID := env.seedUser(ctx, t, "admin", pg.RoleAdmin)
	plaintext := "token-expired"
	_, err := env.store.InsertEnrollmentToken(
		ctx, pg.HashEnrollmentToken(plaintext),
		userID, "", time.Now().Add(-time.Minute), // already expired
	)
	if err != nil {
		t.Fatalf("InsertEnrollmentToken: %v", err)
	}
	_, err = env.client.Enroll(ctx, enrollRequest(t, plaintext, "agent-expired"))
	if err == nil {
		t.Fatal("expired-token Enroll should have failed")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", st.Code())
	}
}

func TestEnroll_UnknownToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := setupEnv(ctx, t)
	defer env.cleanup()

	_, err := env.client.Enroll(ctx, enrollRequest(t, "never-minted", "agent-x"))
	if err == nil {
		t.Fatal("unknown-token Enroll should have failed")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", st.Code())
	}
}

// --- test harness ---

type testEnv struct {
	store   *pg.Store
	client  pb.AgentServiceClient
	cleanup func()
}

func setupEnv(ctx context.Context, t *testing.T) *testEnv {
	t.Helper()
	requireDocker(t)

	dsn, stopPG := startPostgres(ctx, t)
	if err := pg.Migrate(ctx, dsn); err != nil {
		stopPG()
		t.Fatalf("Migrate: %v", err)
	}
	store, err := pg.Open(ctx, dsn)
	if err != nil {
		stopPG()
		t.Fatalf("pg.Open: %v", err)
	}

	ca := newTestCA(t)
	svc := grpcserv.NewEnrollService(store, ca, telemetry.NewCounters())

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		store.Close()
		stopPG()
		t.Fatalf("grpc.NewClient: %v", err)
	}

	return &testEnv{
		store:  store,
		client: pb.NewAgentServiceClient(conn),
		cleanup: func() {
			_ = conn.Close()
			srv.Stop()
			store.Close()
			stopPG()
		},
	}
}

func (e *testEnv) seedUser(ctx context.Context, t *testing.T, username string, role pg.UserRole) string {
	t.Helper()
	// argon2id hash placeholder; Phase 2 #41 replaces with real auth.
	id, err := e.store.InsertUser(ctx, username, "$argon2id$placeholder", role)
	if err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	return id
}

func enrollRequest(t *testing.T, token, hostname string) *pb.EnrollRequest {
	t.Helper()
	csrPEM, _ := newCSR(t)
	return &pb.EnrollRequest{
		EnrollmentToken: token,
		CsrPem:          csrPEM,
		Fingerprint: &pb.HostFingerprint{
			Hostname:      hostname,
			MachineId:     "mid-" + hostname,
			OsName:        "debian",
			OsVersion:     "13",
			KernelVersion: "6.12",
			Arch:          "amd64",
		},
	}
}

// newCSR returns a fresh P-256 CSR with blank CN (the Enroll RPC fills
// it from the server-assigned host_id).
func newCSR(t *testing.T) (pemBytes []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

// newTestCA mirrors the ca.go happy-path: generate a P-256 CA, write
// it to a tempdir, load via LoadCA so the full code path is exercised.
func newTestCA(t *testing.T) *mtls.CA {
	t.Helper()
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkix.Name{CommonName: "slither-ca-it"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	ca, err := mtls.LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca
}

// --- small helpers duplicated from the mtls package because build tags
// keep integration test files isolated from sibling-package test code. ---

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("DOCKER_HOST") != "" {
		return
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skipf("docker not reachable: %v", err)
	}
	c, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
	if err != nil {
		t.Skipf("docker socket dial: %v", err)
	}
	_ = c.Close()
}

func startPostgres(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()
	container, err := pgcontainer.Run(ctx,
		"postgres:16-alpine",
		pgcontainer.WithDatabase("slither_test"),
		pgcontainer.WithUsername("slither"),
		pgcontainer.WithPassword("slither"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg container: %v", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		t.Fatalf("conn str: %v", err)
	}
	return dsn, func() {
		termCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(termCtx); err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("container terminate: %v", err)
		}
	}
}

// bigOne wraps big.NewInt(1). The name keeps the test helpers compact.
func bigOne() *big.Int { return big.NewInt(1) }
