package enroll

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/t3rmit3/slither/agent/internal/keystore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// stubEnroll is a minimal AgentService.Enroll implementation. Each test
// configures it via the response or the err field; the captured request
// is exposed via the lastRequest method for assertions.
type stubEnroll struct {
	pb.UnimplementedAgentServiceServer

	mu      sync.Mutex
	lastReq *pb.EnrollRequest

	respFn func(*pb.EnrollRequest) (*pb.EnrollResponse, error)
}

func (s *stubEnroll) Enroll(_ context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	s.mu.Lock()
	s.lastReq = req
	s.mu.Unlock()
	return s.respFn(req)
}

func (s *stubEnroll) lastRequest() *pb.EnrollRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReq
}

func spawnStub(t *testing.T, stub *stubEnroll) (opts Options, stop func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterAgentServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()
	dial := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	return Options{
			ServerAddr:  "passthrough:bufnet",
			DialOptions: dial,
		}, func() {
			srv.Stop()
		}
}

// fakeCAResponse mints a one-shot self-signed CA + a client cert for the
// CSR in req. Only used so the stub returns plausibly-shaped PEM data;
// the test doesn't validate the cert chain (the server-side enroll
// integration test already covers that).
func fakeCAResponse(t *testing.T, req *pb.EnrollRequest, hostID string) *pb.EnrollResponse {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	block, _ := pem.Decode(req.GetCsrPem())
	if block == nil {
		t.Fatal("decode csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, cert, caTmpl, csr.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	return &pb.EnrollResponse{
		HostId:        hostID,
		ClientCertPem: clientPEM,
		CaCertPem:     caPEM,
	}
}

func newOpts(t *testing.T, base Options) Options {
	t.Helper()
	base.Token = "tok"
	base.StateDir = t.TempDir()
	base.FingerprintProvider = func() (HostFingerprint, error) {
		return HostFingerprint{
			Hostname:      "agent-test",
			MachineID:     "mid-test",
			OSName:        "debian",
			OSVersion:     "13",
			KernelVersion: "6.12.0",
			Arch:          "amd64",
		}, nil
	}
	return base
}

func TestEnroll_HappyPathWritesAllFiles(t *testing.T) {
	stub := &stubEnroll{}
	stub.respFn = func(req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
		return fakeCAResponse(t, req, "host-abc"), nil
	}
	base, stop := spawnStub(t, stub)
	defer stop()
	opts := newOpts(t, base)

	res, err := Enroll(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.HostID != "host-abc" {
		t.Errorf("HostID = %q", res.HostID)
	}

	// host_id is always a file regardless of keystore choice.
	if fi, statErr := os.Stat(res.HostIDPath); statErr != nil {
		t.Fatalf("host_id missing: %v", statErr)
	} else if fi.Size() == 0 {
		t.Errorf("host_id empty")
	}

	// Cert material lands in whichever keystore AutoSelect picked
	// for this host (kernel-keyring on a normal Linux runner; file
	// in a container without /proc/keys). Phase 5 #98 — assert via
	// keystore.AutoSelect.Load() so the test is store-agnostic.
	store := keystore.AutoSelect(opts.StateDir)
	mat, err := store.Load()
	if err != nil {
		t.Fatalf("keystore.Load: %v (chose %s)", err, store.Name())
	}
	if len(mat.ClientKey) == 0 {
		t.Error("ClientKey empty after enroll")
	}
	if len(mat.ClientCert) == 0 {
		t.Error("ClientCert empty after enroll")
	}
	if len(mat.CACert) == 0 {
		t.Error("CACert empty after enroll")
	}
	if res.StoreName != store.Name() {
		t.Errorf("Result.StoreName = %q, want %q", res.StoreName, store.Name())
	}

	// File-store-specific check: when AutoSelect picked file, the
	// client.key on disk is mode 0600. Skip on keyring (no file
	// to stat).
	if store.Name() == "file" {
		st, err := os.Stat(res.KeyPath)
		if err != nil {
			t.Fatalf("client.key missing on file store: %v", err)
		}
		if mode := st.Mode().Perm(); mode != 0o600 {
			t.Errorf("key perm = %o, want 0600", mode)
		}
	}

	// host_id file content matches HostID.
	idBytes, err := os.ReadFile(res.HostIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(idBytes)); got != "host-abc" {
		t.Errorf("host_id file contents = %q", got)
	}

	// Request fingerprint propagated.
	req := stub.lastRequest()
	if req.GetFingerprint().GetHostname() != "agent-test" {
		t.Errorf("hostname = %q", req.GetFingerprint().GetHostname())
	}
	if req.GetFingerprint().GetArch() != "amd64" {
		t.Errorf("arch = %q", req.GetFingerprint().GetArch())
	}

	// CSR is parseable, P-256, blank CN.
	block, _ := pem.Decode(req.GetCsrPem())
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("CSR PEM missing or wrong type")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("CSR parse: %v", err)
	}
	if csr.Subject.CommonName != "" {
		t.Errorf("CSR CN = %q, want blank", csr.Subject.CommonName)
	}
	if pk, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Errorf("CSR not P-256 ecdsa: %T", csr.PublicKey)
	}
}

func TestEnroll_ServerErrorWritesNothing(t *testing.T) {
	stub := &stubEnroll{}
	stub.respFn = func(*pb.EnrollRequest) (*pb.EnrollResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "token_used")
	}
	base, stop := spawnStub(t, stub)
	defer stop()
	opts := newOpts(t, base)

	_, err := Enroll(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error")
	}
	st, ok := status.FromError(errors.Unwrap(err))
	if !ok {
		t.Fatalf("not a gRPC status: %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v", st.Code())
	}

	for _, name := range []string{"client.key", "client.crt", "ca.crt", "host_id"} {
		if _, err := os.Stat(filepath.Join(opts.StateDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists after failure", name)
		}
	}
}

func TestEnroll_RejectsBadOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"missing token", Options{ServerAddr: "x", StateDir: t.TempDir(), InsecureSkipVerify: true}},
		{"missing server", Options{Token: "t", StateDir: t.TempDir(), InsecureSkipVerify: true}},
		{"missing state dir", Options{Token: "t", ServerAddr: "x", InsecureSkipVerify: true}},
		{"no trust mode", Options{Token: "t", ServerAddr: "x", StateDir: t.TempDir()}},
		{"both trust modes", Options{Token: "t", ServerAddr: "x", StateDir: t.TempDir(),
			CAPath: "/dev/null", InsecureSkipVerify: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Enroll(context.Background(), c.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEnroll_IncompleteResponse(t *testing.T) {
	stub := &stubEnroll{}
	stub.respFn = func(*pb.EnrollRequest) (*pb.EnrollResponse, error) {
		return &pb.EnrollResponse{HostId: "x"}, nil // missing certs
	}
	base, stop := spawnStub(t, stub)
	defer stop()
	opts := newOpts(t, base)
	if _, err := Enroll(context.Background(), opts); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseOSRelease(t *testing.T) {
	in := `NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="13"
`
	id, ver := parseOSRelease(in)
	if id != "debian" || ver != "13" {
		t.Errorf("parseOSRelease = %q,%q", id, ver)
	}
}
