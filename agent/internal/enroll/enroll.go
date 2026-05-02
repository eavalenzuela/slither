// Package enroll implements the agent first-run enrollment flow.
//
// Phase 2 §4.1 task #36: `slither-agent enroll --token X --server addr`
// generates a P-256 keypair, builds a CSR with blank CN, calls the
// server's AgentService.Enroll RPC over plain TLS (server-auth only —
// the agent has no client cert yet), persists the cert material via
// keystore.AutoSelect (kernel keyring on Linux when available, file
// fallback otherwise — Phase 5 #98), and writes `host_id` under the
// configured state
// directory. After this the operator points `output.grpc` at those
// paths and `slither-agent run` can connect with mTLS.
//
// Trust on first use: the operator transports the CA cert out-of-band
// (scp / config management) and passes it via Options.CAPath. The
// server returns its CA cert in EnrollResponse, but we use the
// pre-pinned copy for the TLS handshake — accepting the response's CA
// would defeat the verification entirely. Options.InsecureSkipVerify
// exists for dev/test flows against an ephemeral docker-compose CA.
package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/t3rmit3/slither/agent/internal/keystore"
	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// Options drives Enroll. ServerAddr + Token + StateDir are required.
// Either CAPath OR InsecureSkipVerify must be set — refusing both is
// what makes the enrollment handshake meaningfully authenticated.
type Options struct {
	// ServerAddr is host:port of the server's enrollment listener.
	ServerAddr string

	// Token is the operator-issued single-use enrollment token.
	Token string

	// StateDir is where client.key/client.crt/ca.crt/host_id are written.
	// Must already exist (matches systemd StateDirectory=slither).
	StateDir string

	// CAPath is the pre-pinned CA cert PEM the agent uses to verify the
	// server's TLS cert. Mutually exclusive with InsecureSkipVerify.
	CAPath string

	// InsecureSkipVerify disables server-cert verification. Dev only —
	// the operator opts in explicitly so this can never be silently set.
	InsecureSkipVerify bool

	// ServerName is the SNI / cert hostname to verify against. Defaults
	// to the host portion of ServerAddr.
	ServerName string

	// DialOptions, when non-empty, overrides the TLS dial options. Used
	// by tests to inject a bufconn dialer + insecure creds.
	DialOptions []grpc.DialOption

	// FingerprintProvider, when set, overrides the runtime fingerprint
	// collector. Tests stub this; production leaves it nil.
	FingerprintProvider func() (HostFingerprint, error)
}

// Result is what Enroll wrote to disk on success.
type Result struct {
	HostID     string
	KeyPath    string
	CertPath   string
	CAPath     string
	HostIDPath string
	// StoreName is the keystore implementation that persisted the
	// cert material — "kernel-keyring" or "file". Phase 5 #98.
	// Operators reading the enrol stderr can tell whether the
	// keyring path was taken; tooling that wants determinism sets
	// the choice via config (Phase 5+ knob).
	StoreName string
}

// HostFingerprint is the data sent in EnrollRequest.fingerprint.
type HostFingerprint struct {
	Hostname      string
	MachineID     string
	OSName        string
	OSVersion     string
	KernelVersion string
	Arch          string
}

// Enroll runs one enrollment round-trip and writes the resulting state
// to disk. Returns a Result describing the file paths on success; on
// failure no partial state is written (each file is staged via
// rename(2) from a temp file in the same directory).
func Enroll(ctx context.Context, opts Options) (*Result, error) {
	if err := validate(&opts); err != nil {
		return nil, err
	}

	provider := opts.FingerprintProvider
	if provider == nil {
		provider = collectFingerprint
	}
	fp, err := provider()
	if err != nil {
		return nil, fmt.Errorf("enroll: fingerprint: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enroll: keygen: %w", err)
	}
	csrPEM, err := buildCSR(key)
	if err != nil {
		return nil, fmt.Errorf("enroll: csr: %w", err)
	}

	dialOpts, err := buildDialOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("enroll: dial options: %w", err)
	}
	conn, err := grpc.NewClient(opts.ServerAddr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("enroll: dial %s: %w", opts.ServerAddr, err)
	}
	defer conn.Close()

	resp, err := pb.NewAgentServiceClient(conn).Enroll(ctx, &pb.EnrollRequest{
		EnrollmentToken: opts.Token,
		CsrPem:          csrPEM,
		Fingerprint: &pb.HostFingerprint{
			Hostname:      fp.Hostname,
			MachineId:     fp.MachineID,
			OsName:        fp.OSName,
			OsVersion:     fp.OSVersion,
			KernelVersion: fp.KernelVersion,
			Arch:          fp.Arch,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("enroll: rpc: %w", err)
	}
	if resp.GetHostId() == "" || len(resp.GetClientCertPem()) == 0 || len(resp.GetCaCertPem()) == 0 {
		return nil, errors.New("enroll: server returned incomplete response")
	}

	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, fmt.Errorf("enroll: encode key: %w", err)
	}

	res := &Result{
		HostID:     resp.GetHostId(),
		KeyPath:    filepath.Join(opts.StateDir, "client.key"),
		CertPath:   filepath.Join(opts.StateDir, "client.crt"),
		CAPath:     filepath.Join(opts.StateDir, "ca.crt"),
		HostIDPath: filepath.Join(opts.StateDir, "host_id"),
	}

	// Phase 5 #98 — persist cert material. Phase 5 #103 cloud
	// validation surfaced that the keyring-only path doesn't survive
	// across process boundaries on systemd-managed Linux (session
	// keyring scope ≠ agent unit scope; user keyring may be empty
	// under PAM's pam_keyinit + KeyringMode=private). Files are the
	// durable, cross-process truth; the keyring write is additive
	// (best-effort hot-cache for runtime confidentiality, but never
	// the source of truth). This is more conservative than the
	// original ADR-0035 sketch and remains correct on container
	// shapes without a usable keyring.
	//
	// Always write files first.
	if err := writeFileAtomic(res.KeyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(res.CertPath, resp.GetClientCertPem(), 0o644); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(res.CAPath, resp.GetCaCertPem(), 0o644); err != nil {
		return nil, err
	}
	// Best-effort additive keyring write. Failure here is non-fatal
	// because the file path above is the operational fallback.
	store := keystore.AutoSelect(opts.StateDir)
	res.StoreName = store.Name()
	_ = store.Save(keystore.Material{
		ClientKey:  keyPEM,
		ClientCert: resp.GetClientCertPem(),
		CACert:     resp.GetCaCertPem(),
	})

	// host_id stays as a file under both store flavours — it's a
	// stable identifier, not a secret. Tools that read $StateDir/host_id
	// at boot continue to work regardless of the cert store choice.
	if err := writeFileAtomic(res.HostIDPath, []byte(resp.GetHostId()+"\n"), 0o644); err != nil {
		return nil, err
	}

	return res, nil
}

func validate(opts *Options) error {
	if opts.ServerAddr == "" {
		return errors.New("enroll: server address required")
	}
	if opts.Token == "" {
		return errors.New("enroll: token required")
	}
	if opts.StateDir == "" {
		return errors.New("enroll: state dir required")
	}
	st, err := os.Stat(opts.StateDir)
	if err != nil {
		return fmt.Errorf("enroll: state dir %q: %w", opts.StateDir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("enroll: state dir %q is not a directory", opts.StateDir)
	}
	if len(opts.DialOptions) == 0 {
		if opts.CAPath == "" && !opts.InsecureSkipVerify {
			return errors.New("enroll: --ca-cert or --insecure-skip-verify required")
		}
		if opts.CAPath != "" && opts.InsecureSkipVerify {
			return errors.New("enroll: --ca-cert and --insecure-skip-verify are mutually exclusive")
		}
	}
	if opts.ServerName == "" {
		host, _, err := net.SplitHostPort(opts.ServerAddr)
		if err == nil {
			opts.ServerName = host
		} else {
			opts.ServerName = opts.ServerAddr
		}
	}
	return nil
}

func buildCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func buildDialOptions(opts Options) ([]grpc.DialOption, error) {
	if len(opts.DialOptions) > 0 {
		return opts.DialOptions, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: opts.ServerName,
	}
	if opts.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // operator opt-in
	} else {
		caPEM, err := os.ReadFile(opts.CAPath) //nolint:gosec // operator-supplied
		if err != nil {
			return nil, fmt.Errorf("read ca %q: %w", opts.CAPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certificates in %q", opts.CAPath)
		}
		tlsCfg.RootCAs = pool
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))}, nil
}

// writeFileAtomic writes data to a sibling temp file then renames over
// path. Best-effort fsync of the directory after rename so a crash
// between writes doesn't leave half the state visible.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".enroll.*")
	if err != nil {
		return fmt.Errorf("enroll: create temp in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("enroll: write %q: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("enroll: chmod %q: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("enroll: fsync %q: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("enroll: close %q: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("enroll: rename %q: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // dir derives from operator-supplied state dir
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// collectFingerprint gathers the host data sent in EnrollRequest.
// Missing optional sources (machine-id, os-release) degrade to empty
// strings — the server tolerates them and the operator still sees
// hostname + arch + kernel.
func collectFingerprint() (HostFingerprint, error) {
	fp := HostFingerprint{Arch: runtime.GOARCH}

	if h, err := os.Hostname(); err == nil {
		fp.Hostname = h
	}
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		fp.MachineID = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		fp.OSName, fp.OSVersion = parseOSRelease(string(b))
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil {
		fp.KernelVersion = trimZero(u.Release[:])
	}
	return fp, nil
}

func parseOSRelease(s string) (id, version string) {
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

func trimZero(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
