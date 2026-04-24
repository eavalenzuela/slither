package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMTLSHandshakeRoundtrip wires ServerMTLSConfig against a real
// listener, has an agent-like client present a CA-signed cert, and
// asserts the TLS handshake completes. Then flips to the enrollment
// listener and proves a client WITHOUT a cert is accepted there.
func TestMTLSHandshakeRoundtrip(t *testing.T) {
	ca := testCA(t)
	srvKey, srvCert := issueServerCert(t, ca)

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{srvCert.Raw},
		PrivateKey:  srvKey,
	}

	mtls := ServerMTLSConfig(serverTLSCert, ca.Cert)
	enroll := ServerEnrollTLSConfig(serverTLSCert)

	t.Run("mtls-rejects-clientless-dial", func(t *testing.T) {
		ln := listenTLS(t, mtls)
		defer ln.Close()
		_, err := dialTLS(t, ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test dialer
			MinVersion:         tls.VersionTLS13,
		})
		if err == nil {
			t.Fatal("mTLS listener accepted a connection without a client cert")
		}
	})

	t.Run("mtls-accepts-signed-client-cert", func(t *testing.T) {
		ln := listenTLS(t, mtls)
		defer ln.Close()
		acceptAndClose(t, ln)

		clientKey, clientCert := issueClientCert(t, ca, "host-01")
		conn, err := dialTLS(t, ln.Addr().String(), &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  clientKey,
			}},
			RootCAs:    mustPool(ca.Cert),
			ServerName: "slither-test",
			MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		defer conn.Close()
		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Error("no peer certificates after handshake")
		}
	})

	t.Run("enroll-accepts-anonymous-client", func(t *testing.T) {
		ln := listenTLS(t, enroll)
		defer ln.Close()
		acceptAndClose(t, ln)
		conn, err := dialTLS(t, ln.Addr().String(), &tls.Config{
			RootCAs:    mustPool(ca.Cert),
			ServerName: "slither-test",
			MinVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		_ = conn.Close()
	})
}

func TestLoadCAPoolFromFile(t *testing.T) {
	ca := testCA(t)
	// testCA already wrote the cert to disk; reach in via os.Readdir
	// isn't needed — re-PEM from the in-memory cert.
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
	pool, err := LoadCAPoolFromFile(path)
	if err != nil {
		t.Fatalf("LoadCAPoolFromFile: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

// --- helpers shared with sign_test.go ---

// issueServerCert signs a minimal server cert (SAN=slither-test) off the
// test CA so the round-trip handshake has a valid server identity.
func issueServerCert(t *testing.T, ca *CA) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := p256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkix.Name{CommonName: "slither-test"},
		DNSNames:              []string{"slither-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("sign server cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return key, cert
}

// issueClientCert re-uses SignCSR so this test also exercises the actual
// signer path end-to-end.
func issueClientCert(t *testing.T, ca *CA, hostID string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := p256Key(t)
	csr := makeCSR(t, key, csrShape{cn: hostID})
	pemBytes, err := ca.SignCSR(csr, SignOptions{HostID: hostID, TTL: time.Hour})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode issued cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return key, cert
}

func listenTLS(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// acceptAndClose accepts exactly one connection, forces the TLS
// handshake, then closes. Runs in a goroutine so the test main can dial.
func acceptAndClose(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if tc, ok := conn.(*tls.Conn); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tc.HandshakeContext(ctx)
		}
		// Discard any client bytes until close.
		_, _ = io.Copy(io.Discard, conn)
	}()
}

func dialTLS(t *testing.T, addr string, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    cfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Unwrap via errors.As for diagnostic clarity on failures.
		var ne *net.OpError
		if errors.As(err, &ne) {
			return nil, ne
		}
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

func mustPool(cert *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p
}
