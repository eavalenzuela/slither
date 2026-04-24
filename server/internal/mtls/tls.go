package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerKeyPair loads a server TLS keypair for use on both slither
// listeners. Wraps tls.LoadX509KeyPair with our error vocabulary so
// callers can errors.Is the result.
func LoadServerKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("%w: server keypair: %w", ErrCA, err)
	}
	return cert, nil
}

// ServerMTLSConfig returns a *tls.Config for the agent Session listener:
// mTLS with client-cert required AND verified against caCert. Agents
// without a signed client cert are rejected at the TLS handshake.
func ServerMTLSConfig(serverCert tls.Certificate, caCert *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
}

// ServerEnrollTLSConfig returns a *tls.Config for the Enroll RPC
// listener: plain server-auth TLS with NO client cert requirement. The
// whole point of the enrollment endpoint is that agents don't have a
// client cert yet — they're trading a single-use token for one.
//
// This is why #33 exposes two distinct TLS configs: if we reused one
// listener with ClientAuth=VerifyClientCertIfGiven, a bug or a future
// gRPC middleware edit could accidentally expose Session-only RPCs to
// unauthenticated callers. Separate listener + separate TLS config is
// the cheapest way to make that failure mode impossible.
func ServerEnrollTLSConfig(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// LoadCAPoolFromFile builds an x509.CertPool containing exactly the CA
// cert on disk. Useful for agent-side server-verification and for tests.
func LoadCAPoolFromFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // operator-supplied
	if err != nil {
		return nil, fmt.Errorf("%w: read CA %q: %w", ErrCA, path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: no valid certificates in %q", ErrCA, path)
	}
	return pool, nil
}
