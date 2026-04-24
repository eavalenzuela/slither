// Package mtls owns the slither CA: loading the CA key/cert from disk,
// issuing per-host client certs from CSRs, and building TLS configs for
// the listeners in package grpcserv.
//
// Phase 2 §4.1 task #33: CA load + SignCSR + TLS config helpers.
// Enroll RPC (#34) and Session handler (#37) consume this package as-is.
package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ErrCA is the sentinel wrapping every user-visible CA/signer error.
var ErrCA = errors.New("mtls")

// CA is the loaded slither CA: its certificate plus private key used to
// sign per-host client certs issued from Enroll RPC CSRs.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer

	// certPEM caches the PEM-encoded CA cert so the Enroll RPC can send
	// the chain back to agents without re-serialising on every call.
	certPEM []byte
}

// LoadCA reads a PEM-encoded CA certificate and private key from disk and
// verifies the cert is actually a CA (basicConstraints.CA: TRUE). The key
// type is constrained to the same set we accept in CSRs — P-256 ECDSA or
// Ed25519 — because a stronger bar on the signing key costs nothing and
// rules out old RSA keys lingering from a previous PKI.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // operator-supplied
	if err != nil {
		return nil, fmt.Errorf("%w: read cert %q: %w", ErrCA, certPath, err)
	}
	cert, err := parseSingleCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse cert %q: %w", ErrCA, certPath, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%w: %q is not a CA certificate", ErrCA, certPath)
	}

	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // operator-supplied
	if err != nil {
		return nil, fmt.Errorf("%w: read key %q: %w", ErrCA, keyPath, err)
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse key %q: %w", ErrCA, keyPath, err)
	}
	if err := assertAcceptedKey(key.Public()); err != nil {
		return nil, fmt.Errorf("%w: CA key: %w", ErrCA, err)
	}
	return &CA{Cert: cert, Key: key, certPEM: certPEM}, nil
}

// CertPEM returns the CA certificate in PEM form. Safe for concurrent use;
// callers must not mutate the returned slice.
func (c *CA) CertPEM() []byte { return c.certPEM }

// parseSingleCert extracts one X.509 certificate from a PEM blob. Multiple
// CERTIFICATE blocks (chains) are rejected — the slither CA is a single
// self-signed root in Phase 2; a chain implies an intermediate hierarchy we
// don't support yet.
func parseSingleCert(pemBytes []byte) (*x509.Certificate, error) {
	var cert *x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert != nil {
			return nil, errors.New("multiple CERTIFICATE blocks; slither expects a single self-signed CA")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		cert = c
	}
	if cert == nil {
		return nil, errors.New("no CERTIFICATE block found")
	}
	return cert, nil
}

// parsePrivateKey accepts PKCS#8 (the openssl default for EC + Ed25519) and
// the legacy SEC1 EC / PKCS#1 forms for compatibility with older key files.
// Returns the key as crypto.Signer so the signer doesn't care about the
// concrete type.
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key type %T is not a crypto.Signer", k)
		}
		return signer, nil
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return nil, errors.New("RSA keys are not accepted; use P-256 or Ed25519")
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// assertAcceptedKey enforces the same key-type constraint in two places:
// (1) the loaded CA key and (2) every CSR public key. Accepted: P-256
// ECDSA, Ed25519. RSA is rejected because every sane modern PKI default
// emits EC and because RSA-signed handshakes are ~10x slower for the gRPC
// Session TLS setup on the agent side.
func assertAcceptedKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("ECDSA curve %q rejected; require P-256", k.Curve.Params().Name)
		}
		return nil
	case ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("unsupported public-key type %T; require P-256 ECDSA or Ed25519", pub)
	}
}
