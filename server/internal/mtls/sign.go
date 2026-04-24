package mtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SignOptions captures the per-call inputs to SignCSR. Factored into a
// struct so adding fields later (e.g. an explicit "not before" for clock
// skew) doesn't churn callers.
type SignOptions struct {
	// HostID is the Enroll-RPC-issued host identity. Becomes Subject.CN
	// on the signed cert. The CSR's CN must match exactly — any
	// discrepancy is rejected so a captured CSR cannot be re-signed for
	// a different host.
	HostID string

	// TTL is the cert validity window. 0 defaults to 365 days, matching
	// the server cert; agents re-enroll via an out-of-band operator
	// flow today (Phase 2 §10 deferred #2 will revisit).
	TTL time.Duration
}

const defaultClientTTL = 365 * 24 * time.Hour

// SignCSR validates a CSR and returns a PEM-encoded client certificate
// signed by the CA. Validation is strict by design; any soft spot here
// becomes a path to a rogue agent.
//
// Accepted:
//   - PEM-encoded CERTIFICATE REQUEST (single block).
//   - Public key type P-256 ECDSA or Ed25519 (see assertAcceptedKey).
//   - Subject.CommonName is either empty (agent's first-enroll case —
//     host_id isn't known until the server assigns one) or exactly
//     equal to opts.HostID.
//
// Rejected:
//   - RSA keys, ECDSA curves other than P-256 (weak-key guard).
//   - CSR signature mismatch.
//   - Non-empty CN that doesn't match HostID (so a CSR minted for one
//     host cannot be re-signed under another host's identity).
//   - Any SubjectAltName extension. The slither identity model is
//     "CN == host_id"; SANs open alternative identities and defeat
//     that guarantee.
//   - Any extension carried from the CSR at all: the CA decides what
//     goes on the cert, not the agent. We emit a fixed template.
func (c *CA) SignCSR(csrPEM []byte, opts SignOptions) ([]byte, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("%w: SignCSR: serial: %w", ErrCA, err)
	}
	return c.SignCSRWithSerial(csrPEM, opts, serial)
}

// SignCSRWithSerial is SignCSR but with a caller-supplied serial. Used
// by the Enroll RPC, which pre-commits the serial to hosts.cert_serial
// inside the enrollment transaction so revocation lookups keyed on
// serial number find exactly the right host row. Every other caller
// should use SignCSR for a random serial.
func (c *CA) SignCSRWithSerial(csrPEM []byte, opts SignOptions, serial *big.Int) ([]byte, error) {
	if c == nil || c.Cert == nil || c.Key == nil {
		return nil, fmt.Errorf("%w: CA not loaded", ErrCA)
	}
	if opts.HostID == "" {
		return nil, fmt.Errorf("%w: SignCSR: empty HostID", ErrCA)
	}
	if serial == nil || serial.Sign() <= 0 {
		return nil, fmt.Errorf("%w: SignCSR: non-positive serial", ErrCA)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: SignCSR: no PEM block in CSR", ErrCA)
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: SignCSR: wrong PEM type %q (want CERTIFICATE REQUEST)", ErrCA, block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: SignCSR: parse: %w", ErrCA, err)
	}
	if sigErr := csr.CheckSignature(); sigErr != nil {
		return nil, fmt.Errorf("%w: SignCSR: signature: %w", ErrCA, sigErr)
	}
	if kErr := assertAcceptedKey(csr.PublicKey); kErr != nil {
		return nil, fmt.Errorf("%w: SignCSR: %w", ErrCA, kErr)
	}
	if csr.Subject.CommonName != "" && csr.Subject.CommonName != opts.HostID {
		return nil, fmt.Errorf("%w: SignCSR: CN %q != HostID %q",
			ErrCA, csr.Subject.CommonName, opts.HostID)
	}
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, fmt.Errorf("%w: SignCSR: subjectAltName not permitted in agent CSRs", ErrCA)
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultClientTTL
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.HostID, Organization: []string{"slither"}},
		NotBefore:             now.Add(-1 * time.Minute), // small backdating for clock skew
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("%w: SignCSR: create: %w", ErrCA, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// randomSerial returns a cryptographically random 128-bit positive integer
// for use as an X.509 serial number. RFC 5280 requires ≤20-byte positive
// integers; 16 random bytes keeps us well under.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		return nil, errors.New("serial is zero")
	}
	return n, nil
}
