package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA returns a throwaway P-256 CA written to a tempdir + loaded via
// LoadCA, mirroring the real flow. Keeps the test free of openssl.
func testCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          bigOne(),
		Subject:               pkix.Name{CommonName: "slither-ca-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)

	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca
}

// makeCSR returns a PEM-encoded CSR signed by key with the given subject
// CN. SAN helpers let tests seed an invalid CSR on demand.
type csrShape struct {
	cn       string
	dnsNames []string
	ipAddrs  []net.IP
}

func makeCSR(t *testing.T, key crypto.Signer, shape csrShape) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: shape.cn},
		DNSNames:    shape.dnsNames,
		IPAddresses: shape.ipAddrs,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("p256: %v", err)
	}
	return k
}

func TestSignCSR_HappyPathP256(t *testing.T) {
	ca := testCA(t)
	key := p256Key(t)
	csr := makeCSR(t, key, csrShape{cn: "host-01"})

	certPEM, err := ca.SignCSR(csr, SignOptions{HostID: "host-01", TTL: time.Hour})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert := parseCertPEM(t, certPEM)
	if cert.Subject.CommonName != "host-01" {
		t.Errorf("CN = %q, want host-01", cert.Subject.CommonName)
	}
	if got := cert.Issuer.CommonName; got != ca.Cert.Subject.CommonName {
		t.Errorf("Issuer CN = %q, want %q", got, ca.Cert.Subject.CommonName)
	}
	if !containsEKU(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Errorf("missing clientAuth EKU: %v", cert.ExtKeyUsage)
	}
	if cert.IsCA {
		t.Error("signed client cert has CA=true")
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("cert signature does not verify against CA: %v", err)
	}
}

func TestSignCSR_HappyPathEd25519(t *testing.T) {
	ca := testCA(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	csr := makeCSR(t, priv, csrShape{cn: "host-ed"})
	if _, err := ca.SignCSR(csr, SignOptions{HostID: "host-ed"}); err != nil {
		t.Fatalf("SignCSR ed25519: %v", err)
	}
}

func TestSignCSR_RejectsRSAKey(t *testing.T) {
	ca := testCA(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	csr := makeCSR(t, rsaKey, csrShape{cn: "host-rsa"})
	_, err = ca.SignCSR(csr, SignOptions{HostID: "host-rsa"})
	if err == nil {
		t.Fatal("RSA CSR should have been rejected")
	}
	if !strings.Contains(err.Error(), "unsupported public-key type") {
		t.Errorf("error should mention key type: %v", err)
	}
}

func TestSignCSR_RejectsP384(t *testing.T) {
	ca := testCA(t)
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384: %v", err)
	}
	csr := makeCSR(t, k, csrShape{cn: "host-p384"})
	_, err = ca.SignCSR(csr, SignOptions{HostID: "host-p384"})
	if err == nil {
		t.Fatal("P-384 CSR should have been rejected")
	}
	if !strings.Contains(err.Error(), "P-256") {
		t.Errorf("error should mention P-256 requirement: %v", err)
	}
}

func TestSignCSR_RejectsWrongCN(t *testing.T) {
	ca := testCA(t)
	csr := makeCSR(t, p256Key(t), csrShape{cn: "host-A"})
	_, err := ca.SignCSR(csr, SignOptions{HostID: "host-B"})
	if err == nil {
		t.Fatal("CN != HostID should have been rejected")
	}
	if !strings.Contains(err.Error(), "!=") {
		t.Errorf("error should flag CN mismatch: %v", err)
	}
}

func TestSignCSR_RejectsDNSSAN(t *testing.T) {
	ca := testCA(t)
	csr := makeCSR(t, p256Key(t), csrShape{cn: "host-01", dnsNames: []string{"rogue.example"}})
	_, err := ca.SignCSR(csr, SignOptions{HostID: "host-01"})
	if err == nil {
		t.Fatal("CSR with DNS SAN should have been rejected")
	}
	if !strings.Contains(err.Error(), "subjectAltName") {
		t.Errorf("error should flag SAN rejection: %v", err)
	}
}

func TestSignCSR_RejectsIPSAN(t *testing.T) {
	ca := testCA(t)
	csr := makeCSR(t, p256Key(t), csrShape{cn: "host-01", ipAddrs: []net.IP{net.IPv4(10, 0, 0, 1)}})
	_, err := ca.SignCSR(csr, SignOptions{HostID: "host-01"})
	if err == nil {
		t.Fatal("CSR with IP SAN should have been rejected")
	}
}

func TestSignCSR_RejectsEmptyHostID(t *testing.T) {
	ca := testCA(t)
	csr := makeCSR(t, p256Key(t), csrShape{cn: ""})
	_, err := ca.SignCSR(csr, SignOptions{HostID: ""})
	if err == nil {
		t.Fatal("empty HostID should have been rejected")
	}
}

func TestSignCSR_RejectsTamperedCSR(t *testing.T) {
	ca := testCA(t)
	csr := makeCSR(t, p256Key(t), csrShape{cn: "host-01"})
	// Flip a byte near the signature tail.
	block, _ := pem.Decode(csr)
	if block == nil {
		t.Fatal("decode")
	}
	der := block.Bytes
	der[len(der)-5] ^= 0xff
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	_, err := ca.SignCSR(tampered, SignOptions{HostID: "host-01"})
	if err == nil {
		t.Fatal("tampered CSR signature should have been rejected")
	}
}

func TestLoadCA_RejectsNonCA(t *testing.T) {
	// A cert with IsCA=false written in place of a real CA — should
	// fail LoadCA's basicConstraints check.
	dir := t.TempDir()
	key := p256Key(t)
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "not-a-ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)

	if _, err := LoadCA(certPath, keyPath); err == nil {
		t.Fatal("LoadCA accepted non-CA cert")
	}
}

// --- small helpers ---

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func parseCertPEM(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(p)
	if block == nil {
		t.Fatal("parseCertPEM: no block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func containsEKU(xs []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func bigOne() *big.Int { return big.NewInt(1) }
