package dcpkey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// testCA is a self-signed root used to sign test leaf certificates.
type testCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *rsa.PrivateKey
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return testCA{cert: cert, certPEM: certPEM, key: key}
}

// newLeafCert issues a leaf certificate signed by ca, valid [notBefore,
// notAfter], returning its PEM encoding and private key.
func newLeafCert(t *testing.T, ca testCA, commonName string, notBefore, notAfter time.Time) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func newIssuerIdentity(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	ca := newTestCA(t, "heain-access Test Issuer")
	keyDER := x509.MarshalPKCS1PrivateKey(ca.key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	return ca.certPEM, keyPEM
}

func baseEvidence(targetCertPEM string, contentKey []byte) map[string]string {
	now := time.Now()
	return map[string]string{
		"target_certificate_pem": targetCertPEM,
		"content_key_hex":        hex.EncodeToString(contentKey),
		"cpl_id":                 "cpl-test-0001",
		"content_title_text":     "Test Feature Reel",
		"kdm_not_valid_before":   now.Format(time.RFC3339),
		"kdm_not_valid_after":    now.Add(48 * time.Hour).Format(time.RFC3339),
	}
}

func TestIssuer_ValidCertificate_IssuesKDM(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	leafPEM, leafKey := newLeafCert(t, trustedCA, "Screen 1 SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)

	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	contentKey := make([]byte, 16)
	for i := range contentKey {
		contentKey[i] = byte(i)
	}

	res, err := v.Issue(context.Background(), Input{
		Evidence: baseEvidence(string(leafPEM), contentKey),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Fatalf("expected Allow for a validly-chained certificate, got Deny: %s", res.Reason)
	}

	// The encrypted key must actually decrypt, with the leaf's own private
	// key, back to the original content key -- proving this is a real
	// RSA-OAEP wrap, not a placeholder.
	encB64 := res.Output["kdm_encrypted_key_b64"]
	if encB64 == "" {
		t.Fatal("expected kdm_encrypted_key_b64 in Output")
	}
	encBytes, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		t.Fatalf("decoding kdm_encrypted_key_b64: %v", err)
	}
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, leafKey, encBytes, nil)
	if err != nil {
		t.Fatalf("decrypting KDM content key with leaf private key: %v", err)
	}
	if string(decrypted) != string(contentKey) {
		t.Errorf("decrypted content key does not match original: got %x, want %x", decrypted, contentKey)
	}

	// The signature must verify against the issuer certificate's public
	// key, over the same canonical summary the verifier signed.
	sigB64 := res.Output["kdm_signature_b64"]
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding kdm_signature_b64: %v", err)
	}
	issuerCertBlock, _ := pem.Decode(issuerCertPEM)
	issuerCert, err := x509.ParseCertificate(issuerCertBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing issuer certificate: %v", err)
	}
	issuerPub := issuerCert.PublicKey.(*rsa.PublicKey)

	canonical := res.Output["kdm_cpl_id"] + "|" +
		res.Output["kdm_content_title_text"] + "|" +
		res.Output["kdm_recipient_thumbprint_sha256"] + "|" +
		res.Output["kdm_not_valid_before"] + "|" +
		res.Output["kdm_not_valid_after"] + "|" +
		res.Output["kdm_encrypted_key_b64"]
	digest := sha256.Sum256([]byte(canonical))
	if err := rsa.VerifyPSS(issuerPub, crypto.SHA256, digest[:], sigBytes, nil); err != nil {
		t.Errorf("KDM signature did not verify against issuer certificate: %v", err)
	}

	if res.Output["kdm_cpl_id"] != "cpl-test-0001" {
		t.Errorf("got kdm_cpl_id %q, want cpl-test-0001", res.Output["kdm_cpl_id"])
	}
	if res.Output["kdm_issuer_certificate_pem"] == "" {
		t.Error("expected kdm_issuer_certificate_pem in Output")
	}
}

func TestIssuer_UntrustedCertificate(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	otherCA := newTestCA(t, "Some Other Root")
	leafPEM, _ := newLeafCert(t, otherCA, "Rogue SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)

	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := v.Issue(context.Background(), Input{
		Evidence: baseEvidence(string(leafPEM), []byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Deny for a certificate signed by an untrusted CA")
	}
	if res.Reason == "" {
		t.Error("expected a non-empty Reason on denial")
	}
}

func TestIssuer_ExpiredCertificate(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	// Valid only in the past -- expired as of "now".
	leafPEM, _ := newLeafCert(t, trustedCA, "Expired SPB", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)

	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	res, err := v.Issue(context.Background(), Input{
		Evidence: baseEvidence(string(leafPEM), []byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Deny for an expired certificate")
	}
}

func TestIssuer_MissingTargetCertificate(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evidence := baseEvidence("dummy", []byte("0123456789abcdef"))
	delete(evidence, "target_certificate_pem")

	_, err = v.Issue(context.Background(), Input{Evidence: evidence})
	if err == nil {
		t.Fatal("expected an error when target_certificate_pem evidence is missing, got nil")
	}
}

func TestIssuer_MissingContentKey(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	leafPEM, _ := newLeafCert(t, trustedCA, "Screen 1 SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evidence := baseEvidence(string(leafPEM), []byte("0123456789abcdef"))
	delete(evidence, "content_key_hex")

	_, err = v.Issue(context.Background(), Input{Evidence: evidence})
	if err == nil {
		t.Fatal("expected an error when content_key_hex evidence is missing, got nil")
	}
}

func TestIssuer_MissingCPLID(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	leafPEM, _ := newLeafCert(t, trustedCA, "Screen 1 SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evidence := baseEvidence(string(leafPEM), []byte("0123456789abcdef"))
	delete(evidence, "cpl_id")

	_, err = v.Issue(context.Background(), Input{Evidence: evidence})
	if err == nil {
		t.Fatal("expected an error when cpl_id evidence is missing, got nil")
	}
}

func TestIssuer_InvalidContentKeyHex(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	leafPEM, _ := newLeafCert(t, trustedCA, "Screen 1 SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evidence := baseEvidence(string(leafPEM), []byte("0123456789abcdef"))
	evidence["content_key_hex"] = "not-hex!!"

	_, err = v.Issue(context.Background(), Input{Evidence: evidence})
	if err == nil {
		t.Fatal("expected an error for invalid content_key_hex, got nil")
	}
}

func TestIssuer_InvalidValidityWindow(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted Cinema Root")
	leafPEM, _ := newLeafCert(t, trustedCA, "Screen 1 SPB", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	v, err := New(trustedCA.certPEM, issuerCertPEM, issuerKeyPEM)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	evidence := baseEvidence(string(leafPEM), []byte("0123456789abcdef"))
	// Swap so "after" precedes "before".
	evidence["kdm_not_valid_before"], evidence["kdm_not_valid_after"] =
		evidence["kdm_not_valid_after"], evidence["kdm_not_valid_before"]

	_, err = v.Issue(context.Background(), Input{Evidence: evidence})
	if err == nil {
		t.Fatal("expected an error when kdm_not_valid_after precedes kdm_not_valid_before, got nil")
	}
}

func TestNew_InvalidCAPEM(t *testing.T) {
	issuerCertPEM, issuerKeyPEM := newIssuerIdentity(t)
	_, err := New([]byte("not a cert"), issuerCertPEM, issuerKeyPEM)
	if err == nil {
		t.Fatal("expected an error for invalid CA PEM, got nil")
	}
}
