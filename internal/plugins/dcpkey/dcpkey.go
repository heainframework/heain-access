// Package dcpkey is heain-access's optional dcp-key plugin (manifest plugins:
// dcp-key): KDM-style key issuance for DCI cinema packages -- the one
// industry-specific part of heain-access (author decision 2026-10-06), moved
// unchanged from the Stage A dcp_key verifier.
package dcpkey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Issuer implements the dcp_key Stage A verification method: the
// last of heain-access's five methods, and the only one that is not an
// ML-backed match -- key issuance for digital cinema playback is an
// inherently deterministic, cryptographic operation (there is no "model"
// for "is this the right playback device"), so this Verifier needs no
// Python sidecar at all, unlike id_card/face/fingerprint.
//
// Per the user's explicit choice, this Verifier does two things in one
// call, not just a check: it verifies the presented target playback
// device's certificate (its "SPB certificate" in DCI terms -- the
// Security Processor Block identity a real digital cinema server/
// projector presents) against a configured trust root, and, on success,
// actually issues a KDM (Key Delivery Message) -- a real public-key
// cryptographic structure that wraps a content key so only the holder of
// the target certificate's matching private key can recover it, signed by
// heain-access's own issuer key so the recipient can authenticate it came
// from a trusted source.
//
// Honest scope note: this is a real, genuinely asymmetric-cryptographic
// KDM mechanism (RSA-OAEP content-key wrapping + RSA-PSS issuer
// signature over a canonical summary of the KDM's fields), structurally
// analogous to a SMPTE 430-1 KDM, but it is NOT byte-for-byte compliant
// with the DCI/SMPTE KDM XML schema (ETM, XML digital signature, the
// specific structured-cipher-data encoding, etc.) -- that level of
// interoperability is deferred until heain-mastering's real DCP work
// needs to hand a KDM to a genuine third-party playback server. Stage A's
// job is the trust decision and the real cryptographic wrapping; exact
// wire-format compliance is a later, separate piece of work. Likewise,
// Stage A's own trust root (the CA/issuer key pair heain-access is
// configured with) is a self-signed test/demo root, not a real DCI
// trust-chain member -- mirrored by the user's own choice of "SPB
// certificate (simulated)" for this round's evidence.
type Issuer struct {
	roots       *x509.CertPool
	issuerCert  *x509.Certificate
	issuerKey   *rsa.PrivateKey
	issuerChain []byte // PEM-encoded issuer certificate, handed back in Output so a recipient can verify the KDM signature without a separate lookup.
	now         func() time.Time
}

// NewIssuer builds a Issuer from PEM-encoded inputs:
// caPEM is one or more trusted root/intermediate certificates against
// which a presented target certificate is verified; issuerCertPEM and
// issuerKeyPEM (PKCS#1 or PKCS#8 RSA) are heain-access's own signing
// identity, used to sign every KDM this Verifier issues. All three are
// required; an error is returned if any fail to parse.
func New(caPEM, issuerCertPEM, issuerKeyPEM []byte) (*Issuer, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("verifier: dcp_key: no valid certificates found in CA PEM")
	}

	issuerCertBlock, _ := pem.Decode(issuerCertPEM)
	if issuerCertBlock == nil {
		return nil, fmt.Errorf("verifier: dcp_key: issuer certificate PEM contains no block")
	}
	issuerCert, err := x509.ParseCertificate(issuerCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("verifier: dcp_key: parsing issuer certificate: %w", err)
	}

	issuerKey, err := parseRSAPrivateKeyPEM(issuerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("verifier: dcp_key: parsing issuer private key: %w", err)
	}

	return &Issuer{
		roots:       roots,
		issuerCert:  issuerCert,
		issuerKey:   issuerKey,
		issuerChain: issuerCertPEM,
		now:         time.Now,
	}, nil
}

func parseRSAPrivateKeyPEM(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("PEM contains no block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid PKCS#1 or PKCS#8 RSA private key: %w", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not an RSA key")
	}
	return rsaKey, nil
}

// Verify requires the evidence keys:
//   - "target_certificate_pem": the presented target playback device's
//     certificate (SPB certificate), PEM-encoded, used both as the trust
//     check subject and as the RSA public key the content key is wrapped
//     for.
//   - "content_key_hex": the raw content key to protect, hex-encoded
//     (supplied by the caller -- e.g. heain-mastering generates this when
//     packaging a DCP -- never generated by heain-access itself).
//   - "cpl_id": the Composition Playlist id this key unlocks.
//   - "content_title_text": a human-readable title for the KDM.
//   - "kdm_not_valid_before" / "kdm_not_valid_after": RFC3339 timestamps
//     for the KDM's own validity window. VerifyInput has no access to the
//     IssueGrantRequest's top-level ValidFrom/ValidUntil (Verify is
//     deliberately evidence-only, same as every other Stage A method), so
//     a caller wanting the KDM's window to match the AccessGrant's own
//     window must pass the same two values as evidence explicitly. This
//     duplication is a known Stage A simplification.
func (v *Issuer) Issue(ctx context.Context, in Input) (Result, error) {
	targetPEM, ok := in.Evidence["target_certificate_pem"]
	if !ok || targetPEM == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "target_certificate_pem")
	}
	contentKeyHex, ok := in.Evidence["content_key_hex"]
	if !ok || contentKeyHex == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "content_key_hex")
	}
	cplID, ok := in.Evidence["cpl_id"]
	if !ok || cplID == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "cpl_id")
	}
	contentTitle, ok := in.Evidence["content_title_text"]
	if !ok || contentTitle == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "content_title_text")
	}
	notBeforeStr, ok := in.Evidence["kdm_not_valid_before"]
	if !ok || notBeforeStr == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "kdm_not_valid_before")
	}
	notAfterStr, ok := in.Evidence["kdm_not_valid_after"]
	if !ok || notAfterStr == "" {
		return Result{}, fmt.Errorf("verifier: dcp_key evidence missing required key %q", "kdm_not_valid_after")
	}

	notBefore, err := time.Parse(time.RFC3339, notBeforeStr)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: dcp_key: kdm_not_valid_before is not RFC3339: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: dcp_key: kdm_not_valid_after is not RFC3339: %w", err)
	}
	if !notAfter.After(notBefore) {
		return Result{}, fmt.Errorf("verifier: dcp_key: kdm_not_valid_after must be after kdm_not_valid_before")
	}

	contentKey, err := hex.DecodeString(strings.TrimSpace(contentKeyHex))
	if err != nil {
		return Result{}, fmt.Errorf("verifier: dcp_key: content_key_hex is not valid hex: %w", err)
	}

	block, _ := pem.Decode([]byte(targetPEM))
	if block == nil {
		return Denied("target_certificate_pem contains no PEM block"), nil
	}
	targetCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Denied(fmt.Sprintf("target certificate could not be parsed: %v", err)), nil
	}

	if _, err := targetCert.Verify(x509.VerifyOptions{
		Roots:       v.roots,
		CurrentTime: v.nowFunc(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Denied(fmt.Sprintf("target certificate is not trusted: %v", err)), nil
	}

	targetPub, ok := targetCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return Denied("target certificate's public key is not RSA; dcp_key only supports RSA-OAEP key wrapping"), nil
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, targetPub, contentKey, nil)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: dcp_key: encrypting content key: %w", err)
	}

	thumbprint := sha256.Sum256(targetCert.Raw)
	thumbprintHex := hex.EncodeToString(thumbprint[:])
	encryptedKeyB64 := base64.StdEncoding.EncodeToString(encryptedKey)

	// Sign a canonical summary of the KDM's fields with the issuer key, so
	// the recipient can authenticate this KDM came from heain-access and
	// was not tampered with in transit.
	canonical := strings.Join([]string{
		cplID,
		contentTitle,
		thumbprintHex,
		notBefore.UTC().Format(time.RFC3339),
		notAfter.UTC().Format(time.RFC3339),
		encryptedKeyB64,
	}, "|")
	digest := sha256.Sum256([]byte(canonical))
	signature, err := rsa.SignPSS(rand.Reader, v.issuerKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: dcp_key: signing KDM: %w", err)
	}

	return Result{
		Allow: true,
		Output: map[string]string{
			"kdm_cpl_id":                      cplID,
			"kdm_content_title_text":          contentTitle,
			"kdm_recipient_thumbprint_sha256": thumbprintHex,
			"kdm_not_valid_before":            notBefore.UTC().Format(time.RFC3339),
			"kdm_not_valid_after":             notAfter.UTC().Format(time.RFC3339),
			"kdm_encrypted_key_b64":           encryptedKeyB64,
			"kdm_signature_b64":               base64.StdEncoding.EncodeToString(signature),
			"kdm_issuer_certificate_pem":      string(v.issuerChain),
		},
	}, nil
}

func (v *Issuer) nowFunc() time.Time {
	if v.now == nil {
		return time.Now()
	}
	return v.now()
}

// Input is the KDM request: the evidence keys documented on Issue.
type Input struct {
	Evidence map[string]string
}

// Result is the issuer's decision; Output carries the KDM fields.
type Result struct {
	Allow  bool
	Reason string
	Output map[string]string
}

// Denied is a clean refusal.
func Denied(reason string) Result { return Result{Reason: reason} }
