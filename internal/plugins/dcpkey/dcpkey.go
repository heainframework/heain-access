// Package dcpkey is heain-access's optional dcp-key plugin (manifest
// plugins: dcp-key): it issues Key Delivery Messages for encrypted digital
// cinema packages -- the one industry-specific part of heain-access.
//
// Step 4j (author decision 2026-10-06): the KDM is a real SMPTE ST 430-1
// KDM in the ST 430-3 Extra-Theater Message envelope, so a real cinema
// server can open it:
//
//   - AuthenticatedPublic: MessageId, MessageType (kdm-key-type), IssueDate,
//     Signer, and KDMRequiredExtensions -- Recipient (issuer/serial and
//     subject of the target certificate), CompositionPlaylistId,
//     ContentAuthenticator (optional), ContentTitleText, the key validity
//     window, AuthorizedDeviceInfo and the KeyIdList (typed key ids);
//   - AuthenticatedPrivate: one enc:EncryptedKey per content key, the ST
//     430-1 138-byte block (structure id, signer thumbprint, CPL id, key
//     type, key id, validity window, key) under RSA-OAEP (SHA-1, MGF1) to
//     the target certificate's public key;
//   - an XML Signature (RSA-SHA256) over both, with heain-access's issuer
//     chain in KeyInfo.
//
// The target certificate (the cinema server's security manager) must chain
// to a configured trust root. Content keys are never generated or stored
// here: the caller (heain-mastering) holds them sealed and passes them for
// one issuance. Only the callers configured with -dcp-key-callers may ask
// (the plugin signs whatever keys it is given).
package dcpkey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	x "github.com/heainframework/heain-access/internal/xmldsig"
)

// ST 430-1 / 430-3 identifiers.
const (
	NSETM          = "http://www.smpte-ra.org/schemas/430-3/2006/ETM"
	NSKDM          = "http://www.smpte-ra.org/schemas/430-1/2006/KDM"
	MessageTypeKDM = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type"
	// AssumeTrust is the "assume trust" thumbprint (SHA-1 of the empty
	// string) used in Modified Transitional 1 device lists.
	AssumeTrust = "2jmj7l5rSw0yVb/vlWAYkK/YBwk="
	timeLayout  = "2006-01-02T15:04:05+00:00"
)

var structureID = []byte{0xf1, 0xdc, 0x12, 0x44, 0x60, 0x16, 0x9a, 0x0e, 0x85, 0xbc, 0x30, 0x06, 0x42, 0xf8, 0x66, 0xab}

var keyTypes = map[string]bool{"MDIK": true, "MDAK": true, "MDSK": true, "FMIK": true, "FMAK": true, "MDEK": true}

// Issuer issues KDMs signed by heain-access's issuer identity.
type Issuer struct {
	roots  *x509.CertPool
	signer *x509.Certificate
	sig    *x.Signer
	now    func() time.Time
}

// New builds an Issuer from PEM: caPEM holds the trust root(s) of target
// certificates; issuerCertPEM is the issuer chain, leaf first (a single
// certificate is accepted); issuerKeyPEM its RSA key (PKCS#1 or PKCS#8).
func New(caPEM, issuerCertPEM, issuerKeyPEM []byte) (*Issuer, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("dcp-key: no valid certificate in the CA PEM")
	}
	s, err := x.LoadSigner(issuerCertPEM, issuerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("dcp-key: issuer: %w", err)
	}
	return &Issuer{roots: roots, signer: s.Chain[0], sig: s, now: time.Now}, nil
}

// Key is one content key to deliver.
type Key struct {
	Type string `json:"type"`    // MDIK (picture), MDAK (sound), MDSK (subtitle), ...
	ID   string `json:"id"`      // the key id (UUID) written in the track file
	Hex  string `json:"key_hex"` // 16 bytes AES-128
}

// Request is one KDM issuance.
type Request struct {
	TargetCertificatePEM string    `json:"target_certificate_pem"` // leaf first; intermediates may follow
	CPLID                string    `json:"cpl_id"`
	ContentTitleText     string    `json:"content_title_text"`
	AnnotationText       string    `json:"annotation_text,omitempty"`
	ContentAuthenticator string    `json:"content_authenticator,omitempty"` // base64 thumbprint of a CPL signer certificate
	NotValidBefore       time.Time `json:"not_valid_before"`
	NotValidAfter        time.Time `json:"not_valid_after"`
	Keys                 []Key     `json:"keys"`
	// DeviceList is "assume_trust" (default: Modified Transitional 1) or
	// "recipient" (the target certificate's own thumbprint).
	DeviceList string `json:"device_list,omitempty"`
}

// Result is the decision: Allow with the KDM, or a refusal reason.
type Result struct {
	Allow     bool
	Reason    string
	KDM       []byte
	MessageID string
	Recipient string
}

// Denied is a clean refusal (the target is not acceptable).
func Denied(reason string) Result { return Result{Reason: reason} }

// BadRequest is an error in the request itself.
type BadRequest struct{ msg string }

func (e *BadRequest) Error() string { return e.msg }

func bad(f string, v ...any) error { return &BadRequest{fmt.Sprintf(f, v...)} }

var uuidRe = regexp.MustCompile(`^(?:urn:uuid:)?([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$`)

func parseUUID(s string) ([]byte, string, error) {
	m := uuidRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return nil, "", fmt.Errorf("%q is not a UUID", s)
	}
	b, _ := hex.DecodeString(strings.Join(m[1:], ""))
	return b, strings.ToLower(strings.Join(m[1:], "-")), nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Issue checks the target and builds and signs the KDM.
func (v *Issuer) Issue(ctx context.Context, req Request) (Result, error) {
	cplRaw, cplID, err := parseUUID(req.CPLID)
	if err != nil {
		return Result{}, bad("cpl_id: %v", err)
	}
	if strings.TrimSpace(req.ContentTitleText) == "" {
		return Result{}, bad("content_title_text is required")
	}
	nb, na := req.NotValidBefore.UTC().Truncate(time.Second), req.NotValidAfter.UTC().Truncate(time.Second)
	if nb.IsZero() || na.IsZero() || !na.After(nb) {
		return Result{}, bad("not_valid_after must be after not_valid_before (both RFC 3339)")
	}
	if !na.After(v.now()) {
		return Result{}, bad("the validity window has already ended")
	}
	if len(req.Keys) == 0 || len(req.Keys) > 64 {
		return Result{}, bad("give 1 to 64 keys")
	}
	type key struct {
		typ      string
		id, k    []byte
		idString string
	}
	keys := make([]key, 0, len(req.Keys))
	for i, k := range req.Keys {
		if !keyTypes[k.Type] {
			return Result{}, bad("keys[%d].type %q is not a KDM key type", i, k.Type)
		}
		idb, ids, err := parseUUID(k.ID)
		if err != nil {
			return Result{}, bad("keys[%d].id: %v", i, err)
		}
		kb, err := hex.DecodeString(strings.TrimSpace(k.Hex))
		if err != nil || len(kb) != 16 {
			return Result{}, bad("keys[%d].key_hex must be 16 bytes of hex", i)
		}
		keys = append(keys, key{k.Type, idb, kb, ids})
	}
	dl := req.DeviceList
	if dl == "" {
		dl = "assume_trust"
	}
	if dl != "assume_trust" && dl != "recipient" {
		return Result{}, bad("device_list must be assume_trust or recipient")
	}

	chain, err := x.ParseChain([]byte(req.TargetCertificatePEM))
	if err != nil {
		return Denied("target_certificate_pem: " + err.Error()), nil
	}
	target := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := target.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: inter, CurrentTime: v.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return Denied("the target certificate is not trusted: " + err.Error()), nil
	}
	pub, ok := target.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return Denied("the target certificate's key is not RSA of at least 2048 bits"), nil
	}

	// AuthenticatedPrivate: the ST 430-1 cipher blocks
	thumb := x.Thumbprint(v.signer)
	priv := x.E("AuthenticatedPrivate").Attr("Id", "ID_AuthenticatedPrivate")
	typed := x.E("KeyIdList")
	for _, k := range keys {
		blk := make([]byte, 0, 138)
		blk = append(blk, structureID...)
		blk = append(blk, thumb...)
		blk = append(blk, cplRaw...)
		blk = append(blk, k.typ...)
		blk = append(blk, k.id...)
		blk = append(blk, nb.Format(timeLayout)...)
		blk = append(blk, na.Format(timeLayout)...)
		blk = append(blk, k.k...)
		if len(blk) != 138 {
			return Result{}, fmt.Errorf("dcp-key: cipher block is %d bytes", len(blk))
		}
		ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, blk, nil)
		if err != nil {
			return Result{}, fmt.Errorf("dcp-key: wrap key: %w", err)
		}
		priv.Add(x.E("enc:EncryptedKey",
			x.E("enc:EncryptionMethod", x.E("dsig:DigestMethod").Attr("Algorithm", x.DigestSHA1)).Attr("Algorithm", x.RSAOAEPMGF1P),
			x.E("enc:CipherData", x.E("enc:CipherValue", base64.StdEncoding.EncodeToString(ct)))))
		typed.Add(x.E("TypedKeyId", x.E("KeyType", k.typ).Attr("scope", MessageTypeKDM), x.E("KeyId", "urn:uuid:"+k.idString)))
	}

	device := AssumeTrust
	if dl == "recipient" {
		device = base64.StdEncoding.EncodeToString(x.Thumbprint(target))
	}
	var auth *x.Elem
	if req.ContentAuthenticator != "" {
		if b, err := base64.StdEncoding.DecodeString(req.ContentAuthenticator); err != nil || len(b) != 20 {
			return Result{}, bad("content_authenticator must be a base64 SHA-1 thumbprint")
		}
		auth = x.E("ContentAuthenticator", req.ContentAuthenticator)
	}
	ext := x.E("KDMRequiredExtensions",
		x.E("Recipient",
			x.E("X509IssuerSerial", x.IssuerSerial(target)...),
			x.E("X509SubjectName", x.DN(target.RawSubject))),
		x.E("CompositionPlaylistId", "urn:uuid:"+cplID),
		auth,
		x.E("ContentTitleText", req.ContentTitleText),
		x.E("ContentKeysNotValidBefore", nb.Format(timeLayout)),
		x.E("ContentKeysNotValidAfter", na.Format(timeLayout)),
		x.E("AuthorizedDeviceInfo",
			x.E("DeviceListIdentifier", "urn:uuid:"+newUUID()),
			x.E("DeviceList", x.E("CertificateThumbprint", device))),
		typed,
	).Decl("", NSKDM)
	msgID := newUUID()
	var ann *x.Elem
	if req.AnnotationText != "" {
		ann = x.E("AnnotationText", req.AnnotationText)
	}
	pubEl := x.E("AuthenticatedPublic",
		x.E("MessageId", "urn:uuid:"+msgID),
		x.E("MessageType", MessageTypeKDM),
		ann,
		x.E("IssueDate", v.now().UTC().Format(timeLayout)),
		v.sig.SignerElem(true),
		x.E("RequiredExtensions", ext),
		x.E("NonCriticalExtensions"),
	).Attr("Id", "ID_AuthenticatedPublic")
	root := x.E("DCinemaSecurityMessage", pubEl, priv).Decl("", NSETM).Decl("dsig", x.NSDsig).Decl("enc", x.NSEnc)
	x.Indent(root, 0)
	if err := v.sig.Sign(root, []x.Ref{{URI: "#ID_AuthenticatedPublic"}, {URI: "#ID_AuthenticatedPrivate"}}); err != nil {
		return Result{}, err
	}
	return Result{Allow: true, KDM: x.Document(root), MessageID: msgID, Recipient: x.DN(target.RawSubject)}, nil
}
