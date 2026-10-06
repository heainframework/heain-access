// Package xmldsig builds the XML documents of digital cinema (SMPTE 429-x
// CPL/PKL/ASSETMAP, SMPTE 430-1/430-3 KDM) and signs them with XML
// Signature (RSA-SHA256, SHA-256 digests).
//
// The documents are built as a small tree and written by one serializer
// that emits Canonical XML 1.0 (inclusive, W3C REC-xml-c14n-20010315)
// directly: no XML declaration inside, attributes sorted, namespace
// declarations rendered where c14n renders them, empty elements as
// start/end pairs, c14n escaping. The bytes in the file are therefore the
// bytes that are digested, and a reference to a sub-tree (#ID) is the same
// serializer started at that element with every in-scope namespace on it --
// which is what inclusive c14n of a document subset does. There are no
// comments, so "with comments" and "without" coincide.
//
// The same file is kept in heain-access (internal/xmldsig) and
// heain-mastering (internal/xmldsig): two apps, no shared module.
package xmldsig

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// Namespaces and algorithm identifiers.
const (
	NSDsig         = "http://www.w3.org/2000/09/xmldsig#"
	NSEnc          = "http://www.w3.org/2001/04/xmlenc#"
	C14NWithCmt    = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	C14N           = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	RSASHA256      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	DigestSHA256   = "http://www.w3.org/2001/04/xmlenc#sha256"
	EnvelopedSig   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	RSAOAEPMGF1P   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	DigestSHA1     = "http://www.w3.org/2000/09/xmldsig#sha1"
	xmlDeclaration = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` + "\n"
)

// Elem is one element. Kids are *Elem or string (text).
type Elem struct {
	Name  string // "local" or "prefix:local"
	NS    [][2]string
	Attrs [][2]string // unqualified attributes only
	Kids  []any
}

// E makes an element; a kid that is a string is text, nil kids are skipped.
func E(name string, kids ...any) *Elem {
	e := &Elem{Name: name}
	for _, k := range kids {
		switch v := k.(type) {
		case nil:
		case *Elem:
			if v != nil {
				e.Kids = append(e.Kids, v)
			}
		case string:
			e.Kids = append(e.Kids, v)
		default:
			e.Kids = append(e.Kids, fmt.Sprint(v))
		}
	}
	return e
}

// Decl declares namespace prefix ("" = default) on e.
func (e *Elem) Decl(prefix, uri string) *Elem {
	e.NS = append(e.NS, [2]string{prefix, uri})
	return e
}

// Attr sets an unqualified attribute.
func (e *Elem) Attr(k, v string) *Elem {
	e.Attrs = append(e.Attrs, [2]string{k, v})
	return e
}

// Add appends kids.
func (e *Elem) Add(kids ...any) *Elem {
	e.Kids = append(e.Kids, E("x", kids...).Kids...)
	return e
}

// Text is the concatenated text directly under e.
func (e *Elem) Text() string {
	var b strings.Builder
	for _, k := range e.Kids {
		if s, ok := k.(string); ok {
			b.WriteString(s)
		}
	}
	return b.String()
}

// Indent puts newline+indent text between the element children of every
// element that has no text of its own (call before signing).
func Indent(e *Elem, depth int) {
	hasElem, hasText := false, false
	var els []*Elem
	for _, k := range e.Kids {
		switch v := k.(type) {
		case *Elem:
			hasElem = true
			els = append(els, v)
		case string:
			if strings.TrimSpace(v) != "" {
				hasText = true
			}
		}
	}
	if !hasElem || hasText {
		return
	}
	pad := "\n" + strings.Repeat("  ", depth+1)
	kids := make([]any, 0, 2*len(els)+1)
	for _, c := range els {
		kids = append(kids, pad, c)
		Indent(c, depth+1)
	}
	kids = append(kids, "\n"+strings.Repeat("  ", depth))
	e.Kids = kids
}

func escText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")
	return r.Replace(s)
}

func escAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
	return r.Replace(s)
}

// canon writes e in canonical form. inScope is the namespace context of
// e's parent; rendered is what the nearest output ancestor rendered (nil at
// the apex, so every in-scope namespace is rendered there). skip is left out.
func canon(b *bytes.Buffer, e *Elem, inScope, rendered map[string]string, skip *Elem) {
	scope := map[string]string{}
	for k, v := range inScope {
		scope[k] = v
	}
	for _, d := range e.NS {
		scope[d[0]] = d[1]
	}
	var decls []string
	for p, u := range scope {
		if p == "" && u == "" {
			if rendered != nil && rendered[""] != "" {
				decls = append(decls, p)
			}
			continue
		}
		if rv, ok := rendered[p]; !ok || rv != u {
			decls = append(decls, p)
		}
	}
	sort.Strings(decls) // "" (default) sorts first
	b.WriteString("<" + e.Name)
	for _, p := range decls {
		if p == "" {
			b.WriteString(` xmlns="` + escAttr(scope[""]) + `"`)
		} else {
			b.WriteString(" xmlns:" + p + `="` + escAttr(scope[p]) + `"`)
		}
	}
	attrs := append([][2]string(nil), e.Attrs...)
	sort.Slice(attrs, func(i, j int) bool { return attrs[i][0] < attrs[j][0] })
	for _, a := range attrs {
		b.WriteString(" " + a[0] + `="` + escAttr(a[1]) + `"`)
	}
	b.WriteString(">")
	for _, k := range e.Kids {
		switch v := k.(type) {
		case string:
			b.WriteString(escText(v))
		case *Elem:
			if v == skip {
				continue
			}
			canon(b, v, scope, scope, skip)
		}
	}
	b.WriteString("</" + e.Name + ">")
}

// Canonical is the canonical form of the whole document rooted at root,
// without skip (the enveloped-signature transform).
func Canonical(root, skip *Elem) []byte {
	var b bytes.Buffer
	canon(&b, root, map[string]string{}, nil, skip)
	return b.Bytes()
}

// Document is the file: an XML declaration and the canonical root.
func Document(root *Elem) []byte {
	return append([]byte(xmlDeclaration), append(Canonical(root, nil), '\n')...)
}

// SubsetCanonical is the canonical form of the sub-tree target of root
// (inclusive c14n of a document subset: every in-scope namespace on it).
func SubsetCanonical(root, target *Elem) ([]byte, error) {
	scope, ok := findScope(root, target, map[string]string{})
	if !ok {
		return nil, fmt.Errorf("xmldsig: element %s is not in the document", target.Name)
	}
	var b bytes.Buffer
	canon(&b, target, scope, nil, nil)
	return b.Bytes(), nil
}

func findScope(e, target *Elem, parent map[string]string) (map[string]string, bool) {
	if e == target {
		return parent, true
	}
	scope := map[string]string{}
	for k, v := range parent {
		scope[k] = v
	}
	for _, d := range e.NS {
		scope[d[0]] = d[1]
	}
	for _, k := range e.Kids {
		if c, ok := k.(*Elem); ok {
			if s, ok := findScope(c, target, scope); ok {
				return s, true
			}
		}
	}
	return nil, false
}

// FindID finds the element with attribute Id=id.
func FindID(e *Elem, id string) *Elem {
	for _, a := range e.Attrs {
		if a[0] == "Id" && a[1] == id {
			return e
		}
	}
	for _, k := range e.Kids {
		if c, ok := k.(*Elem); ok {
			if f := FindID(c, id); f != nil {
				return f
			}
		}
	}
	return nil
}

// ---- certificates

// ParseChain reads every certificate in pem (leaf first, as given).
func ParseChain(pemData []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, pemData = pem.Decode(pemData)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("xmldsig: no certificate in PEM")
	}
	return out, nil
}

// ParseRSAKey reads a PKCS#1 or PKCS#8 RSA private key.
func ParseRSAKey(pemData []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemData)
	if blk == nil {
		return nil, fmt.Errorf("xmldsig: key PEM contains no block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("xmldsig: not a PKCS#1 or PKCS#8 RSA key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("xmldsig: key is not RSA")
	}
	return rk, nil
}

// Thumbprint is the SMPTE 430-2 certificate thumbprint: SHA-1 of the DER
// TBSCertificate.
func Thumbprint(c *x509.Certificate) []byte {
	s := sha1.Sum(c.RawTBSCertificate)
	return s[:]
}

var oidNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.11": "OU", "2.5.4.10": "O", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.46": "dnQualifier", "2.5.4.5": "serialNumber", "0.9.2342.19200300.100.1.25": "DC",
}

// DN formats a distinguished name as RFC 2253 (last RDN first), with the
// attribute names digital cinema uses (dnQualifier by name).
func DN(raw []byte) string {
	var seq pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return ""
	}
	parts := make([]string, 0, len(seq))
	for i := len(seq) - 1; i >= 0; i-- {
		var avs []string
		for _, av := range seq[i] {
			k := oidNames[av.Type.String()]
			if k == "" {
				k = av.Type.String()
			}
			avs = append(avs, k+"="+escDN(fmt.Sprint(av.Value)))
		}
		parts = append(parts, strings.Join(avs, "+"))
	}
	return strings.Join(parts, ",")
}

func escDN(s string) string {
	var b strings.Builder
	for i, r := range s {
		switch {
		case strings.ContainsRune(`,+"\<>;`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		case (r == '#' || r == ' ') && i == 0, r == ' ' && i == len(s)-1:
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// IssuerSerial is <dsig:X509IssuerName> and <dsig:X509SerialNumber> of c.
func IssuerSerial(c *x509.Certificate) []any {
	return []any{E("dsig:X509IssuerName", DN(c.RawIssuer)), E("dsig:X509SerialNumber", c.SerialNumber.String())}
}

// ---- signing

// Signer is a signing identity: an RSA key and its chain, leaf first.
type Signer struct {
	Key   *rsa.PrivateKey
	Chain []*x509.Certificate
}

// LoadSigner reads a chain PEM (leaf first) and its key PEM.
func LoadSigner(chainPEM, keyPEM []byte) (*Signer, error) {
	ch, err := ParseChain(chainPEM)
	if err != nil {
		return nil, err
	}
	k, err := ParseRSAKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pub, ok := ch[0].PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(k.N) != 0 {
		return nil, fmt.Errorf("xmldsig: the key does not belong to the first certificate of the chain")
	}
	return &Signer{Key: k, Chain: ch}, nil
}

// Ref is one reference: "#ID" or "" (the enveloping document).
type Ref struct{ URI string }

// Profile is how a kind of document is signed (the signature itself is
// always RSA-SHA256).
type Profile struct {
	C14N   string // SignedInfo's canonicalization method
	Digest string // the references' digest method: DigestSHA1 or DigestSHA256
}

var (
	// ProfileETM: KDMs (SMPTE ST 430-3) -- c14n with comments, SHA-256 digests.
	ProfileETM = Profile{C14N: C14NWithCmt, Digest: DigestSHA256}
	// ProfileCPL: CPL and PKL (SMPTE ST 429-7 / 429-8, as libdcp writes and
	// ClairMeta checks them) -- c14n without comments, SHA-1 digests.
	ProfileCPL = Profile{C14N: C14N, Digest: DigestSHA1}
)

// Sign signs with ProfileETM.
func (s *Signer) Sign(root *Elem, refs []Ref) error { return s.SignAs(root, refs, ProfileETM) }

// SignAs appends a <dsig:Signature> (indented at depth 1) to root, which
// must declare the dsig prefix and already be indented. "" uses the
// enveloped-signature transform alone, "#ID" none (a bare-name pointer is
// canonicalized by default). The documents have no comments, so the two
// c14n methods give the same bytes.
func (s *Signer) SignAs(root *Elem, refs []Ref, p Profile) error {
	if (p.Digest != DigestSHA1 && p.Digest != DigestSHA256) || (p.C14N != C14N && p.C14N != C14NWithCmt) {
		return fmt.Errorf("xmldsig: unsupported profile %+v", p)
	}
	// the whitespace around the signature belongs to the document
	if n := len(root.Kids); n > 0 {
		if t, ok := root.Kids[n-1].(string); ok && strings.TrimSpace(t) == "" {
			root.Kids = root.Kids[:n-1]
		}
	}
	sig := E("dsig:Signature")
	root.Kids = append(root.Kids, "\n  ", sig, "\n")
	si := E("dsig:SignedInfo",
		E("dsig:CanonicalizationMethod").Attr("Algorithm", p.C14N),
		E("dsig:SignatureMethod").Attr("Algorithm", RSASHA256))
	for _, r := range refs {
		var data []byte
		ref := E("dsig:Reference").Attr("URI", r.URI)
		if r.URI == "" {
			data = Canonical(root, sig)
			// one transform, as libdcp writes it: after it the node-set is
			// canonicalized (c14n without comments; there are none)
			ref.Add(E("dsig:Transforms", E("dsig:Transform").Attr("Algorithm", EnvelopedSig)))
		} else {
			t := FindID(root, strings.TrimPrefix(r.URI, "#"))
			if t == nil {
				return fmt.Errorf("xmldsig: no element with Id %s", r.URI)
			}
			var err error
			if data, err = SubsetCanonical(root, t); err != nil {
				return err
			}
		}
		var d []byte
		if p.Digest == DigestSHA1 {
			h := sha1.Sum(data)
			d = h[:]
		} else {
			h := sha256.Sum256(data)
			d = h[:]
		}
		ref.Add(E("dsig:DigestMethod").Attr("Algorithm", p.Digest), E("dsig:DigestValue", base64.StdEncoding.EncodeToString(d)))
		si.Add(ref)
	}
	sv := E("dsig:SignatureValue")
	ki := E("dsig:KeyInfo")
	for _, c := range s.Chain {
		ki.Add(E("dsig:X509Data",
			E("dsig:X509IssuerSerial", IssuerSerial(c)...),
			E("dsig:X509Certificate", base64.StdEncoding.EncodeToString(c.Raw))))
	}
	sig.Add(si, sv, ki)
	Indent(sig, 1)
	c, err := SubsetCanonical(root, si)
	if err != nil {
		return err
	}
	h := sha256.Sum256(c)
	v, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, h[:])
	if err != nil {
		return err
	}
	sv.Kids = []any{base64.StdEncoding.EncodeToString(v)}
	return nil
}

// SignerElem is the <Signer> of CPL/PKL/KDM: the leaf's issuer and serial.
// kdm selects the ETM form (IssuerName/SerialNumber directly under Signer).
func (s *Signer) SignerElem(kdm bool) *Elem {
	if kdm {
		return E("Signer", IssuerSerial(s.Chain[0])...)
	}
	return E("Signer", E("dsig:X509Data", E("dsig:X509IssuerSerial", IssuerSerial(s.Chain[0])...), E("dsig:X509SubjectName", DN(s.Chain[0].RawSubject))))
}
