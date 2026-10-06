package dcpkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	x "github.com/heainframework/heain-access/internal/xmldsig"
)

type ca struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pem  []byte
}

func mk(t *testing.T, cn string, parent *ca, isCA bool) *ca {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<40))
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn, Organization: []string{"heain-test"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	if isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	pt, pk := tpl, k
	if parent != nil {
		pt, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, pt, &k.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func keyPEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

type kdmDoc struct {
	Public struct {
		Ext struct {
			CPL     string   `xml:"CompositionPlaylistId"`
			Title   string   `xml:"ContentTitleText"`
			Before  string   `xml:"ContentKeysNotValidBefore"`
			After   string   `xml:"ContentKeysNotValidAfter"`
			Device  string   `xml:"AuthorizedDeviceInfo>DeviceList>CertificateThumbprint"`
			KeyIDs  []string `xml:"KeyIdList>TypedKeyId>KeyId"`
			Subject string   `xml:"Recipient>X509SubjectName"`
		} `xml:"RequiredExtensions>KDMRequiredExtensions"`
	} `xml:"AuthenticatedPublic"`
	Cipher []string `xml:"AuthenticatedPrivate>EncryptedKey>CipherData>CipherValue"`
}

func setup(t *testing.T) (*Issuer, *ca, *ca) {
	root := mk(t, "trust root", nil, true)
	inter := mk(t, "device intermediate", root, true)
	target := mk(t, "SM.server-1", inter, false)
	iroot := mk(t, "issuer root", nil, true)
	ileaf := mk(t, "CS.heain-access", iroot, false)
	is, err := New(root.pem, append(append([]byte{}, ileaf.pem...), iroot.pem...), keyPEM(ileaf.key))
	if err != nil {
		t.Fatal(err)
	}
	return is, target, inter
}

func TestIssueSMPTE(t *testing.T) {
	is, target, inter := setup(t)
	nb := time.Now().Add(-time.Minute).UTC()
	na := nb.Add(24 * time.Hour)
	pk, sk := strings.Repeat("11", 16), strings.Repeat("22", 16)
	res, err := is.Issue(context.Background(), Request{
		TargetCertificatePEM: string(target.pem) + string(inter.pem), CPLID: "urn:uuid:0f1e2d3c-4b5a-4968-8778-a69584736251",
		ContentTitleText: "Test <Feature> & Co", NotValidBefore: nb, NotValidAfter: na,
		Keys: []Key{{Type: "MDIK", ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Hex: pk}, {Type: "MDAK", ID: "11111111-2222-4333-8444-555555555555", Hex: sk}},
	})
	if err != nil || !res.Allow {
		t.Fatalf("issue: %v %+v", err, res)
	}
	var d kdmDoc
	if err := xml.Unmarshal(res.KDM, &d); err != nil {
		t.Fatal(err)
	}
	e := d.Public.Ext
	if e.CPL != "urn:uuid:0f1e2d3c-4b5a-4968-8778-a69584736251" || e.Title != "Test <Feature> & Co" || e.Device != AssumeTrust || len(e.KeyIDs) != 2 || len(d.Cipher) != 2 {
		t.Fatalf("public part: %+v", d)
	}
	if !strings.Contains(e.Subject, "CN=SM.server-1") || e.Before != nb.Truncate(time.Second).Format(timeLayout) {
		t.Fatalf("recipient/window: %q %q", e.Subject, e.Before)
	}
	want := map[string]string{"MDIK": pk, "MDAK": sk}
	for _, cv := range d.Cipher {
		ct, _ := base64.StdEncoding.DecodeString(cv)
		blk, err := rsa.DecryptOAEP(sha1.New(), nil, target.key, ct, nil)
		if err != nil || len(blk) != 138 {
			t.Fatalf("decrypt: %v %d", err, len(blk))
		}
		if !bytes.Equal(blk[:16], structureID) || !bytes.Equal(blk[16:36], x.Thumbprint(is.signer)) {
			t.Fatal("structure id / signer thumbprint")
		}
		if hex.EncodeToString(blk[36:52]) != "0f1e2d3c4b5a49688778a69584736251" {
			t.Fatal("cpl id")
		}
		typ := string(blk[52:56])
		if string(blk[72:97]) != e.Before || string(blk[97:122]) != e.After || hex.EncodeToString(blk[122:]) != want[typ] {
			t.Fatalf("block for %s: %q %q", typ, blk[72:97], blk[97:122])
		}
	}
	// the signature: digests and value
	if !bytes.Contains(res.KDM, []byte(`<dsig:Reference URI="#ID_AuthenticatedPublic">`)) || !bytes.Contains(res.KDM, []byte("dsig:X509Certificate")) {
		t.Fatal("signature missing")
	}
}

func TestRefusals(t *testing.T) {
	is, target, inter := setup(t)
	other := mk(t, "SM.rogue", mk(t, "rogue root", nil, true), false)
	nb := time.Now().UTC()
	base := Request{TargetCertificatePEM: string(target.pem) + string(inter.pem), CPLID: "0f1e2d3c-4b5a-4968-8778-a69584736251", ContentTitleText: "T",
		NotValidBefore: nb, NotValidAfter: nb.Add(time.Hour), Keys: []Key{{Type: "MDIK", ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Hex: strings.Repeat("ab", 16)}}}
	r := base
	r.TargetCertificatePEM = string(other.pem)
	if res, err := is.Issue(context.Background(), r); err != nil || res.Allow || !strings.Contains(res.Reason, "not trusted") {
		t.Fatalf("untrusted target: %v %+v", err, res)
	}
	r = base
	r.TargetCertificatePEM = string(target.pem) // the intermediate is needed
	if res, _ := is.Issue(context.Background(), r); res.Allow {
		t.Fatal("chain without its intermediate was accepted")
	}
	var br *BadRequest
	for name, mod := range map[string]func(*Request){
		"key type": func(q *Request) { q.Keys = []Key{{Type: "XXXX", ID: q.Keys[0].ID, Hex: q.Keys[0].Hex}} },
		"key size": func(q *Request) { q.Keys = []Key{{Type: "MDIK", ID: q.Keys[0].ID, Hex: "abcd"}} },
		"window":   func(q *Request) { q.NotValidAfter = q.NotValidBefore },
		"ended":    func(q *Request) { q.NotValidBefore, q.NotValidAfter = nb.Add(-2*time.Hour), nb.Add(-time.Hour) },
		"cpl":      func(q *Request) { q.CPLID = "nope" },
	} {
		q := base
		mod(&q)
		if _, err := is.Issue(context.Background(), q); !errors.As(err, &br) {
			t.Fatalf("%s: want a bad request, got %v", name, err)
		}
	}
}
