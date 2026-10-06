package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

type signer struct {
	k    *ecdsa.PrivateKey
	cert []byte
}

func newSigner() *signer {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "heain-access.x1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return &signer{k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func (s *signer) SignDigest(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, s.k, d) }
func (s *signer) CertificatePEM() []byte              { return s.cert }

func TestGrants(t *testing.T) {
	sl, _ := heain.NewSealer(bytes.Repeat([]byte{2}, 32))
	st, err := Open(filepath.Join(t.TempDir(), "g.db"), sl, newSigner())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	if _, err := st.Issue(Grant{Recipient: "r", AssetRef: "a", ValidFrom: now, ValidUntil: now}); err == nil {
		t.Fatal("empty window")
	}
	g, err := st.Issue(Grant{Recipient: "somchai", AssetRef: "door-7", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour), Method: "face", VerificationID: "v1"})
	if err != nil || g.ID == "" || len(g.Signature) == 0 {
		t.Fatal(err)
	}
	if ok, why, _ := st.Check(g.ID, "door-7"); !ok {
		t.Fatalf("valid: %s", why)
	}
	if ok, why, _ := st.Check(g.ID, "door-8"); ok || why != "grant is for another asset" {
		t.Fatal("other asset")
	}
	g2, _ := st.Get(g.ID)
	g2.AssetRef = "door-8"
	_ = st.put(g2) // tampered
	if ok, why, _ := st.Check(g.ID, "door-8"); ok || why != "signature does not verify" {
		t.Fatalf("tamper: %s", why)
	}
	_ = st.put(g)
	_ = st.Revoke(g.ID)
	if ok, why, _ := st.Check(g.ID, "door-7"); ok || why != "revoked" {
		t.Fatal("revoked")
	}
	st.now = func() time.Time { return now.Add(2 * time.Hour) }
	g3, _ := st.Issue(Grant{Recipient: "x", AssetRef: "a", ValidFrom: now, ValidUntil: now.Add(time.Hour)})
	if ok, why, _ := st.Check(g3.ID, "a"); ok || why != "expired" {
		t.Fatal("expired")
	}
	if _, _, err := st.Check("nope", "a"); err != ErrNotFound {
		t.Fatal("unknown")
	}
}
