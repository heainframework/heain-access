// Package grants keeps heain-access's AccessGrants: who (recipient) may use
// what (asset_ref) between two times, issued after a successful
// verification. Every grant is signed with heain-access's app key, so any
// holder of its certificate can check that a grant was issued by it and
// not altered; the store is sealed under the app's "inside" data key.
package grants

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/heain"
)

// ErrNotFound: no such grant.
var ErrNotFound = errors.New("grants: not found")

// Grant is one AccessGrant.
type Grant struct {
	ID             string    `json:"id"`
	Recipient      string    `json:"recipient"`
	AssetRef       string    `json:"asset_ref"`
	ValidFrom      time.Time `json:"valid_from"`
	ValidUntil     time.Time `json:"valid_until"`
	Method         string    `json:"verification_method"`
	VerificationID string    `json:"verification_id"`
	IssuedAt       time.Time `json:"issued_at"`
	Revoked        bool      `json:"revoked"`
	Signature      []byte    `json:"signature_b64"`
	CertPEM        string    `json:"issuer_cert_pem"`
}

// Digest is what the signature covers.
func (g Grant) Digest() []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("heain-access grant v1|%s|%s|%s|%s|%s|%s|%s|%s", g.ID, g.Recipient, g.AssetRef,
		g.ValidFrom.UTC().Format(time.RFC3339), g.ValidUntil.UTC().Format(time.RFC3339), g.Method, g.VerificationID, g.IssuedAt.UTC().Format(time.RFC3339Nano))))
	return h[:]
}

// Signer signs grant digests (heain.App).
type Signer interface {
	SignDigest([]byte) ([]byte, error)
	CertificatePEM() []byte
}

var bucket = []byte("grants")

// Store is the grant database.
type Store struct {
	db  *bolt.DB
	s   *heain.Sealer
	sig Signer
	now func() time.Time
}

// Open opens the store.
func Open(path string, s *heain.Sealer, sig Signer) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("grants: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucketIfNotExists(bucket); return err }); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, s: s, sig: sig, now: time.Now}, nil
}

// Close closes the file.
func (st *Store) Close() error { return st.db.Close() }

func (st *Store) put(g Grant) error {
	b, _ := json.Marshal(g)
	return st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(g.ID), st.s.Seal(b, []byte("grant/"+g.ID)))
	})
}

// Issue signs and stores g (ID, IssuedAt and signature are set here).
func (st *Store) Issue(g Grant) (Grant, error) {
	if g.Recipient == "" || g.AssetRef == "" {
		return Grant{}, errors.New("grants: recipient and asset_ref are required")
	}
	if !g.ValidUntil.After(g.ValidFrom) {
		return Grant{}, errors.New("grants: valid_until must be after valid_from")
	}
	g.ID, g.IssuedAt = heain.NewID(), st.now().UTC()
	var err error
	if g.Signature, err = st.sig.SignDigest(g.Digest()); err != nil {
		return Grant{}, err
	}
	g.CertPEM = string(st.sig.CertificatePEM())
	return g, st.put(g)
}

// Get reads a grant.
func (st *Store) Get(id string) (Grant, error) {
	var g Grant
	err := st.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucket).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		p, err := st.s.Open(v, []byte("grant/"+id))
		if err != nil {
			return err
		}
		return json.Unmarshal(p, &g)
	})
	return g, err
}

// Check reports whether grant id lets its recipient use assetRef now.
func (st *Store) Check(id, assetRef string) (bool, string, error) {
	g, err := st.Get(id)
	if err != nil {
		return false, "unknown grant", err
	}
	now := st.now()
	switch {
	case heain.VerifyDigest([]byte(g.CertPEM), g.Digest(), g.Signature) != nil:
		return false, "signature does not verify", nil
	case g.Revoked:
		return false, "revoked", nil
	case g.AssetRef != assetRef:
		return false, "grant is for another asset", nil
	case now.Before(g.ValidFrom):
		return false, "not valid yet", nil
	case !now.Before(g.ValidUntil):
		return false, "expired", nil
	}
	return true, "", nil
}

// Revoke marks a grant revoked (idempotent).
func (st *Store) Revoke(id string) error {
	g, err := st.Get(id)
	if err != nil {
		return err
	}
	g.Revoked = true
	return st.put(g)
}
