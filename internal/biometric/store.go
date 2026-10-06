// Package biometric keeps enrolled biometric templates -- face embeddings
// and fingerprint minutiae templates, never images (data class
// biometric_template: raw_storage forbidden, retention max 30d,
// crypto_shred, node-local).
//
// Each subject has its own data key in heain-core's KMS; the subject's
// templates are sealed under it, so removing a subject (or its retention
// running out) destroys the key: a crypto-shred that also covers any copy
// of the file. Subjects are filed under an HMAC of their id (key from the
// app's "inside" data key), so neither the file nor core's KMS key names
// reveal an id.
package biometric

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/heain"
)

// ErrNotEnrolled: no live template for this subject and method.
var ErrNotEnrolled = errors.New("biometric: not enrolled")

// Keys gives sealers over per-subject data keys and destroys them.
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Template is one enrolled template.
type Template struct {
	Method     string    `json:"method"` // face | fingerprint
	Data       []byte    `json:"data"`   // face: JSON []float64; fingerprint: sidecar template
	EnrolledAt time.Time `json:"enrolled_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type subject struct {
	KeyName string               `json:"key_name"`
	Methods map[string]time.Time `json:"methods"` // method -> expires_at
}

var (
	bSubjects  = []byte("subjects")
	bTemplates = []byte("templates")
)

// Store is the enrolment database.
type Store struct {
	db     *bolt.DB
	inside *heain.Sealer
	mac    []byte
	keys   Keys
	now    func() time.Time
}

// Open opens the store; inside seals the subject index, insideKey derives
// the HMAC for subject ids.
func Open(path string, inside *heain.Sealer, insideKey []byte, keys Keys) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("biometric: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bSubjects, bTemplates} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, insideKey)
	m.Write([]byte("heain-access/subject/v1"))
	return &Store{db: db, inside: inside, mac: m.Sum(nil), keys: keys, now: time.Now}, nil
}

// Close closes the file.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ix(subjectID string) string {
	m := hmac.New(sha256.New, s.mac)
	m.Write([]byte(subjectID))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) readSubject(tx *bolt.Tx, ix string) (subject, bool) {
	var sub subject
	v := tx.Bucket(bSubjects).Get([]byte(ix))
	if v == nil {
		return sub, false
	}
	p, err := s.inside.Open(v, []byte("subject/"+ix))
	if err != nil || json.Unmarshal(p, &sub) != nil {
		return sub, false
	}
	return sub, true
}

func (s *Store) writeSubject(tx *bolt.Tx, ix string, sub subject) error {
	b, _ := json.Marshal(sub)
	return tx.Bucket(bSubjects).Put([]byte(ix), s.inside.Seal(b, []byte("subject/"+ix)))
}

// Enroll stores a template for subjectID, replacing an earlier one of the
// same method, kept for ttl.
func (s *Store) Enroll(ctx context.Context, subjectID, method string, data []byte, ttl time.Duration) (Template, error) {
	if subjectID == "" || len(data) == 0 {
		return Template{}, errors.New("biometric: subject and template are required")
	}
	ix := s.ix(subjectID)
	keyName := "subj-" + ix[:40]
	sealer, err := s.keys.Sealer(ctx, keyName)
	if err != nil {
		return Template{}, fmt.Errorf("biometric: subject key: %w", err)
	}
	now := s.now().UTC()
	t := Template{Method: method, Data: data, EnrolledAt: now, ExpiresAt: now.Add(ttl)}
	return t, s.db.Update(func(tx *bolt.Tx) error {
		sub, ok := s.readSubject(tx, ix)
		if !ok {
			sub = subject{KeyName: keyName, Methods: map[string]time.Time{}}
		}
		sub.Methods[method] = t.ExpiresAt
		if err := s.writeSubject(tx, ix, sub); err != nil {
			return err
		}
		b, _ := json.Marshal(t)
		k := ix + "/" + method
		return tx.Bucket(bTemplates).Put([]byte(k), sealer.Seal(b, []byte("template/"+k)))
	})
}

// Get returns the live template of subjectID for method.
func (s *Store) Get(ctx context.Context, subjectID, method string) (Template, error) {
	ix := s.ix(subjectID)
	var sub subject
	var sealed []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		var ok bool
		if sub, ok = s.readSubject(tx, ix); !ok {
			return ErrNotEnrolled
		}
		if exp, ok := sub.Methods[method]; !ok || !s.now().Before(exp) {
			return ErrNotEnrolled
		}
		v := tx.Bucket(bTemplates).Get([]byte(ix + "/" + method))
		if v == nil {
			return ErrNotEnrolled
		}
		sealed = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return Template{}, err
	}
	sealer, err := s.keys.Sealer(ctx, sub.KeyName)
	if err != nil {
		return Template{}, err
	}
	k := ix + "/" + method
	p, err := sealer.Open(sealed, []byte("template/"+k))
	if err != nil {
		return Template{}, ErrNotEnrolled // the subject key was destroyed
	}
	var t Template
	return t, json.Unmarshal(p, &t)
}

// Remove deletes every template of subjectID and destroys its key.
func (s *Store) Remove(ctx context.Context, subjectID string) (bool, error) {
	return s.remove(ctx, s.ix(subjectID), nil)
}

// remove drops the given methods (nil = all) of subject ix; when none is
// left the subject and its key go.
func (s *Store) remove(ctx context.Context, ix string, methods []string) (bool, error) {
	var keyName string
	gone := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		sub, ok := s.readSubject(tx, ix)
		if !ok {
			return nil
		}
		if methods == nil {
			for m := range sub.Methods {
				methods = append(methods, m)
			}
		}
		for _, m := range methods {
			delete(sub.Methods, m)
			if err := tx.Bucket(bTemplates).Delete([]byte(ix + "/" + m)); err != nil {
				return err
			}
		}
		if len(sub.Methods) > 0 {
			return s.writeSubject(tx, ix, sub)
		}
		keyName, gone = sub.KeyName, true
		return tx.Bucket(bSubjects).Delete([]byte(ix))
	})
	if err != nil || !gone {
		return gone, err
	}
	return true, s.keys.Destroy(ctx, keyName)
}

// Sweep removes templates whose retention ran out (and the keys of
// subjects left with none). It returns how many templates went.
func (s *Store) Sweep(ctx context.Context) (int, error) {
	now := s.now()
	expired := map[string][]string{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bSubjects).ForEach(func(k, _ []byte) error {
			if sub, ok := s.readSubject(tx, string(k)); ok {
				for m, exp := range sub.Methods {
					if !now.Before(exp) {
						expired[string(k)] = append(expired[string(k)], m)
					}
				}
			}
			return nil
		})
	})
	n := 0
	for ix, ms := range expired {
		if _, err := s.remove(ctx, ix, ms); err != nil {
			return n, err
		}
		n += len(ms)
	}
	return n, nil
}
