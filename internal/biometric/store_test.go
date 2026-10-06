package biometric

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

type fakeKMS struct{ keys map[string][]byte }

func (f *fakeKMS) api() Keys {
	return Keys{
		Sealer: func(_ context.Context, n string) (*heain.Sealer, error) {
			if f.keys[n] == nil {
				k := make([]byte, 32)
				_, _ = rand.Read(k)
				f.keys[n] = k
			}
			return heain.NewSealer(f.keys[n])
		},
		Destroy: func(_ context.Context, n string) error { delete(f.keys, n); return nil },
	}
}

func TestEnrolment(t *testing.T) {
	ctx := context.Background()
	ik := bytes.Repeat([]byte{1}, 32)
	in, _ := heain.NewSealer(ik)
	f := &fakeKMS{keys: map[string][]byte{}}
	p := filepath.Join(t.TempDir(), "b.db")
	s, err := Open(p, in, ik, f.api())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if _, err := s.Enroll(ctx, "1100500012345", "face", []byte("[0.1,0.2,secret-embedding]"), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Enroll(ctx, "1100500012345", "fingerprint", []byte("minutiae-secret"), time.Hour)
	if tm, err := s.Get(ctx, "1100500012345", "face"); err != nil || !bytes.Contains(tm.Data, []byte("secret-embedding")) {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.Get(ctx, "someone-else", "face"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("not enrolled")
	}
	if len(f.keys) != 1 {
		t.Fatal("one key per subject")
	}
	now = now.Add(2 * time.Hour) // fingerprint retention ran out
	if _, err := s.Get(ctx, "1100500012345", "fingerprint"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("expired template must not be used")
	}
	if n, _ := s.Sweep(ctx); n != 1 || len(f.keys) != 1 {
		t.Fatalf("sweep removes the expired template, keeps the key while face remains: %d %d", n, len(f.keys))
	}
	if gone, err := s.Remove(ctx, "1100500012345"); err != nil || !gone || len(f.keys) != 0 {
		t.Fatal("remove destroys the subject key (crypto-shred)")
	}
	if _, err := s.Get(ctx, "1100500012345", "face"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("removed")
	}
	_, _ = s.Enroll(ctx, "x2", "face", []byte("e"), time.Hour)
	now = now.Add(2 * time.Hour)
	if n, _ := s.Sweep(ctx); n != 1 || len(f.keys) != 0 {
		t.Fatal("a subject left with nothing loses its key")
	}
	_ = s.Close()
	raw, _ := os.ReadFile(p)
	for _, m := range []string{"1100500012345", "secret-embedding", "minutiae-secret"} {
		if bytes.Contains(raw, []byte(m)) {
			t.Fatalf("plaintext %q at rest", m)
		}
	}
}
