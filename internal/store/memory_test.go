package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-access/internal/accesswire"
)

func sampleGrant(id string) accesswire.AccessGrant {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	return accesswire.AccessGrant{
		ID:                 id,
		Recipient:          "projector-01",
		AssetRef:           "dcp://feature-xyz",
		ValidFrom:          now,
		ValidUntil:         now.Add(72 * time.Hour),
		VerificationMethod: accesswire.VerificationMethodKeycard,
		IssuedAt:           now,
	}
}

func TestInMemoryStore_SaveAndGet(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	g := sampleGrant("grant-1")

	if err := s.Save(ctx, g); err != nil {
		t.Fatalf("unexpected error saving: %v", err)
	}

	got, err := s.Get(ctx, "grant-1")
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}
	if got.ID != g.ID || got.Recipient != g.Recipient {
		t.Errorf("got %+v, want %+v", got, g)
	}
}

func TestInMemoryStore_GetMissing(t *testing.T) {
	s := NewInMemoryStore()

	_, err := s.Get(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got err %v, want ErrNotFound", err)
	}
}

func TestInMemoryStore_SaveOverwrites(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()

	g := sampleGrant("grant-1")
	if err := s.Save(ctx, g); err != nil {
		t.Fatalf("unexpected error on first save: %v", err)
	}

	g.Recipient = "projector-02"
	if err := s.Save(ctx, g); err != nil {
		t.Fatalf("unexpected error on second save: %v", err)
	}

	got, err := s.Get(ctx, "grant-1")
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}
	if got.Recipient != "projector-02" {
		t.Errorf("got recipient %q, want %q (overwrite expected)", got.Recipient, "projector-02")
	}
}

func TestInMemoryStore_ConcurrentAccess(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g := sampleGrant("grant-concurrent")
			_ = s.Save(ctx, g)
			_, _ = s.Get(ctx, "grant-concurrent")
		}(i)
	}
	wg.Wait()

	if _, err := s.Get(ctx, "grant-concurrent"); err != nil {
		t.Fatalf("unexpected error after concurrent access: %v", err)
	}
}

// Compile-time check that InMemoryStore satisfies Store.
var _ Store = (*InMemoryStore)(nil)
