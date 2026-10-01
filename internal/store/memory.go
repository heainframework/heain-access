package store

import (
	"context"
	"sync"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// InMemoryStore is a Store backed by a mutex-guarded map. It holds no
// grants across process restarts, which is acceptable for Stage A: no
// caller depends on heain-access surviving a restart with grants intact
// yet. Safe for concurrent use.
type InMemoryStore struct {
	mu     sync.RWMutex
	grants map[string]accesswire.AccessGrant
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		grants: make(map[string]accesswire.AccessGrant),
	}
}

func (s *InMemoryStore) Save(ctx context.Context, g accesswire.AccessGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.ID] = g
	return nil
}

func (s *InMemoryStore) Get(ctx context.Context, id string) (accesswire.AccessGrant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[id]
	if !ok {
		return accesswire.AccessGrant{}, ErrNotFound
	}
	return g, nil
}
