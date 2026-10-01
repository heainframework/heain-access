// Package store persists AccessGrants issued by heain-access and serves
// the lookups needed to verify them later (POST /verify-grant). Stage A
// ships one implementation, InMemoryStore; it is expected to be replaced
// or supplemented by a durable backing store once heain-access runs
// outside a single process, without the Store interface itself changing.
package store

import (
	"context"
	"errors"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// ErrNotFound is returned by Get when no grant with the given ID exists.
var ErrNotFound = errors.New("store: access grant not found")

// Store persists and retrieves AccessGrants by ID.
type Store interface {
	// Save persists g, keyed by g.ID. Saving a grant whose ID already
	// exists overwrites the previous record — issuance is expected to
	// generate a fresh ID per grant, so an overwrite in practice means a
	// caller is retrying the same issuance and intends idempotent
	// behavior, not that two distinct grants are colliding.
	Save(ctx context.Context, g accesswire.AccessGrant) error

	// Get returns the grant with the given ID, or ErrNotFound if none
	// exists.
	Get(ctx context.Context, id string) (accesswire.AccessGrant, error)
}
