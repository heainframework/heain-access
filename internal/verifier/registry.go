package verifier

import (
	"fmt"
	"sync"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// Registry maps a VerificationMethod to the Verifier that implements it.
// heain-access's HTTP layer holds one Registry, populated at startup with
// the five Stage A implementations, and looks up the right Verifier per
// request by the method named in IssueGrantRequest.
//
// Registry is safe for concurrent use; registration is expected to happen
// once at startup, lookups happen per-request.
type Registry struct {
	mu        sync.RWMutex
	verifiers map[accesswire.VerificationMethod]Verifier
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		verifiers: make(map[accesswire.VerificationMethod]Verifier),
	}
}

// Register adds v under its own Method(). It returns an error if a
// Verifier is already registered for that method, since exactly one
// implementation per method is expected.
func (r *Registry) Register(v Verifier) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := v.Method()
	if !m.Valid() {
		return fmt.Errorf("verifier: refusing to register unknown verification_method %q", m)
	}
	if _, exists := r.verifiers[m]; exists {
		return fmt.Errorf("verifier: a Verifier is already registered for method %q", m)
	}
	r.verifiers[m] = v
	return nil
}

// Get returns the Verifier registered for m, or an error if none is
// registered.
func (r *Registry) Get(m accesswire.VerificationMethod) (Verifier, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, ok := r.verifiers[m]
	if !ok {
		return nil, fmt.Errorf("verifier: no Verifier registered for method %q", m)
	}
	return v, nil
}
