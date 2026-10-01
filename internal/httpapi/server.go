// Package httpapi wires a verifier.Registry and a store.Store into the
// two HTTP endpoints heain-access exposes to its callers (e.g.
// heain-mastering at DCP-build time): POST /issue-grant and
// POST /verify-grant. heain-access is a standalone service -- these
// endpoints are called directly, never registered into heain-job's
// data-type strategy/registry-pool.
package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/heainframework/heain-access/internal/accesswire"
	"github.com/heainframework/heain-access/internal/store"
	"github.com/heainframework/heain-access/internal/verifier"
)

// Server holds the dependencies the handlers need: a Verifier registry
// and a grant Store. now is overridable in tests; production code should
// leave it nil, in which case Routes defaults it to time.Now.
type Server struct {
	registry *verifier.Registry
	store    store.Store
	now      func() time.Time
}

// NewServer returns a Server. reg and st must not be nil.
func NewServer(reg *verifier.Registry, st store.Store) *Server {
	return &Server{registry: reg, store: st, now: time.Now}
}

// Routes returns the configured *http.ServeMux. Callers mount it directly
// or wrap it with their own middleware (logging, mTLS client-cert checks,
// etc. -- not yet added here; Stage A ships the generic HTTP mechanism
// first).
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/issue-grant", s.handleIssueGrant)
	mux.HandleFunc("/verify-grant", s.handleVerifyGrant)
	return mux
}

func (s *Server) handleIssueGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req accesswire.IssueGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Recipient == "" || req.AssetRef == "" {
		http.Error(w, "recipient and asset_ref are required", http.StatusBadRequest)
		return
	}
	if !req.Method.Valid() {
		http.Error(w, "unknown verification_method", http.StatusBadRequest)
		return
	}
	if !req.ValidUntil.After(req.ValidFrom) {
		http.Error(w, "valid_until must be after valid_from", http.StatusBadRequest)
		return
	}

	v, err := s.registry.Get(req.Method)
	if err != nil {
		http.Error(w, "no verifier available for this method", http.StatusServiceUnavailable)
		return
	}

	result, err := v.Verify(r.Context(), verifier.VerifyInput{
		Recipient: req.Recipient,
		AssetRef:  req.AssetRef,
		Evidence:  req.Evidence,
	})
	if err != nil {
		log.Printf("httpapi: verify error for method %s: %v", req.Method, err)
		http.Error(w, "verification could not be completed", http.StatusBadGateway)
		return
	}
	if !result.Allow {
		writeJSON(w, http.StatusForbidden, accesswire.VerifyGrantResponse{
			Valid:  false,
			Reason: result.Reason,
		})
		return
	}

	id, err := newGrantID()
	if err != nil {
		log.Printf("httpapi: generating grant id: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	grant := accesswire.AccessGrant{
		ID:                 id,
		Recipient:          req.Recipient,
		AssetRef:           req.AssetRef,
		ValidFrom:          req.ValidFrom,
		ValidUntil:         req.ValidUntil,
		VerificationMethod: req.Method,
		IssuedAt:           s.nowFunc(),
		Output:             result.Output,
	}
	if err := grant.Validate(); err != nil {
		http.Error(w, "generated grant failed validation: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.store.Save(r.Context(), grant); err != nil {
		log.Printf("httpapi: saving grant: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, accesswire.IssueGrantResponse{Grant: grant})
}

func (s *Server) handleVerifyGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req accesswire.VerifyGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.GrantID == "" {
		http.Error(w, "grant_id is required", http.StatusBadRequest)
		return
	}

	grant, err := s.store.Get(r.Context(), req.GrantID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, accesswire.VerifyGrantResponse{
			Valid:  false,
			Reason: "grant not found",
		})
		return
	}
	if err != nil {
		log.Printf("httpapi: looking up grant: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if req.AssetRef != "" && grant.AssetRef != req.AssetRef {
		writeJSON(w, http.StatusOK, accesswire.VerifyGrantResponse{
			Valid:  false,
			Reason: "asset_ref does not match grant",
		})
		return
	}

	if !grant.IsValidAt(s.nowFunc()) {
		writeJSON(w, http.StatusOK, accesswire.VerifyGrantResponse{
			Valid:  false,
			Reason: "grant is outside its validity window",
		})
		return
	}

	writeJSON(w, http.StatusOK, accesswire.VerifyGrantResponse{Valid: true})
}

func (s *Server) nowFunc() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("httpapi: encoding response: %v", err)
	}
}
