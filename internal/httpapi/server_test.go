package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/heainframework/heain-access/internal/accesswire"
	"github.com/heainframework/heain-access/internal/store"
	"github.com/heainframework/heain-access/internal/verifier"
)

type stubVerifier struct {
	method accesswire.VerificationMethod
	result verifier.Result
}

func (v stubVerifier) Method() accesswire.VerificationMethod { return v.method }
func (v stubVerifier) Verify(ctx context.Context, in verifier.VerifyInput) (verifier.Result, error) {
	return v.result, nil
}

func newTestServer(t *testing.T, v verifier.Verifier, fixedNow time.Time) *Server {
	t.Helper()
	reg := verifier.NewRegistry()
	if err := reg.Register(v); err != nil {
		t.Fatalf("unexpected error registering verifier: %v", err)
	}
	s := NewServer(reg, store.NewInMemoryStore())
	s.now = func() time.Time { return fixedNow }
	return s
}

func doJSON(t *testing.T, mux *http.ServeMux, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestIssueGrant_Allowed(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{
		method: accesswire.VerificationMethodKeycard,
		result: verifier.Allowed(0),
	}, now)

	rec := doJSON(t, s.Routes(), http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "projector-01",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodKeycard,
		ValidFrom:  now,
		ValidUntil: now.Add(72 * time.Hour),
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp accesswire.IssueGrantResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Grant.ID == "" {
		t.Error("expected a non-empty grant ID")
	}
	if resp.Grant.Recipient != "projector-01" {
		t.Errorf("got recipient %q, want %q", resp.Grant.Recipient, "projector-01")
	}
}

func TestIssueGrant_Denied(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{
		method: accesswire.VerificationMethodKeycard,
		result: verifier.Denied("uid not on ACL"),
	}, now)

	rec := doJSON(t, s.Routes(), http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "projector-01",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodKeycard,
		ValidFrom:  now,
		ValidUntil: now.Add(72 * time.Hour),
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var resp accesswire.VerifyGrantResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid to be false")
	}
	if resp.Reason != "uid not on ACL" {
		t.Errorf("got reason %q, want %q", resp.Reason, "uid not on ACL")
	}
}

func TestIssueGrant_UnknownMethod(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{method: accesswire.VerificationMethodKeycard}, now)

	rec := doJSON(t, s.Routes(), http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "projector-01",
		AssetRef:   "dcp://feature-xyz",
		Method:     "quantum_retina_scan",
		ValidFrom:  now,
		ValidUntil: now.Add(time.Hour),
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestIssueGrant_NoRegisteredVerifier(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{method: accesswire.VerificationMethodFace}, now)

	rec := doJSON(t, s.Routes(), http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "projector-01",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodKeycard,
		ValidFrom:  now,
		ValidUntil: now.Add(time.Hour),
	})

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestVerifyGrant_RoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{
		method: accesswire.VerificationMethodDCPKey,
		result: verifier.Allowed(1),
	}, now)
	mux := s.Routes()

	issueRec := doJSON(t, mux, http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "theater-42",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodDCPKey,
		ValidFrom:  now,
		ValidUntil: now.Add(72 * time.Hour),
	})
	if issueRec.Code != http.StatusCreated {
		t.Fatalf("issue: got status %d, want %d; body: %s", issueRec.Code, http.StatusCreated, issueRec.Body.String())
	}
	var issueResp accesswire.IssueGrantResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issueResp); err != nil {
		t.Fatalf("decoding issue response: %v", err)
	}

	verifyRec := doJSON(t, mux, http.MethodPost, "/verify-grant", accesswire.VerifyGrantRequest{
		GrantID:  issueResp.Grant.ID,
		AssetRef: "dcp://feature-xyz",
	})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify: got status %d, want %d; body: %s", verifyRec.Code, http.StatusOK, verifyRec.Body.String())
	}
	var verifyResp accesswire.VerifyGrantResponse
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decoding verify response: %v", err)
	}
	if !verifyResp.Valid {
		t.Errorf("expected grant to verify as valid, got reason: %q", verifyResp.Reason)
	}
}

func TestVerifyGrant_NotFound(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{method: accesswire.VerificationMethodFace}, now)

	rec := doJSON(t, s.Routes(), http.MethodPost, "/verify-grant", accesswire.VerifyGrantRequest{
		GrantID: "grant-does-not-exist",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp accesswire.VerifyGrantResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Valid {
		t.Error("expected Valid to be false for a nonexistent grant")
	}
}

func TestVerifyGrant_WrongAssetRef(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{
		method: accesswire.VerificationMethodFace,
		result: verifier.Allowed(0.9),
	}, now)
	mux := s.Routes()

	issueRec := doJSON(t, mux, http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "staff-7",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodFace,
		ValidFrom:  now,
		ValidUntil: now.Add(time.Hour),
	})
	var issueResp accesswire.IssueGrantResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issueResp); err != nil {
		t.Fatalf("decoding issue response: %v", err)
	}

	verifyRec := doJSON(t, mux, http.MethodPost, "/verify-grant", accesswire.VerifyGrantRequest{
		GrantID:  issueResp.Grant.ID,
		AssetRef: "dcp://some-other-asset",
	})
	var verifyResp accesswire.VerifyGrantResponse
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decoding verify response: %v", err)
	}
	if verifyResp.Valid {
		t.Error("expected Valid to be false when asset_ref does not match")
	}
}

func TestVerifyGrant_ExpiredWindow(t *testing.T) {
	issuedAt := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{
		method: accesswire.VerificationMethodFace,
		result: verifier.Allowed(0.9),
	}, issuedAt)
	mux := s.Routes()

	issueRec := doJSON(t, mux, http.MethodPost, "/issue-grant", accesswire.IssueGrantRequest{
		Recipient:  "staff-7",
		AssetRef:   "dcp://feature-xyz",
		Method:     accesswire.VerificationMethodFace,
		ValidFrom:  issuedAt,
		ValidUntil: issuedAt.Add(time.Hour),
	})
	var issueResp accesswire.IssueGrantResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issueResp); err != nil {
		t.Fatalf("decoding issue response: %v", err)
	}

	s.now = func() time.Time { return issuedAt.Add(2 * time.Hour) }

	verifyRec := doJSON(t, mux, http.MethodPost, "/verify-grant", accesswire.VerifyGrantRequest{
		GrantID: issueResp.Grant.ID,
	})
	var verifyResp accesswire.VerifyGrantResponse
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("decoding verify response: %v", err)
	}
	if verifyResp.Valid {
		t.Error("expected Valid to be false once the grant has expired")
	}
}

func TestIssueGrant_MethodNotAllowed(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := newTestServer(t, stubVerifier{method: accesswire.VerificationMethodFace}, now)

	req := httptest.NewRequest(http.MethodGet, "/issue-grant", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
