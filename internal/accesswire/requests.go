package accesswire

import "time"

// IssueGrantRequest is the HTTP request body for POST /issue-grant.
// Evidence is method-specific (e.g. a face-match image reference, a
// keycard UID, a KDM recipient certificate) and is validated by the
// Verifier selected via Method, not by accesswire itself.
type IssueGrantRequest struct {
	Recipient  string             `json:"recipient"`
	AssetRef   string             `json:"asset_ref"`
	Method     VerificationMethod `json:"verification_method"`
	ValidFrom  time.Time          `json:"valid_from"`
	ValidUntil time.Time          `json:"valid_until"`
	Evidence   map[string]string  `json:"evidence,omitempty"`
}

// IssueGrantResponse is the HTTP response body for POST /issue-grant.
type IssueGrantResponse struct {
	Grant AccessGrant `json:"grant"`
}

// VerifyGrantRequest is the HTTP request body for POST /verify-grant.
type VerifyGrantRequest struct {
	GrantID  string `json:"grant_id"`
	AssetRef string `json:"asset_ref"`
}

// VerifyGrantResponse is the HTTP response body for POST /verify-grant.
// Reason is populated only when Valid is false.
type VerifyGrantResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason,omitempty"`
}
