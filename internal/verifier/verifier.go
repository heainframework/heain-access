// Package verifier defines the pluggable Verifier interface implemented by
// each of heain-access's Stage A verification methods (ID card, face,
// fingerprint, keycard, DCP/KDM key issuance), and the shared types they
// exchange with the HTTP layer that selects between them.
package verifier

import (
	"context"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// Verifier checks method-specific evidence and decides whether an
// AccessGrant should be issued. heain-access's HTTP layer selects an
// implementation by accesswire.VerificationMethod from the incoming
// IssueGrantRequest and delegates to it.
//
// A Verifier does not issue the AccessGrant itself -- persistence and ID
// generation are the store's job, triggered by the caller once Result.Allow
// is true. This keeps each Verifier focused purely on the evidence check.
type Verifier interface {
	// Method reports which accesswire.VerificationMethod this Verifier
	// implements. Exactly one Verifier should be registered per method.
	Method() accesswire.VerificationMethod

	// Verify inspects the evidence in in and returns a decision. An error
	// return means the evidence could not be evaluated at all (e.g. a
	// malformed input, an unreachable model sidecar) -- distinct from a
	// clean Result{Allow: false}, which means the evidence was evaluated
	// and did not clear the bar.
	Verify(ctx context.Context, in VerifyInput) (Result, error)
}

// VerifyInput carries the evidence a Verifier needs to reach a decision.
// Evidence is a method-specific bag of key/value strings (e.g. a face
// embedding reference, a keycard UID, a KDM recipient certificate) -- each
// Verifier implementation documents the keys it expects and returns an
// error from Verify if a required key is missing.
type VerifyInput struct {
	Recipient string
	AssetRef  string
	Evidence  map[string]string
}

// Result is a Verifier's decision.
//
// Confidence is in [0,1] for confidence-scored methods (ID card, face,
// fingerprint match) and is left at its zero value for methods whose
// decision is boolean by design.
//
// AnomalyScore is advisory-only and never overrides Allow. It exists so
// that keycard -- whose Allow decision stays a genuinely deterministic
// hard ACL/UID-list check, never a model's call -- can still carry a
// model-backed risk signal alongside that hard decision, per Stage A's
// confirmed design. Other methods may leave it at 0.
type Result struct {
	Allow        bool
	Confidence   float64
	AnomalyScore float64
	Reason       string

	// Output carries verifier-specific data produced alongside an Allow
	// decision, beyond the generic AccessGrant shape -- e.g. dcp_key's
	// generated KDM fields (encrypted content key, signature, recipient
	// thumbprint). nil/empty for every other Stage A method, which have
	// nothing to report beyond Allow/Confidence. httpapi copies this
	// straight into the issued AccessGrant.Output when non-nil.
	Output map[string]string
}

// Allowed is a convenience constructor for a clean positive decision with
// no anomaly signal.
func Allowed(confidence float64) Result {
	return Result{Allow: true, Confidence: confidence}
}

// Denied is a convenience constructor for a clean negative decision.
func Denied(reason string) Result {
	return Result{Allow: false, Reason: reason}
}
