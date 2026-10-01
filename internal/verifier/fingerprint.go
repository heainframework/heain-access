package verifier

import (
	"context"
	"fmt"

	"github.com/heainframework/heain-access/internal/accesswire"
	"github.com/heainframework/heain-access/internal/mlclient"
)

// DefaultFingerprintMatchThreshold is the minimum SourceAFIS match score for
// FingerprintVerifier to Allow. SourceAFIS's own documentation treats a
// score around this level as a genuine match at a practical false-match
// rate (roughly FMR 0.01%); like DefaultFaceMatchThreshold, it is a Stage A
// starting point, not a value calibrated against this deployment's own
// labeled genuine/impostor dataset, which doesn't exist yet.
const DefaultFingerprintMatchThreshold = 40.0

// fingerprintConfidenceDivisor normalizes SourceAFIS's unbounded raw match
// score into a [0,1] Confidence for Result, consistent with the other
// confidence-scored Verifiers. It is a display/reporting convenience only --
// it never affects the Allow decision, which compares the raw score against
// threshold directly.
const fingerprintConfidenceDivisor = 100.0

// matchFunc is the shape of the fingerprint-matching call FingerprintVerifier
// delegates to. Production code uses mlclient.MatchFingerprint; tests inject
// a stub so they never need a real sidecar running.
type matchFunc func(ctx context.Context, sidecarURL, presentedImageB64, enrolledImageB64 string) (score float64, err error)

// FingerprintVerifier implements the fingerprint Stage A verification
// method.
//
// Per the user's explicit requirement, the sidecar behind this Verifier
// wraps a production-grade fingerprint matching engine (SourceAFIS), not a
// toy feature-matcher. Same "ML for the inherently non-deterministic part,
// deterministic Go for the rest" split already used by id_card and face:
// the sidecar does the actual minutiae extraction and matching (real ML/CV,
// no honest deterministic stand-in exists for "are these two fingerprints
// the same finger"); FingerprintVerifier's own job is the deterministic
// half -- comparing the engine's raw match score against Threshold.
//
// Stage A has no persistent enrollment store (mirrors face's and id_card's
// own Stage A simplifications), so the caller supplies the enrolled
// reference fingerprint image directly as evidence on every call, rather
// than heain-access looking up a previously-enrolled fingerprint by
// Recipient.
type FingerprintVerifier struct {
	sidecarURL string
	match      matchFunc
	threshold  float64
}

// NewFingerprintVerifier returns a FingerprintVerifier that calls the
// fingerprint sidecar at sidecarURL (e.g. "http://localhost:9702") and
// Allows at DefaultFingerprintMatchThreshold.
func NewFingerprintVerifier(sidecarURL string) *FingerprintVerifier {
	return &FingerprintVerifier{sidecarURL: sidecarURL, match: mlclient.MatchFingerprint, threshold: DefaultFingerprintMatchThreshold}
}

func (v *FingerprintVerifier) Method() accesswire.VerificationMethod {
	return accesswire.VerificationMethodFingerprint
}

// Verify requires the evidence keys "fingerprint_image_b64" (the presented
// live fingerprint scan, base64-encoded) and
// "enrolled_fingerprint_image_b64" (a reference scan of the recipient the
// caller expects, also base64-encoded, supplied from the caller's own
// trusted context).
func (v *FingerprintVerifier) Verify(ctx context.Context, in VerifyInput) (Result, error) {
	presented, ok := in.Evidence["fingerprint_image_b64"]
	if !ok || presented == "" {
		return Result{}, fmt.Errorf("verifier: fingerprint evidence missing required key %q", "fingerprint_image_b64")
	}
	enrolled, ok := in.Evidence["enrolled_fingerprint_image_b64"]
	if !ok || enrolled == "" {
		return Result{}, fmt.Errorf("verifier: fingerprint evidence missing required key %q", "enrolled_fingerprint_image_b64")
	}

	score, err := v.match(ctx, v.sidecarURL, presented, enrolled)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: fingerprint match failed: %w", err)
	}

	confidence := score / fingerprintConfidenceDivisor
	if confidence > 1 {
		confidence = 1
	}
	if confidence < 0 {
		confidence = 0
	}

	if score < v.threshold {
		return Denied(fmt.Sprintf("fingerprint match score %.2f is below the match threshold %.2f", score, v.threshold)), nil
	}

	return Allowed(confidence), nil
}
