package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/heainframework/heain-access/internal/accesswire"
)

func stubMatcher(scores map[[2]string]float64) matchFunc {
	return func(ctx context.Context, sidecarURL, presentedImageB64, enrolledImageB64 string) (float64, error) {
		return scores[[2]string{presentedImageB64, enrolledImageB64}], nil
	}
}

func TestFingerprintVerifier_Match(t *testing.T) {
	v := &FingerprintVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFingerprintMatchThreshold,
		match:      stubMatcher(map[[2]string]float64{{"presented-img", "enrolled-img"}: 1.0}),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"fingerprint_image_b64":          "presented-img",
			"enrolled_fingerprint_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Error("expected Allow to be true for a score above threshold")
	}
	if res.Confidence != 1.0 {
		t.Errorf("got confidence %v, want 1.0", res.Confidence)
	}
}

func TestFingerprintVerifier_Mismatch(t *testing.T) {
	v := &FingerprintVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFingerprintMatchThreshold,
		match:      stubMatcher(map[[2]string]float64{{"presented-img", "enrolled-img"}: 0.14}),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"fingerprint_image_b64":          "presented-img",
			"enrolled_fingerprint_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false for a score below threshold")
	}
	if res.Reason == "" {
		t.Error("expected a non-empty Reason on denial")
	}
}

func TestFingerprintVerifier_JustBelowThreshold(t *testing.T) {
	v := &FingerprintVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFingerprintMatchThreshold,
		match:      stubMatcher(map[[2]string]float64{{"presented-img", "enrolled-img"}: 0.79}),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"fingerprint_image_b64":          "presented-img",
			"enrolled_fingerprint_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false for a score just below the 0.8 threshold")
	}
}

func TestFingerprintVerifier_MissingPresentedEvidence(t *testing.T) {
	v := NewFingerprintVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"enrolled_fingerprint_image_b64": "x"},
	})
	if err == nil {
		t.Fatal("expected an error when fingerprint_image_b64 evidence is missing, got nil")
	}
}

func TestFingerprintVerifier_MissingEnrolledEvidence(t *testing.T) {
	v := NewFingerprintVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"fingerprint_image_b64": "x"},
	})
	if err == nil {
		t.Fatal("expected an error when enrolled_fingerprint_image_b64 evidence is missing, got nil")
	}
}

func TestFingerprintVerifier_MatchError(t *testing.T) {
	v := &FingerprintVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFingerprintMatchThreshold,
		match: func(ctx context.Context, sidecarURL, presentedImageB64, enrolledImageB64 string) (float64, error) {
			return 0, errors.New("sidecar unreachable")
		},
	}
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"fingerprint_image_b64":          "presented-img",
			"enrolled_fingerprint_image_b64": "enrolled-img",
		},
	})
	if err == nil {
		t.Fatal("expected an error when the fingerprint sidecar call fails, got nil")
	}
}

func TestFingerprintVerifier_Method(t *testing.T) {
	v := NewFingerprintVerifier("http://unused")
	if v.Method() != accesswire.VerificationMethodFingerprint {
		t.Errorf("got method %q, want %q", v.Method(), accesswire.VerificationMethodFingerprint)
	}
}

// Compile-time check that FingerprintVerifier satisfies Verifier.
var _ Verifier = (*FingerprintVerifier)(nil)
