package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/heainframework/heain-access/internal/accesswire"
)

func stubEmbedder(embeddings map[string][]float64, detected map[string]bool) embedFunc {
	return func(ctx context.Context, sidecarURL, imageB64 string) ([]float64, bool, float64, error) {
		return embeddings[imageB64], detected[imageB64], 0.9, nil
	}
}

func TestFaceVerifier_Match(t *testing.T) {
	v := &FaceVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFaceMatchThreshold,
		embed: stubEmbedder(
			map[string][]float64{
				"presented-img": {1, 0, 0},
				"enrolled-img":  {1, 0, 0},
			},
			map[string]bool{"presented-img": true, "enrolled-img": true},
		),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"face_image_b64":     "presented-img",
			"enrolled_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Error("expected Allow to be true for identical embeddings")
	}
	if res.Confidence < 0.999 {
		t.Errorf("got confidence %v, want ~1.0 for identical embeddings", res.Confidence)
	}
}

func TestFaceVerifier_Mismatch(t *testing.T) {
	v := &FaceVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFaceMatchThreshold,
		embed: stubEmbedder(
			map[string][]float64{
				"presented-img": {1, 0, 0},
				"enrolled-img":  {0, 1, 0},
			},
			map[string]bool{"presented-img": true, "enrolled-img": true},
		),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"face_image_b64":     "presented-img",
			"enrolled_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false for orthogonal (dissimilar) embeddings")
	}
	if res.Reason == "" {
		t.Error("expected a non-empty Reason on denial")
	}
}

func TestFaceVerifier_NoFaceInPresented(t *testing.T) {
	v := &FaceVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFaceMatchThreshold,
		embed: stubEmbedder(
			map[string][]float64{"enrolled-img": {1, 0, 0}},
			map[string]bool{"presented-img": false, "enrolled-img": true},
		),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"face_image_b64":     "presented-img",
			"enrolled_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false when no face is detected in the presented image")
	}
}

func TestFaceVerifier_NoFaceInEnrolled(t *testing.T) {
	v := &FaceVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFaceMatchThreshold,
		embed: stubEmbedder(
			map[string][]float64{"presented-img": {1, 0, 0}},
			map[string]bool{"presented-img": true, "enrolled-img": false},
		),
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"face_image_b64":     "presented-img",
			"enrolled_image_b64": "enrolled-img",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false when no face is detected in the enrolled image")
	}
}

func TestFaceVerifier_MissingPresentedEvidence(t *testing.T) {
	v := NewFaceVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"enrolled_image_b64": "x"},
	})
	if err == nil {
		t.Fatal("expected an error when face_image_b64 evidence is missing, got nil")
	}
}

func TestFaceVerifier_MissingEnrolledEvidence(t *testing.T) {
	v := NewFaceVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"face_image_b64": "x"},
	})
	if err == nil {
		t.Fatal("expected an error when enrolled_image_b64 evidence is missing, got nil")
	}
}

func TestFaceVerifier_EmbeddingError(t *testing.T) {
	v := &FaceVerifier{
		sidecarURL: "http://unused",
		threshold:  DefaultFaceMatchThreshold,
		embed: func(ctx context.Context, sidecarURL, imageB64 string) ([]float64, bool, float64, error) {
			return nil, false, 0, errors.New("sidecar unreachable")
		},
	}
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"face_image_b64":     "presented-img",
			"enrolled_image_b64": "enrolled-img",
		},
	})
	if err == nil {
		t.Fatal("expected an error when the face sidecar call fails, got nil")
	}
}

func TestFaceVerifier_Method(t *testing.T) {
	v := NewFaceVerifier("http://unused")
	if v.Method() != accesswire.VerificationMethodFace {
		t.Errorf("got method %q, want %q", v.Method(), accesswire.VerificationMethodFace)
	}
}

func TestCosineSimilarity_LengthMismatch(t *testing.T) {
	_, err := cosineSimilarity([]float64{1, 2}, []float64{1, 2, 3})
	if err == nil {
		t.Fatal("expected an error for mismatched embedding lengths, got nil")
	}
}

func TestCosineSimilarity_ZeroMagnitude(t *testing.T) {
	_, err := cosineSimilarity([]float64{0, 0, 0}, []float64{1, 2, 3})
	if err == nil {
		t.Fatal("expected an error for a zero-magnitude embedding, got nil")
	}
}

// Compile-time check that FaceVerifier satisfies Verifier.
var _ Verifier = (*FaceVerifier)(nil)
