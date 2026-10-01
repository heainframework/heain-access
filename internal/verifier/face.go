package verifier

import (
	"context"
	"fmt"
	"math"

	"github.com/heainframework/heain-access/internal/accesswire"
	"github.com/heainframework/heain-access/internal/mlclient"
)

// DefaultFaceMatchThreshold is the minimum cosine similarity between two
// face embeddings for FaceVerifier to Allow. It is a Stage A starting
// point, not a calibrated production value -- real threshold tuning needs
// a labeled dataset of genuine/impostor pairs, which doesn't exist yet.
const DefaultFaceMatchThreshold = 0.5

// embedFunc is the shape of the face-embedding call FaceVerifier delegates
// to. Production code uses mlclient.EmbedFace; tests inject a stub so they
// never need a real sidecar running.
type embedFunc func(ctx context.Context, sidecarURL, imageB64 string) (embedding []float64, faceDetected bool, confidence float64, err error)

// FaceVerifier implements the face Stage A verification method.
//
// Per the same "ML for the inherently non-deterministic part, deterministic
// Go for the rest" split already used by id_card: the sidecar does face
// detection and produces an embedding for each image (real ML, no
// deterministic placeholder -- there is no honest deterministic stand-in
// for "do these two faces belong to the same person"); FaceVerifier's own
// job is the deterministic half -- computing cosine similarity between the
// two embeddings and comparing it against Threshold.
//
// Stage A has no persistent enrollment store (mirrors keycard's and
// id_card's own Stage A simplifications), so the caller supplies the
// enrolled reference image directly as evidence on every call, rather than
// heain-access looking up a previously-enrolled embedding by Recipient.
type FaceVerifier struct {
	sidecarURL string
	embed      embedFunc
	threshold  float64
}

// NewFaceVerifier returns a FaceVerifier that calls the face sidecar at
// sidecarURL (e.g. "http://localhost:9701") and Allows at
// DefaultFaceMatchThreshold.
func NewFaceVerifier(sidecarURL string) *FaceVerifier {
	return &FaceVerifier{sidecarURL: sidecarURL, embed: mlclient.EmbedFace, threshold: DefaultFaceMatchThreshold}
}

func (v *FaceVerifier) Method() accesswire.VerificationMethod {
	return accesswire.VerificationMethodFace
}

// Verify requires the evidence keys "face_image_b64" (the presented live
// face image, base64-encoded) and "enrolled_image_b64" (a reference image
// of the recipient the caller expects, also base64-encoded, supplied from
// the caller's own trusted context).
func (v *FaceVerifier) Verify(ctx context.Context, in VerifyInput) (Result, error) {
	presented, ok := in.Evidence["face_image_b64"]
	if !ok || presented == "" {
		return Result{}, fmt.Errorf("verifier: face evidence missing required key %q", "face_image_b64")
	}
	enrolled, ok := in.Evidence["enrolled_image_b64"]
	if !ok || enrolled == "" {
		return Result{}, fmt.Errorf("verifier: face evidence missing required key %q", "enrolled_image_b64")
	}

	presentedEmbedding, presentedDetected, _, err := v.embed(ctx, v.sidecarURL, presented)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: face embedding (presented image) failed: %w", err)
	}
	if !presentedDetected {
		return Denied("no face detected in the presented image"), nil
	}

	enrolledEmbedding, enrolledDetected, _, err := v.embed(ctx, v.sidecarURL, enrolled)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: face embedding (enrolled image) failed: %w", err)
	}
	if !enrolledDetected {
		return Denied("no face detected in the enrolled reference image"), nil
	}

	similarity, err := cosineSimilarity(presentedEmbedding, enrolledEmbedding)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: comparing face embeddings: %w", err)
	}

	if similarity < v.threshold {
		return Denied(fmt.Sprintf("face similarity %.4f is below the match threshold %.4f", similarity, v.threshold)), nil
	}

	return Allowed(similarity), nil
}

// cosineSimilarity returns the cosine similarity between two equal-length
// vectors, in [-1,1]. It errors on a length mismatch or a zero-length
// vector, both of which indicate the sidecar returned something
// FaceVerifier cannot meaningfully compare.
func cosineSimilarity(a, b []float64) (float64, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("embedding length mismatch: %d vs %d", len(a), len(b))
	}
	if len(a) == 0 {
		return 0, fmt.Errorf("empty embedding")
	}

	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0, fmt.Errorf("zero-magnitude embedding")
	}

	return dot / (math.Sqrt(normA) * math.Sqrt(normB)), nil
}
