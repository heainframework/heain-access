// Package mlclient calls heain-access's Python ML sidecars over plain HTTP,
// mirroring the sidecar-client pattern already established by heain-image
// and heain-videos: the model itself lives in a small Python service, and
// this package is the thin Go-side bridge to it.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout is generous for CPU-only inference (OCR, face embedding
// included), matching the convention already used by heain-image's own
// mlclient package.
const DefaultTimeout = 60 * time.Second

type ocrRequest struct {
	ImageB64 string `json:"image_b64"`
}

type ocrResponse struct {
	Text       string  `json:"text"`
	Confidence float64 `json:"confidence"`
	Error      string  `json:"error"`
}

// ExtractText calls the OCR sidecar's POST /extract endpoint and returns
// the recognized text plus the sidecar's own average per-detection
// confidence score, in [0,1].
func ExtractText(ctx context.Context, sidecarURL, imageB64 string) (string, float64, error) {
	reqBody, err := json.Marshal(ocrRequest{ImageB64: imageB64})
	if err != nil {
		return "", 0, fmt.Errorf("mlclient: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL+"/extract", bytes.NewReader(reqBody))
	if err != nil {
		return "", 0, fmt.Errorf("mlclient: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("mlclient: calling OCR sidecar: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("mlclient: reading OCR sidecar response: %w", err)
	}

	var out ocrResponse
	if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
		return "", 0, fmt.Errorf("mlclient: decoding OCR sidecar response: %w", jsonErr)
	}

	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return "", 0, fmt.Errorf("mlclient: OCR sidecar error: %s", out.Error)
		}
		return "", 0, fmt.Errorf("mlclient: OCR sidecar returned HTTP %d", resp.StatusCode)
	}

	return out.Text, out.Confidence, nil
}

type embedRequest struct {
	ImageB64 string `json:"image_b64"`
}

type embedResponse struct {
	FaceDetected bool      `json:"face_detected"`
	Embedding    []float64 `json:"embedding"`
	Confidence   float64   `json:"confidence"`
	Error        string    `json:"error"`
}

// EmbedFace calls the face sidecar's POST /embed endpoint. It returns
// faceDetected=false (with a nil embedding, no error) when the sidecar ran
// successfully but found no face in the image -- that is a normal outcome
// for bad evidence, not a failure to evaluate it. embedding is the raw
// face-recognition embedding vector (model-specific length; heain-access's
// FaceVerifier only ever compares two embeddings produced by the same
// sidecar, so it never needs to know the length itself). confidence is the
// sidecar's own face-detection confidence, in [0,1].
func EmbedFace(ctx context.Context, sidecarURL, imageB64 string) (embedding []float64, faceDetected bool, confidence float64, err error) {
	reqBody, err := json.Marshal(embedRequest{ImageB64: imageB64})
	if err != nil {
		return nil, false, 0, fmt.Errorf("mlclient: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL+"/embed", bytes.NewReader(reqBody))
	if err != nil {
		return nil, false, 0, fmt.Errorf("mlclient: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, false, 0, fmt.Errorf("mlclient: calling face sidecar: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, 0, fmt.Errorf("mlclient: reading face sidecar response: %w", err)
	}

	var out embedResponse
	if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
		return nil, false, 0, fmt.Errorf("mlclient: decoding face sidecar response: %w", jsonErr)
	}

	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, false, 0, fmt.Errorf("mlclient: face sidecar error: %s", out.Error)
		}
		return nil, false, 0, fmt.Errorf("mlclient: face sidecar returned HTTP %d", resp.StatusCode)
	}

	return out.Embedding, out.FaceDetected, out.Confidence, nil
}

type fingerprintRequest struct {
	PresentedImageB64 string `json:"presented_image_b64"`
	EnrolledImageB64  string `json:"enrolled_image_b64"`
}

type fingerprintResponse struct {
	Score float64 `json:"score"`
	Error string  `json:"error"`
}

// MatchFingerprint calls the fingerprint sidecar's POST /match endpoint,
// which wraps a production-grade fingerprint matching engine (SourceAFIS)
// rather than a toy feature-matcher, per the user's explicit requirement.
// It returns the engine's raw match score: an unbounded, non-negative
// number where SourceAFIS's own documentation treats roughly 40+ as a
// genuine match at a practical false-match rate. Score normalization and
// thresholding are the caller's (FingerprintVerifier's) job, not the
// sidecar's -- matching the same "ML for the non-deterministic part,
// deterministic Go for the rest" split already used by id_card and face.
func MatchFingerprint(ctx context.Context, sidecarURL, presentedImageB64, enrolledImageB64 string) (float64, error) {
	reqBody, err := json.Marshal(fingerprintRequest{
		PresentedImageB64: presentedImageB64,
		EnrolledImageB64:  enrolledImageB64,
	})
	if err != nil {
		return 0, fmt.Errorf("mlclient: encoding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, sidecarURL+"/match", bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("mlclient: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("mlclient: calling fingerprint sidecar: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("mlclient: reading fingerprint sidecar response: %w", err)
	}

	var out fingerprintResponse
	if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
		return 0, fmt.Errorf("mlclient: decoding fingerprint sidecar response: %w", jsonErr)
	}

	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return 0, fmt.Errorf("mlclient: fingerprint sidecar error: %s", out.Error)
		}
		return 0, fmt.Errorf("mlclient: fingerprint sidecar returned HTTP %d", resp.StatusCode)
	}

	return out.Score, nil
}
