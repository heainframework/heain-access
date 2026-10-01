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

// DefaultTimeout is generous for CPU-only inference (OCR included), matching
// the convention already used by heain-image's own mlclient package.
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
