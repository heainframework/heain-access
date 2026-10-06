// Package sidecar is heain-access's client for its AI sidecars (manifest
// ai_sidecars, contract heain-sidecar/v1, local_only): plain HTTP+JSON on
// localhost, one process per model, run however the operator likes.
//
//	OCR (EasyOCR)        POST /extract        {"image_b64"} -> {"text","confidence"}
//	face (InsightFace)   POST /embed          {"image_b64"} -> {"face_detected","embedding","confidence"}
//	fingerprint (NBIS)   POST /template       {"image_b64"} -> {"template_b64"}
//	                     POST /match_template {"image_b64","template_b64"} -> {"score"}
//	every sidecar        GET  /info           -> {"model": {"name","version","sha256"}}
//
// /info's sha256 identifies the weights actually loaded; heain-access puts it
// in every reasoning record (spec 04: a model hash).
//
// Images go to the sidecar on the same host only and are never stored;
// only face embeddings and fingerprint templates are kept (sealed).
package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ErrNotConfigured: the sidecar for this method has no URL.
var ErrNotConfigured = errors.New("sidecar: not configured")

// Client calls the three sidecars.
type Client struct {
	OCR, Face, Finger string
	HTTP              *http.Client

	mu   sync.Mutex
	info map[string]string // base URL -> model sha256
}

// ModelSHA256 returns the model hash a sidecar reports on GET /info
// (cached once known).
func (c *Client) ModelSHA256(ctx context.Context, base string) (string, error) {
	if base == "" {
		return "", ErrNotConfigured
	}
	c.mu.Lock()
	h, ok := c.info[base]
	c.mu.Unlock()
	if ok {
		return h, nil
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/info", nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("sidecar /info: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Model struct {
			SHA256 string `json:"sha256"`
		} `json:"model"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil || len(out.Model.SHA256) != 64 {
		return "", fmt.Errorf("sidecar %s/info gave no model sha256 (HTTP %d)", base, resp.StatusCode)
	}
	c.mu.Lock()
	if c.info == nil {
		c.info = map[string]string{}
	}
	c.info[base] = out.Model.SHA256
	c.mu.Unlock()
	return out.Model.SHA256, nil
}

func (c *Client) post(ctx context.Context, base, path string, in, out any) error {
	if base == "" {
		return ErrNotConfigured
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	b, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("sidecar %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &e)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sidecar %s: HTTP %d %s", path, resp.StatusCode, e.Error)
	}
	if e.Error != "" {
		return fmt.Errorf("sidecar %s: %s", path, e.Error)
	}
	return json.Unmarshal(data, out)
}

// ExtractText runs OCR on an image.
func (c *Client) ExtractText(ctx context.Context, img []byte) (string, float64, error) {
	var out struct {
		Text       string  `json:"text"`
		Confidence float64 `json:"confidence"`
	}
	err := c.post(ctx, c.OCR, "/extract", map[string]any{"image_b64": img}, &out)
	return out.Text, out.Confidence, err
}

// EmbedFace returns the face embedding of an image (normalized).
func (c *Client) EmbedFace(ctx context.Context, img []byte) ([]float64, bool, float64, error) {
	var out struct {
		Detected   bool      `json:"face_detected"`
		Embedding  []float64 `json:"embedding"`
		Confidence float64   `json:"confidence"`
	}
	err := c.post(ctx, c.Face, "/embed", map[string]any{"image_b64": img}, &out)
	return out.Embedding, out.Detected, out.Confidence, err
}

// FingerTemplate extracts a fingerprint template (minutiae) from an image.
func (c *Client) FingerTemplate(ctx context.Context, img []byte) ([]byte, error) {
	var out struct {
		Template []byte `json:"template_b64"`
	}
	err := c.post(ctx, c.Finger, "/template", map[string]any{"image_b64": img}, &out)
	if err == nil && len(out.Template) == 0 {
		err = errors.New("sidecar /template: no template (no fingerprint found)")
	}
	return out.Template, err
}

// FingerMatch scores an image against an enrolled template (0..1).
func (c *Client) FingerMatch(ctx context.Context, img, tmpl []byte) (float64, error) {
	var out struct {
		Score float64 `json:"score"`
	}
	err := c.post(ctx, c.Finger, "/match_template", map[string]any{"image_b64": img, "template_b64": tmpl}, &out)
	return out.Score, err
}
