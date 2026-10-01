package mlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractText_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/extract" {
			t.Errorf("got path %q, want /extract", r.URL.Path)
		}
		var req ocrRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if req.ImageB64 != "ZmFrZQ==" {
			t.Errorf("got image_b64 %q, want ZmFrZQ==", req.ImageB64)
		}
		_ = json.NewEncoder(w).Encode(ocrResponse{Text: "hello", Confidence: 0.87})
	}))
	defer srv.Close()

	text, confidence, err := ExtractText(context.Background(), srv.URL, "ZmFrZQ==")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if text != "hello" {
		t.Errorf("got text %q, want hello", text)
	}
	if confidence != 0.87 {
		t.Errorf("got confidence %v, want 0.87", confidence)
	}
}

func TestExtractText_SidecarError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(ocrResponse{Error: "model not loaded"})
	}))
	defer srv.Close()

	_, _, err := ExtractText(context.Background(), srv.URL, "ZmFrZQ==")
	if err == nil {
		t.Fatal("expected an error when the sidecar returns a non-200 status, got nil")
	}
}

func TestExtractText_Unreachable(t *testing.T) {
	_, _, err := ExtractText(context.Background(), "http://127.0.0.1:1", "ZmFrZQ==")
	if err == nil {
		t.Fatal("expected an error when the sidecar is unreachable, got nil")
	}
}
