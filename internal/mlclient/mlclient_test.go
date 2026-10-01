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

func TestEmbedFace_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/embed" {
			t.Errorf("got path %q, want /embed", r.URL.Path)
		}
		var req embedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if req.ImageB64 != "ZmFrZQ==" {
			t.Errorf("got image_b64 %q, want ZmFrZQ==", req.ImageB64)
		}
		_ = json.NewEncoder(w).Encode(embedResponse{
			FaceDetected: true,
			Embedding:    []float64{0.1, 0.2, 0.3},
			Confidence:   0.95,
		})
	}))
	defer srv.Close()

	embedding, detected, confidence, err := EmbedFace(context.Background(), srv.URL, "ZmFrZQ==")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !detected {
		t.Error("expected faceDetected to be true")
	}
	if len(embedding) != 3 {
		t.Errorf("got embedding length %d, want 3", len(embedding))
	}
	if confidence != 0.95 {
		t.Errorf("got confidence %v, want 0.95", confidence)
	}
}

func TestEmbedFace_NoFaceDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(embedResponse{FaceDetected: false})
	}))
	defer srv.Close()

	embedding, detected, _, err := EmbedFace(context.Background(), srv.URL, "ZmFrZQ==")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detected {
		t.Error("expected faceDetected to be false")
	}
	if len(embedding) != 0 {
		t.Errorf("expected an empty embedding when no face was detected, got %v", embedding)
	}
}

func TestEmbedFace_SidecarError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(embedResponse{Error: "model not loaded"})
	}))
	defer srv.Close()

	_, _, _, err := EmbedFace(context.Background(), srv.URL, "ZmFrZQ==")
	if err == nil {
		t.Fatal("expected an error when the sidecar returns a non-200 status, got nil")
	}
}

func TestEmbedFace_Unreachable(t *testing.T) {
	_, _, _, err := EmbedFace(context.Background(), "http://127.0.0.1:1", "ZmFrZQ==")
	if err == nil {
		t.Fatal("expected an error when the sidecar is unreachable, got nil")
	}
}

func TestMatchFingerprint_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/match" {
			t.Errorf("got path %q, want /match", r.URL.Path)
		}
		var req fingerprintRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if req.PresentedImageB64 != "cHJlc2VudGVk" {
			t.Errorf("got presented_image_b64 %q, want cHJlc2VudGVk", req.PresentedImageB64)
		}
		if req.EnrolledImageB64 != "ZW5yb2xsZWQ=" {
			t.Errorf("got enrolled_image_b64 %q, want ZW5yb2xsZWQ=", req.EnrolledImageB64)
		}
		_ = json.NewEncoder(w).Encode(fingerprintResponse{Score: 0.92})
	}))
	defer srv.Close()

	score, err := MatchFingerprint(context.Background(), srv.URL, "cHJlc2VudGVk", "ZW5yb2xsZWQ=")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 0.92 {
		t.Errorf("got score %v, want 0.92", score)
	}
}

func TestMatchFingerprint_SidecarError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(fingerprintResponse{Error: "engine not loaded"})
	}))
	defer srv.Close()

	_, err := MatchFingerprint(context.Background(), srv.URL, "cHJlc2VudGVk", "ZW5yb2xsZWQ=")
	if err == nil {
		t.Fatal("expected an error when the sidecar returns a non-200 status, got nil")
	}
}

func TestMatchFingerprint_Unreachable(t *testing.T) {
	_, err := MatchFingerprint(context.Background(), "http://127.0.0.1:1", "cHJlc2VudGVk", "ZW5yb2xsZWQ=")
	if err == nil {
		t.Fatal("expected an error when the sidecar is unreachable, got nil")
	}
}
