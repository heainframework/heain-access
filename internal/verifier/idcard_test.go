package verifier

import (
	"context"
	"errors"
	"testing"

	"github.com/heainframework/heain-access/internal/accesswire"
)

func TestIDCardVerifier_Match(t *testing.T) {
	v := &IDCardVerifier{
		sidecarURL: "http://unused",
		extract: func(ctx context.Context, sidecarURL, imageB64 string) (string, float64, error) {
			return "NAME: SOMCHAI ID: 1-2345-67890-12-3", 0.93, nil
		},
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://demo",
		Evidence: map[string]string{
			"id_card_image_b64":  "ZmFrZQ==",
			"expected_id_number": "1234567890123",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Error("expected Allow to be true when the expected ID number appears in the OCR text")
	}
	if res.Confidence != 0.93 {
		t.Errorf("got confidence %v, want 0.93", res.Confidence)
	}
}

func TestIDCardVerifier_Mismatch(t *testing.T) {
	v := &IDCardVerifier{
		sidecarURL: "http://unused",
		extract: func(ctx context.Context, sidecarURL, imageB64 string) (string, float64, error) {
			return "NAME: SOMCHAI ID: 9-9999-99999-99-9", 0.90, nil
		},
	}

	res, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://demo",
		Evidence: map[string]string{
			"id_card_image_b64":  "ZmFrZQ==",
			"expected_id_number": "1234567890123",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false when the expected ID number is absent from the OCR text")
	}
	if res.Reason == "" {
		t.Error("expected a non-empty Reason on denial")
	}
}

func TestIDCardVerifier_MissingImage(t *testing.T) {
	v := NewIDCardVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"expected_id_number": "1234567890123"},
	})
	if err == nil {
		t.Fatal("expected an error when id_card_image_b64 evidence is missing, got nil")
	}
}

func TestIDCardVerifier_MissingExpected(t *testing.T) {
	v := NewIDCardVerifier("http://unused")
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{"id_card_image_b64": "ZmFrZQ=="},
	})
	if err == nil {
		t.Fatal("expected an error when expected_id_number evidence is missing, got nil")
	}
}

func TestIDCardVerifier_OCRError(t *testing.T) {
	v := &IDCardVerifier{
		sidecarURL: "http://unused",
		extract: func(ctx context.Context, sidecarURL, imageB64 string) (string, float64, error) {
			return "", 0, errors.New("sidecar unreachable")
		},
	}
	_, err := v.Verify(context.Background(), VerifyInput{
		Evidence: map[string]string{
			"id_card_image_b64":  "ZmFrZQ==",
			"expected_id_number": "1234567890123",
		},
	})
	if err == nil {
		t.Fatal("expected an error when the OCR sidecar call fails, got nil")
	}
}

func TestIDCardVerifier_Method(t *testing.T) {
	v := NewIDCardVerifier("http://unused")
	if v.Method() != accesswire.VerificationMethodIDCard {
		t.Errorf("got method %q, want %q", v.Method(), accesswire.VerificationMethodIDCard)
	}
}

// Compile-time check that IDCardVerifier satisfies Verifier.
var _ Verifier = (*IDCardVerifier)(nil)
