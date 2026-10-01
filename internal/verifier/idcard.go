package verifier

import (
	"context"
	"fmt"
	"strings"

	"github.com/heainframework/heain-access/internal/accesswire"
	"github.com/heainframework/heain-access/internal/mlclient"
)

// extractFunc is the shape of the OCR call IDCardVerifier delegates to.
// Production code uses mlclient.ExtractText; tests inject a stub so they
// never need a real sidecar running.
type extractFunc func(ctx context.Context, sidecarURL, imageB64 string) (string, float64, error)

// IDCardVerifier implements the id_card Stage A verification method.
//
// Per the confirmed Stage A design, id_card's OCR step is real ML from the
// first commit, not a deterministic placeholder: text extraction from a
// photographed ID card is inherently non-deterministic (lighting, angle,
// print wear), so there is no honest deterministic stand-in the way there
// was for, say, video_conform. The sidecar does the OCR; IDCardVerifier's
// own job is the deterministic half -- comparing the extracted text against
// the caller-supplied expected ID number -- matching the project's
// established "ML for the non-deterministic part, plain Go for the rest"
// split.
type IDCardVerifier struct {
	sidecarURL string
	extract    extractFunc
}

// NewIDCardVerifier returns an IDCardVerifier that calls the OCR sidecar at
// sidecarURL (e.g. "http://localhost:9700").
func NewIDCardVerifier(sidecarURL string) *IDCardVerifier {
	return &IDCardVerifier{sidecarURL: sidecarURL, extract: mlclient.ExtractText}
}

func (v *IDCardVerifier) Method() accesswire.VerificationMethod {
	return accesswire.VerificationMethodIDCard
}

// Verify requires the evidence keys "id_card_image_b64" (the card image,
// base64-encoded) and "expected_id_number" (the ID number the recipient is
// expected to present, supplied by the caller from its own trusted context
// -- heain-access never originates this expectation itself, it only checks
// the card against it).
func (v *IDCardVerifier) Verify(ctx context.Context, in VerifyInput) (Result, error) {
	imageB64, ok := in.Evidence["id_card_image_b64"]
	if !ok || imageB64 == "" {
		return Result{}, fmt.Errorf("verifier: id_card evidence missing required key %q", "id_card_image_b64")
	}
	expected, ok := in.Evidence["expected_id_number"]
	if !ok || expected == "" {
		return Result{}, fmt.Errorf("verifier: id_card evidence missing required key %q", "expected_id_number")
	}

	text, confidence, err := v.extract(ctx, v.sidecarURL, imageB64)
	if err != nil {
		return Result{}, fmt.Errorf("verifier: id_card OCR failed: %w", err)
	}

	extractedDigits := onlyDigits(text)
	expectedDigits := onlyDigits(expected)

	if expectedDigits == "" || !strings.Contains(extractedDigits, expectedDigits) {
		return Denied("extracted ID card text did not contain the expected ID number"), nil
	}

	return Allowed(confidence), nil
}

// onlyDigits strips everything but digits, so an ID number can be compared
// regardless of how either side punctuates it (dashes, spaces).
func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
