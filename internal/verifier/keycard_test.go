package verifier

import (
	"context"
	"testing"

	"github.com/heainframework/heain-access/internal/accesswire"
)

func TestKeycardVerifier_AllowedUID(t *testing.T) {
	v := NewKeycardVerifier([]string{"uid-001", "uid-002"})

	res, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://feature-xyz",
		Evidence:  map[string]string{"keycard_uid": "uid-001"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Error("expected Allow to be true for a UID on the ACL")
	}
}

func TestKeycardVerifier_DeniedUID(t *testing.T) {
	v := NewKeycardVerifier([]string{"uid-001"})

	res, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://feature-xyz",
		Evidence:  map[string]string{"keycard_uid": "uid-999"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false for a UID not on the ACL")
	}
	if res.Reason == "" {
		t.Error("expected a non-empty Reason on denial")
	}
}

func TestKeycardVerifier_MissingEvidence(t *testing.T) {
	v := NewKeycardVerifier([]string{"uid-001"})

	_, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://feature-xyz",
		Evidence:  map[string]string{},
	})
	if err == nil {
		t.Fatal("expected an error when keycard_uid evidence is missing, got nil")
	}
}

func TestKeycardVerifier_EmptyACL(t *testing.T) {
	v := NewKeycardVerifier(nil)

	res, err := v.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://feature-xyz",
		Evidence:  map[string]string{"keycard_uid": "uid-001"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Error("expected Allow to be false when the ACL is empty")
	}
}

func TestKeycardVerifier_Method(t *testing.T) {
	v := NewKeycardVerifier(nil)
	if v.Method() != accesswire.VerificationMethodKeycard {
		t.Errorf("got method %q, want %q", v.Method(), accesswire.VerificationMethodKeycard)
	}
}

// Compile-time check that KeycardVerifier satisfies Verifier.
var _ Verifier = (*KeycardVerifier)(nil)
