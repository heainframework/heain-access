package accesswire

import (
	"testing"
	"time"
)

func validGrant() AccessGrant {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	return AccessGrant{
		ID:                 "grant-1",
		Recipient:          "projector-01",
		AssetRef:           "dcp://feature-xyz",
		ValidFrom:          now,
		ValidUntil:         now.Add(72 * time.Hour),
		VerificationMethod: VerificationMethodKeycard,
		IssuedAt:           now,
	}
}

func TestAccessGrant_Validate_OK(t *testing.T) {
	g := validGrant()
	if err := g.Validate(); err != nil {
		t.Fatalf("expected valid grant, got error: %v", err)
	}
}

func TestAccessGrant_Validate_EmptyRecipient(t *testing.T) {
	g := validGrant()
	g.Recipient = ""
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for empty recipient, got nil")
	}
}

func TestAccessGrant_Validate_EmptyAssetRef(t *testing.T) {
	g := validGrant()
	g.AssetRef = ""
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for empty asset_ref, got nil")
	}
}

func TestAccessGrant_Validate_UnknownMethod(t *testing.T) {
	g := validGrant()
	g.VerificationMethod = "quantum_retina_scan"
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for unknown verification_method, got nil")
	}
}

func TestAccessGrant_Validate_BadWindow(t *testing.T) {
	g := validGrant()
	g.ValidUntil = g.ValidFrom
	if err := g.Validate(); err == nil {
		t.Fatal("expected error for non-positive validity window, got nil")
	}
}

func TestAccessGrant_IsValidAt(t *testing.T) {
	g := validGrant()

	before := g.ValidFrom.Add(-time.Minute)
	if g.IsValidAt(before) {
		t.Error("expected grant to be invalid before ValidFrom")
	}

	middle := g.ValidFrom.Add(time.Hour)
	if !g.IsValidAt(middle) {
		t.Error("expected grant to be valid inside the window")
	}

	atStart := g.ValidFrom
	if !g.IsValidAt(atStart) {
		t.Error("expected grant to be valid exactly at ValidFrom (inclusive)")
	}

	atEnd := g.ValidUntil
	if g.IsValidAt(atEnd) {
		t.Error("expected grant to be invalid exactly at ValidUntil (exclusive)")
	}
}

func TestVerificationMethod_Valid(t *testing.T) {
	valid := []VerificationMethod{
		VerificationMethodIDCard,
		VerificationMethodFace,
		VerificationMethodFingerprint,
		VerificationMethodKeycard,
		VerificationMethodDCPKey,
	}
	for _, m := range valid {
		if !m.Valid() {
			t.Errorf("expected %q to be valid", m)
		}
	}

	if VerificationMethod("bogus").Valid() {
		t.Error("expected unknown method to be invalid")
	}
}
