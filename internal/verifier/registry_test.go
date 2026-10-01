package verifier

import (
	"context"
	"testing"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// fakeVerifier is a minimal Verifier for exercising the Registry and the
// Verifier interface shape, without any real evidence-checking logic.
type fakeVerifier struct {
	method accesswire.VerificationMethod
	result Result
	err    error
}

func (f fakeVerifier) Method() accesswire.VerificationMethod { return f.method }

func (f fakeVerifier) Verify(ctx context.Context, in VerifyInput) (Result, error) {
	return f.result, f.err
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	fv := fakeVerifier{method: accesswire.VerificationMethodKeycard, result: Allowed(0)}

	if err := r.Register(fv); err != nil {
		t.Fatalf("unexpected error registering: %v", err)
	}

	got, err := r.Get(accesswire.VerificationMethodKeycard)
	if err != nil {
		t.Fatalf("unexpected error getting: %v", err)
	}
	if got.Method() != accesswire.VerificationMethodKeycard {
		t.Errorf("got method %q, want %q", got.Method(), accesswire.VerificationMethodKeycard)
	}
}

func TestRegistry_DuplicateRegistration(t *testing.T) {
	r := NewRegistry()
	fv := fakeVerifier{method: accesswire.VerificationMethodFace}

	if err := r.Register(fv); err != nil {
		t.Fatalf("unexpected error on first registration: %v", err)
	}
	if err := r.Register(fv); err == nil {
		t.Fatal("expected error registering a second Verifier for the same method, got nil")
	}
}

func TestRegistry_RegisterUnknownMethod(t *testing.T) {
	r := NewRegistry()
	fv := fakeVerifier{method: "quantum_retina_scan"}

	if err := r.Register(fv); err == nil {
		t.Fatal("expected error registering an unknown verification_method, got nil")
	}
}

func TestRegistry_GetMissing(t *testing.T) {
	r := NewRegistry()

	if _, err := r.Get(accesswire.VerificationMethodIDCard); err == nil {
		t.Fatal("expected error getting an unregistered method, got nil")
	}
}

func TestVerifier_Verify(t *testing.T) {
	fv := fakeVerifier{
		method: accesswire.VerificationMethodFingerprint,
		result: Allowed(0.97),
	}

	res, err := fv.Verify(context.Background(), VerifyInput{
		Recipient: "projector-01",
		AssetRef:  "dcp://feature-xyz",
		Evidence:  map[string]string{"template_ref": "fp-template-001"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allow {
		t.Error("expected Allow to be true")
	}
	if res.Confidence != 0.97 {
		t.Errorf("got confidence %v, want 0.97", res.Confidence)
	}
}

func TestDenied(t *testing.T) {
	res := Denied("uid not on ACL")
	if res.Allow {
		t.Error("expected Allow to be false")
	}
	if res.Reason != "uid not on ACL" {
		t.Errorf("got reason %q, want %q", res.Reason, "uid not on ACL")
	}
}
