package verifier

import (
	"context"
	"fmt"

	"github.com/heainframework/heain-access/internal/accesswire"
)

// KeycardVerifier implements the keycard Stage A verification method.
//
// Per the confirmed design, keycard is the one exception among the five
// Stage A methods: its Allow decision stays a genuinely deterministic
// hard ACL/UID-list check — a card not on the ACL is never granted
// access, full stop. A model-backed anomaly/risk signal is meant to be
// layered alongside as an advisory-only second signal that never
// overrides the hard deny; that model has not been chosen yet, so
// AnomalyScore is left at its zero value here until it is wired in.
type KeycardVerifier struct {
	acl map[string]bool // keycard UID -> allowed
}

// NewKeycardVerifier returns a KeycardVerifier whose ACL is exactly the
// given set of allowed keycard UIDs.
func NewKeycardVerifier(allowedUIDs []string) *KeycardVerifier {
	acl := make(map[string]bool, len(allowedUIDs))
	for _, uid := range allowedUIDs {
		acl[uid] = true
	}
	return &KeycardVerifier{acl: acl}
}

func (v *KeycardVerifier) Method() accesswire.VerificationMethod {
	return accesswire.VerificationMethodKeycard
}

// Verify requires the evidence key "keycard_uid". It returns an error
// (not a Result) when that key is missing, since that is a malformed
// request rather than a genuine ACL miss.
func (v *KeycardVerifier) Verify(ctx context.Context, in VerifyInput) (Result, error) {
	uid, ok := in.Evidence["keycard_uid"]
	if !ok || uid == "" {
		return Result{}, fmt.Errorf("verifier: keycard evidence missing required key %q", "keycard_uid")
	}

	if !v.acl[uid] {
		return Denied(fmt.Sprintf("keycard uid %q is not on the ACL", uid)), nil
	}

	return Allowed(0), nil
}
