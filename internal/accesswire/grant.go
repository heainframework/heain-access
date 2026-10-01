// Package accesswire defines the wire types exchanged between heain-access
// and its callers (e.g. heain-mastering at DCP-build time), and persisted by
// heain-access's own store. It plays the same structural role for
// heain-access that internal/jobwire plays for heain-job.
package accesswire

import (
	"fmt"
	"time"
)

// VerificationMethod identifies which Verifier produced or will produce an
// AccessGrant. Stage A supports five methods; the set is expected to grow,
// so callers should treat unknown values as a validation error rather than
// a zero-value default.
type VerificationMethod string

const (
	VerificationMethodIDCard      VerificationMethod = "id_card"
	VerificationMethodFace        VerificationMethod = "face"
	VerificationMethodFingerprint VerificationMethod = "fingerprint"
	VerificationMethodKeycard     VerificationMethod = "keycard"
	VerificationMethodDCPKey      VerificationMethod = "dcp_key"
)

// Valid reports whether m is one of the known Stage A verification methods.
func (m VerificationMethod) Valid() bool {
	switch m {
	case VerificationMethodIDCard, VerificationMethodFace, VerificationMethodFingerprint,
		VerificationMethodKeycard, VerificationMethodDCPKey:
		return true
	default:
		return false
	}
}

// AccessGrant is the generic unit of authorization issued by heain-access.
// It deliberately carries no cryptographic material of its own (no embedded
// key, no SMPTE/KDM trust-domain binding) — that belongs to a later,
// method-specific extension once heain-mastering's DCP work needs real
// DCI/SMPTE KDM binding. Stage A ships the generic shape only.
type AccessGrant struct {
	ID                 string             `json:"id"`
	Recipient          string             `json:"recipient"`
	AssetRef           string             `json:"asset_ref"`
	ValidFrom          time.Time          `json:"valid_from"`
	ValidUntil         time.Time          `json:"valid_until"`
	VerificationMethod VerificationMethod `json:"verification_method"`
	IssuedAt           time.Time          `json:"issued_at"`
}

// Validate checks the grant's own invariants (not whether it is currently
// valid in time — see IsValidAt for that). It does not check Recipient or
// AssetRef against any external registry; that is the store's job.
func (g AccessGrant) Validate() error {
	if g.Recipient == "" {
		return fmt.Errorf("accesswire: recipient must not be empty")
	}
	if g.AssetRef == "" {
		return fmt.Errorf("accesswire: asset_ref must not be empty")
	}
	if !g.VerificationMethod.Valid() {
		return fmt.Errorf("accesswire: unknown verification_method %q", g.VerificationMethod)
	}
	if !g.ValidUntil.After(g.ValidFrom) {
		return fmt.Errorf("accesswire: valid_until (%s) must be after valid_from (%s)",
			g.ValidUntil, g.ValidFrom)
	}
	return nil
}

// IsValidAt reports whether the grant is in force at time t: t is within
// [ValidFrom, ValidUntil). ValidUntil is exclusive so a grant's last valid
// instant is unambiguous.
func (g AccessGrant) IsValidAt(t time.Time) bool {
	return !t.Before(g.ValidFrom) && t.Before(g.ValidUntil)
}
