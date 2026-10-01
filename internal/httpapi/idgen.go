package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newGrantID returns a fresh, unpredictable grant ID. It uses
// crypto/rand rather than math/rand because a guessable grant ID would
// let an attacker probe /verify-grant for valid IDs.
func newGrantID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("httpapi: generating grant id: %w", err)
	}
	return "grant-" + hex.EncodeToString(b[:]), nil
}
