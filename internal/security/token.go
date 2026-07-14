package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// randomToken returns n random bytes base64url encoded (unpadded). It is the
// shared primitive behind every opaque secret this service generates: the
// activation token and the discard password stored for a pending or
// gRPC-provisioned user, so every such secret shares one random source and
// encoding.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateActivationToken returns a fresh 256-bit (32 byte) raw activation
// token plus its sha256 lookup hash. The raw value is returned exactly once
// and is never persisted or logged; only the hash is stored. 32 bytes
// base64url encodes to a 43 character string.
func GenerateActivationToken() (raw string, hash []byte, err error) {
	raw, err = randomToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("security.GenerateActivationToken: %w", err)
	}
	return raw, HashToken(raw), nil
}

// HashToken returns the deterministic sha256 lookup hash for a raw token. The
// activate endpoint resolves a credential_tokens row by this hash; the raw
// value itself is never stored.
func HashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// RandomUnusablePassword returns a cryptographically random string suitable as
// the bcrypt input for an account that must not be logged into with any known
// secret (a pending activation user, or a gRPC provisioned temporary
// password). It is never returned to any caller.
func RandomUnusablePassword() (string, error) {
	s, err := randomToken(24)
	if err != nil {
		return "", fmt.Errorf("security.RandomUnusablePassword: %w", err)
	}
	return s, nil
}
