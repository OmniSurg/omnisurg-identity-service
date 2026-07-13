package security

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns a bcrypt hash at the default cost.
func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("security.HashPassword: %w", err)
	}
	return string(h), nil
}

// VerifyPassword reports whether plain matches the bcrypt hash. A malformed
// hash returns false rather than an error so callers treat it as a mismatch.
func VerifyPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// dummyHash is a valid bcrypt hash of a random string, used to spend the same
// bcrypt cost on the not-found login path as a real compare, so response
// latency does not reveal whether an email exists (HG-B3). It is generated at
// bcrypt.DefaultCost so its cost matches HashPassword.
const dummyHash = "$2a$10$TQkYMTQsDLVkxSQ4WpGrou7Sk8YMwado5bPq0EvgjN95iGe2/Ohdm"

// DummyPasswordCompare runs a bcrypt compare against a constant hash and always
// returns false. Call it on the not-found auth path to keep timing uniform.
func DummyPasswordCompare(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password)) == nil
}
