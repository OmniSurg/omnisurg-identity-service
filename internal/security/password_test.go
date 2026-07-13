package security_test

import (
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := security.HashPassword("correct horse battery staple")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.True(t, security.VerifyPassword(hash, "correct horse battery staple"))
	assert.False(t, security.VerifyPassword(hash, "wrong"))
}

func TestVerifyPasswordRejectsGarbageHash(t *testing.T) {
	assert.False(t, security.VerifyPassword("not-a-bcrypt-hash", "anything"))
}

func TestDummyPasswordCompareAlwaysRunsAndReturnsFalse(t *testing.T) {
	// The dummy compare exists so the not-found login path pays the same
	// bcrypt cost as a real compare. It must always return false and must
	// actually exercise bcrypt (a real, valid dummy hash).
	if security.DummyPasswordCompare("anything") {
		t.Fatal("dummy compare must never report a match")
	}
}
