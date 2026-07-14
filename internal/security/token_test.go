package security_test

import (
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateActivationTokenReturnsA43CharRawAndItsHash(t *testing.T) {
	raw, hash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	assert.Len(t, raw, 43, "32 random bytes base64url encode to 43 characters")
	assert.Len(t, hash, 32, "sha256 digest is 32 bytes")
	assert.Equal(t, hash, security.HashToken(raw), "GenerateActivationToken returns the hash of its own raw value")
}

func TestGenerateActivationTokenIsUnique(t *testing.T) {
	raw1, hash1, err := security.GenerateActivationToken()
	require.NoError(t, err)
	raw2, hash2, err := security.GenerateActivationToken()
	require.NoError(t, err)
	assert.NotEqual(t, raw1, raw2)
	assert.NotEqual(t, hash1, hash2)
}

func TestHashTokenIsDeterministic(t *testing.T) {
	h1 := security.HashToken("some-raw-token-value")
	h2 := security.HashToken("some-raw-token-value")
	assert.Equal(t, h1, h2)

	h3 := security.HashToken("a-different-raw-token-value")
	assert.NotEqual(t, h1, h3)
}

func TestRandomUnusablePasswordIsNonEmptyAndUnique(t *testing.T) {
	p1, err := security.RandomUnusablePassword()
	require.NoError(t, err)
	p2, err := security.RandomUnusablePassword()
	require.NoError(t, err)
	assert.NotEmpty(t, p1)
	assert.GreaterOrEqual(t, len(p1), 8, "the generated value must itself clear the platform minimum password length")
	assert.NotEqual(t, p1, p2)
}
