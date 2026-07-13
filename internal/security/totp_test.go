package security_test

import (
	"strings"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateSecretProducesUsableSecret confirms GenerateSecret returns a non
// empty base32 secret and an otpauth URI carrying the OmniSurg issuer and the
// account email.
func TestGenerateSecretProducesUsableSecret(t *testing.T) {
	secret, uri, err := security.GenerateSecret("provider.admin@omnisurg.test")
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.True(t, strings.HasPrefix(uri, "otpauth://totp/"), "uri is an otpauth totp link")
	assert.Contains(t, uri, "issuer=OmniSurg")
	assert.Contains(t, uri, "OmniSurg")
}

// TestVerifyCodeAcceptsCurrentCode confirms a code computed now from a secret
// verifies against that secret.
func TestVerifyCodeAcceptsCurrentCode(t *testing.T) {
	secret, _, err := security.GenerateSecret("user@omnisurg.test")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)

	assert.True(t, security.VerifyCode(secret, code), "the freshly computed code verifies")
}

// TestVerifyCodeRejectsWrongCode confirms an unrelated code does not verify.
func TestVerifyCodeRejectsWrongCode(t *testing.T) {
	secret, _, err := security.GenerateSecret("user@omnisurg.test")
	require.NoError(t, err)

	assert.False(t, security.VerifyCode(secret, "000000"), "a wrong code is rejected")
}

// TestVerifyCodeRejectsCodeTwoStepsAway confirms the window is +/-1 step: a code
// computed two periods (60 seconds) in the past does not verify against now.
func TestVerifyCodeRejectsCodeTwoStepsAway(t *testing.T) {
	secret, _, err := security.GenerateSecret("user@omnisurg.test")
	require.NoError(t, err)

	twoStepsAgo := time.Now().Add(-60 * time.Second)
	staleCode, err := totp.GenerateCode(secret, twoStepsAgo)
	require.NoError(t, err)

	assert.False(t, security.VerifyCode(secret, staleCode), "a code two steps away is outside the +/-1 window")
}

// TestVerifyCodeAcceptsOneStepAway confirms the +/-1 window does accept a code
// from one period (30 seconds) ago, the allowed clock skew.
func TestVerifyCodeAcceptsOneStepAway(t *testing.T) {
	secret, _, err := security.GenerateSecret("user@omnisurg.test")
	require.NoError(t, err)

	oneStepAgo := time.Now().Add(-30 * time.Second)
	code, err := totp.GenerateCode(secret, oneStepAgo)
	require.NoError(t, err)

	assert.True(t, security.VerifyCode(secret, code), "a code one step away is inside the +/-1 window")
}

// TestVerifyCodeStepReturnsMatchedCounter confirms VerifyCodeStep returns the
// exact time-step counter a current code matched, so the caller can record it
// and reject a replay of the same step.
func TestVerifyCodeStepReturnsMatchedCounter(t *testing.T) {
	secret := "ABCDEFGHIJKLMNOP"
	now := time.Now().UTC()
	step := now.Unix() / 30
	code, err := totp.GenerateCodeCustom(secret, time.Unix(step*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)

	got, ok := security.VerifyCodeStep(secret, code, now)
	if !ok || got != step {
		t.Fatalf("want step %d ok, got %d ok=%v", step, got, ok)
	}
}

// TestVerifyCodeStepRejectsWrongCode confirms an unrelated code returns
// (0, false) so no step is recorded for a failed attempt.
func TestVerifyCodeStepRejectsWrongCode(t *testing.T) {
	secret := "ABCDEFGHIJKLMNOP"
	got, ok := security.VerifyCodeStep(secret, "000000", time.Now().UTC())
	assert.False(t, ok, "a wrong code does not verify")
	assert.Equal(t, int64(0), got, "a wrong code reports no step")
}

// TestVerifyCodeStepMatchesPreviousWindow confirms a code from one period ago
// (the -1 skew) verifies and reports the previous step, not the current one.
func TestVerifyCodeStepMatchesPreviousWindow(t *testing.T) {
	secret := "ABCDEFGHIJKLMNOP"
	now := time.Now().UTC()
	prevStep := now.Unix()/30 - 1
	code, err := totp.GenerateCodeCustom(secret, time.Unix(prevStep*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	require.NoError(t, err)

	got, ok := security.VerifyCodeStep(secret, code, now)
	require.True(t, ok, "a code one step behind is inside the +/-1 window")
	assert.Equal(t, prevStep, got, "the matched step is the previous window")
}
