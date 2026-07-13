package security

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// totpIssuer is the issuer label shown in the authenticator app. It is the
// product name so a provider scanning the code sees "OmniSurg".
const totpIssuer = "OmniSurg"

// totpPeriod is the time step in seconds. totpSkew is the number of steps before
// or after the current one that VerifyCode accepts, giving a +/-1 step window
// (30 seconds either side) to tolerate clock drift. Replay of a code within the
// window is guarded at the service layer: VerifyCodeStep returns the matched
// step so the caller records the last accepted step per user and rejects a
// reused or older one (RFC 6238 section 5.2).
const (
	totpPeriod = 30
	totpSkew   = 1
	totpDigits = otp.DigitsSix
)

// GenerateSecret produces a fresh TOTP shared secret for an account and the
// matching otpauth provisioning URI an authenticator app scans. The returned
// secret is base32 encoded; account is the provider's email so the entry is
// labelled clearly in the app.
func GenerateSecret(account string) (secret string, otpauthURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: account,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("security.GenerateSecret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// VerifyCode reports whether code is a valid TOTP for secret at the current
// time, allowing a +/-1 step window. A malformed secret or code yields false
// rather than an error so callers treat every negative the same way. It is a
// thin wrapper over VerifyCodeStep for callers that do not need the matched step.
// No production caller currently needs the bare bool (they all check the step for
// replay), so this convenience wrapper only avoids breaking existing callers and
// tests.
func VerifyCode(secret, code string) bool {
	_, ok := VerifyCodeStep(secret, code, time.Now().UTC())
	return ok
}

// VerifyCodeStep reports whether code is a valid TOTP for secret at now within
// the +/-1 step window, and if so returns the time-step counter it matched. The
// step lets the caller reject a replay of the same or an older step (RFC 6238
// section 5.2). It walks the window counters [now/period - 1 .. now/period + 1],
// computes the expected code for each, and compares in constant time so a
// mismatch leaks no timing signal. A malformed secret or code yields (0, false)
// rather than an error so callers treat every negative the same way.
func VerifyCodeStep(secret, code string, now time.Time) (int64, bool) {
	current := now.Unix() / totpPeriod
	for counter := current - totpSkew; counter <= current+totpSkew; counter++ {
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(counter*totpPeriod, 0), totp.ValidateOpts{
			Period:    totpPeriod,
			Digits:    totpDigits,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			// A malformed secret fails identically for every counter, so stop.
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return counter, true
		}
	}
	return 0, false
}
