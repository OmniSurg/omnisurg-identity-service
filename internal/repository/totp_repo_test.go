package repository_test

import (
	"context"
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTotpSecretRoundTrip stores an encrypted TOTP secret, reads it back, and
// confirms the plaintext survives the encrypt then decrypt round trip and that
// mfa_enrolled stays false until explicitly flipped.
func TestTotpSecretRoundTrip(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "totp@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	const plainSecret = "ABCDEFGHIJKLMNOP"
	require.NoError(t, repo.SetTotpSecret(ctx, tenantA, u.ID, plainSecret))

	got, enrolled, err := repo.GetTotpSecret(ctx, tenantA, u.ID)
	require.NoError(t, err)
	assert.Equal(t, plainSecret, got, "the stored secret decrypts to the original")
	assert.False(t, enrolled, "storing a secret does not mark the user enrolled")
}

// TestSetMfaEnrolledToggles confirms the flag flips on and off independently of
// the secret.
func TestSetMfaEnrolledToggles(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "flag@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	require.NoError(t, repo.SetMfaEnrolled(ctx, tenantA, u.ID, true))
	got, err := repo.Get(ctx, tenantA, u.ID)
	require.NoError(t, err)
	assert.True(t, got.MFAEnrolled)

	require.NoError(t, repo.SetMfaEnrolled(ctx, tenantA, u.ID, false))
	got, err = repo.Get(ctx, tenantA, u.ID)
	require.NoError(t, err)
	assert.False(t, got.MFAEnrolled)
}

// TestClearTotpWipesSecretAndFlag confirms a reset returns the user to the
// no-secret, not-enrolled state.
func TestClearTotpWipesSecretAndFlag(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "clear@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	require.NoError(t, repo.SetTotpSecret(ctx, tenantA, u.ID, "ABCDEFGHIJKLMNOP"))
	require.NoError(t, repo.SetMfaEnrolled(ctx, tenantA, u.ID, true))

	require.NoError(t, repo.ClearTotp(ctx, tenantA, u.ID))

	secret, enrolled, err := repo.GetTotpSecret(ctx, tenantA, u.ID)
	require.NoError(t, err)
	assert.Empty(t, secret, "the secret is wiped")
	assert.False(t, enrolled, "the enrolled flag is cleared")
}

// TestClearTotpResetsLastStep confirms a reset also wipes the replay state: once
// a step is accepted, the same step is rejected as a replay, but after a reset
// the row starts clean so a fresh re-enrolment can accept that step again. This
// reads the step state back through AcceptTotpStep under the real RLS harness.
func TestClearTotpResetsLastStep(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "clearstep@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	ok, err := repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	require.True(t, ok, "the first step is accepted")

	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	require.False(t, ok, "the same step is a replay before a reset")

	require.NoError(t, repo.ClearTotp(ctx, tenantA, u.ID))

	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	assert.True(t, ok, "after a reset the replay state is cleared so the step is accepted again")
}

// TestGetTotpSecretEmptyWhenUnset confirms a user that never enrolled returns an
// empty secret and not-enrolled, with no error.
func TestGetTotpSecretEmptyWhenUnset(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "unset@acme.test", model.RolePracticeAdmin)

	secret, enrolled, err := repo.GetTotpSecret(context.Background(), tenantA, u.ID)
	require.NoError(t, err)
	assert.Empty(t, secret)
	assert.False(t, enrolled)
}

// TestGetTotpSecretUnknownUser confirms a missing user maps to ErrUserNotFound.
func TestGetTotpSecretUnknownUser(t *testing.T) {
	repo, _ := setup(t)
	_, _, err := repo.GetTotpSecret(context.Background(), tenantA, model.PlatformTenantID)
	assert.ErrorIs(t, err, model.ErrUserNotFound)
}

// TestAuthByEmailHashProjectsMfaEnrolled confirms the extended auth projection
// carries the enrolled flag so login can branch on it.
func TestAuthByEmailHashProjectsMfaEnrolled(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "authmfa@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	hash := kr.EmailBlindIndex("authmfa@acme.test")
	rec, err := repo.AuthByEmailHash(ctx, tenantA, hash)
	require.NoError(t, err)
	assert.False(t, rec.MfaEnrolled, "a fresh user is not enrolled")

	require.NoError(t, repo.SetMfaEnrolled(ctx, tenantA, u.ID, true))
	rec, err = repo.AuthByEmailHash(ctx, tenantA, hash)
	require.NoError(t, err)
	assert.True(t, rec.MfaEnrolled, "after enrolment the auth projection reports it")
}

// TestAcceptTotpStepAdvancesAndRejectsReplay confirms the conditional step write
// accepts a first step, accepts a strictly greater one, and rejects the same or
// an older step (the RFC 6238 5.2 replay guard) atomically.
func TestAcceptTotpStepAdvancesAndRejectsReplay(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "step@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	ok, err := repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	assert.True(t, ok, "the first step is accepted")

	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	assert.False(t, ok, "replaying the same step is rejected")

	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 99)
	require.NoError(t, err)
	assert.False(t, ok, "an older step is rejected")

	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 101)
	require.NoError(t, err)
	assert.True(t, ok, "a strictly greater step is accepted")
}

// TestAcceptTotpStepTenantIsolation confirms the step write cannot advance a row
// in another tenant: a cross tenant id is invisible under RLS, so no row updates
// and the call reports not accepted rather than touching the other tenant.
func TestAcceptTotpStepTenantIsolation(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "stepiso@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()

	ok, err := repo.AcceptTotpStep(ctx, tenantB, u.ID, 100)
	require.NoError(t, err)
	assert.False(t, ok, "a step write scoped to the wrong tenant matches no row")

	// The row under tenant A still has no accepted step, so tenant A can accept.
	ok, err = repo.AcceptTotpStep(ctx, tenantA, u.ID, 100)
	require.NoError(t, err)
	assert.True(t, ok, "the tenant A row was untouched by the cross tenant attempt")
}

// TestSetTotpSecretTenantIsolation confirms a TOTP write under one tenant does
// not touch a row in another tenant: a cross tenant id is invisible under RLS,
// so the read returns not found.
func TestSetTotpSecretTenantIsolation(t *testing.T) {
	repo, kr := setup(t)
	a := mustCreate(t, repo, kr, tenantA, "iso@acme.test", model.RolePracticeAdmin)
	ctx := context.Background()
	require.NoError(t, repo.SetTotpSecret(ctx, tenantA, a.ID, "ABCDEFGHIJKLMNOP"))

	_, _, err := repo.GetTotpSecret(ctx, tenantB, a.ID)
	assert.ErrorIs(t, err, model.ErrUserNotFound)
}
