package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerCaller builds the caller a verified provider JWT yields: the platform
// tenant, a provider role, and the user id from the token subject.
func providerCaller(id uuid.UUID, providerRole string) service.Caller {
	return service.Caller{UserID: id, TenantID: model.PlatformTenantID, ProviderRole: providerRole, RequestID: "req"}
}

func newTotpService(t *testing.T, store *mockStore) (*service.TotpService, *mockAudit) {
	t.Helper()
	audit := &mockAudit{}
	svc := service.NewTotpService(store, audit, secret, time.Hour)
	return svc, audit
}

// TestEnrollStoresSecretWithoutMarkingEnrolled confirms enrol persists a secret
// and an otpauth uri but leaves the user unconfirmed (mfa_enrolled false).
func TestEnrollStoresSecretWithoutMarkingEnrolled(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "enrol@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	res, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	assert.NotEmpty(t, res.Secret)
	assert.Contains(t, res.OtpauthURI, "otpauth://totp/")

	secretStored, enrolled, err := store.GetTotpSecret(context.Background(), model.PlatformTenantID, id)
	require.NoError(t, err)
	assert.Equal(t, res.Secret, secretStored, "the generated secret is persisted")
	assert.False(t, enrolled, "enrol alone does not mark the user enrolled")
}

// TestConfirmWithValidCodeIssuesFullToken confirms a valid code marks the user
// enrolled and mints a full (mfa_verified true) token.
func TestConfirmWithValidCodeIssuesFullToken(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "confirm@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, audit := newTotpService(t, store)

	res, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)

	code, err := totp.GenerateCode(res.Secret, time.Now())
	require.NoError(t, err)

	confirm, err := svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), code)
	require.NoError(t, err)
	require.NotEmpty(t, confirm.Token)
	assert.True(t, mustClaims(t, confirm.Token).MFAVerified, "confirm mints a full token")
	assert.Equal(t, id.String(), mustClaims(t, confirm.Token).Subject)

	_, enrolled, err := store.GetTotpSecret(context.Background(), model.PlatformTenantID, id)
	require.NoError(t, err)
	assert.True(t, enrolled, "a confirmed user is enrolled")

	// Confirming a second factor writes an audit row.
	require.NotEmpty(t, audit.events)
	assert.Equal(t, "identity.provider_totp.confirm", audit.events[len(audit.events)-1].Action)
}

// TestConfirmWithWrongCodeFails confirms a bad code is rejected and the user
// stays unenrolled.
func TestConfirmWithWrongCodeFails(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "badconfirm@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	_, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)

	_, err = svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), "000000")
	assert.ErrorIs(t, err, model.ErrInvalidTotpCode)

	_, enrolled, err := store.GetTotpSecret(context.Background(), model.PlatformTenantID, id)
	require.NoError(t, err)
	assert.False(t, enrolled, "a rejected confirm leaves the user unenrolled")
}

// TestConfirmWithoutEnrollFails confirms confirming before enrolling a secret is
// refused.
func TestConfirmWithoutEnrollFails(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "noenrol@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	_, err := svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), "123456")
	assert.ErrorIs(t, err, model.ErrMfaNotEnrolled)
}

// TestSecondEnrollBeforeConfirmOverwrites confirms re-enrolling before confirm
// replaces the unconfirmed secret rather than refusing.
func TestSecondEnrollBeforeConfirmOverwrites(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "reenrol@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	first, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	second, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	assert.NotEqual(t, first.Secret, second.Secret, "a second enrol generates a fresh secret")

	stored, _, err := store.GetTotpSecret(context.Background(), model.PlatformTenantID, id)
	require.NoError(t, err)
	assert.Equal(t, second.Secret, stored, "the latest unconfirmed secret wins")
}

// TestEnrollWhenAlreadyEnrolledRefused confirms an already enrolled provider
// cannot enrol again and must reset first.
func TestEnrollWhenAlreadyEnrolledRefused(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "already@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	store.markEnrolled(id)
	svc, _ := newTotpService(t, store)

	_, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	assert.ErrorIs(t, err, model.ErrMfaAlreadyEnrolled)
}

// TestVerifyEnrolledWithValidCodeIssuesFullToken confirms the login second
// factor mints a full token for an enrolled provider with a valid code.
func TestVerifyEnrolledWithValidCodeIssuesFullToken(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "verify@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, audit := newTotpService(t, store)

	enrol, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	// The provider is enrolled and logs in later, in a fresh window where no step
	// has been consumed yet, so the login code is accepted.
	store.markEnrolled(id)

	loginCode, err := totp.GenerateCode(enrol.Secret, time.Now())
	require.NoError(t, err)
	res, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), loginCode)
	require.NoError(t, err)
	require.NotEmpty(t, res.Token)
	assert.True(t, mustClaims(t, res.Token).MFAVerified, "verify mints a full token")
	assert.Equal(t, "identity.provider_totp.verify", audit.events[len(audit.events)-1].Action)
}

// TestVerifyWrongCodeFails confirms a bad code at login is rejected.
func TestVerifyWrongCodeFails(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "verifybad@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)
	enrol, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	code, err := totp.GenerateCode(enrol.Secret, time.Now())
	require.NoError(t, err)
	_, err = svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), code)
	require.NoError(t, err)

	_, err = svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), "000000")
	assert.ErrorIs(t, err, model.ErrInvalidTotpCode)
}

// TestVerifyUnenrolledFails confirms verify refuses a provider that has not
// completed enrolment, steering them to enrol first.
func TestVerifyUnenrolledFails(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "verifynoenrol@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	_, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), "123456")
	assert.ErrorIs(t, err, model.ErrMfaNotEnrolled)
}

// TestVerifyRejectsReplayedCode confirms a code accepted once cannot be replayed
// within the same skew window: the second verify with the same code is rejected
// with ErrInvalidTotpCode and issues no token (RFC 6238 section 5.2).
func TestVerifyRejectsReplayedCode(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "replay@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	enrol, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	store.markEnrolled(id)

	loginCode, err := totp.GenerateCode(enrol.Secret, time.Now())
	require.NoError(t, err)
	first, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), loginCode)
	require.NoError(t, err)
	require.NotEmpty(t, first.Token, "a fresh code verifies")

	replay, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), loginCode)
	assert.ErrorIs(t, err, model.ErrInvalidTotpCode, "replaying the same code is rejected")
	assert.Empty(t, replay.Token, "a rejected replay issues no token")
}

// TestVerifyRejectsOlderStepAfterNewer confirms that once a newer step has been
// accepted, a code for an older step still inside the +/-1 window is rejected.
func TestVerifyRejectsOlderStepAfterNewer(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "older@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	enrol, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	newerCode, err := totp.GenerateCode(enrol.Secret, time.Now())
	require.NoError(t, err)
	olderCode, err := totp.GenerateCode(enrol.Secret, time.Now().Add(-30*time.Second))
	require.NoError(t, err)

	// Complete enrolment with a current code, accepting the current step.
	_, err = svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), newerCode)
	require.NoError(t, err)

	// A code for the previous step, though inside the window, is now stale.
	res, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), olderCode)
	assert.ErrorIs(t, err, model.ErrInvalidTotpCode, "an older step after a newer one is rejected")
	assert.Empty(t, res.Token)
}

// TestConfirmThenVerifySameCodeRejectedAsReplay documents the benign edge: a
// confirm accepts the step and completes MFA, so an immediate verify with the
// same code is correctly rejected as a replay. The confirm already issued a full
// token, so nothing is lost.
func TestConfirmThenVerifySameCodeRejectedAsReplay(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "confirmreplay@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	enrol, err := svc.Enroll(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin))
	require.NoError(t, err)
	code, err := totp.GenerateCode(enrol.Secret, time.Now())
	require.NoError(t, err)

	confirm, err := svc.Confirm(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), code)
	require.NoError(t, err)
	require.NotEmpty(t, confirm.Token, "confirm completes MFA and issues a token")

	res, err := svc.Verify(context.Background(), providerCaller(id, model.RoleProviderSuperAdmin), code)
	assert.ErrorIs(t, err, model.ErrInvalidTotpCode, "the same code cannot be reused at verify after confirm")
	assert.Empty(t, res.Token)
}

// TestResetClearsTargetAndAuditsBothParties confirms a super admin reset wipes
// the target's enrolment and writes an audit row naming both the actor (the
// super admin) and the target.
func TestResetClearsTargetAndAuditsBothParties(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	target := seedProvider(t, store, kr, "target@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	store.markEnrolled(target)
	admin := seedProvider(t, store, kr, "super@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, audit := newTotpService(t, store)

	err := svc.Reset(context.Background(), providerCaller(admin, model.RoleProviderSuperAdmin), target)
	require.NoError(t, err)

	_, enrolled, err := store.GetTotpSecret(context.Background(), model.PlatformTenantID, target)
	require.NoError(t, err)
	assert.False(t, enrolled, "the target is no longer enrolled after a reset")

	ev := audit.events[len(audit.events)-1]
	assert.Equal(t, "identity.provider_totp.reset", ev.Action)
	require.NotNil(t, ev.ActorID)
	assert.Equal(t, admin, *ev.ActorID, "the audit row records the acting super admin")
	require.NotNil(t, ev.TargetID)
	assert.Equal(t, target, *ev.TargetID, "the audit row records the target")
}

// TestResetUnknownTargetReturnsNotFound confirms resetting an unknown id reports
// not found rather than silently succeeding.
func TestResetUnknownTargetReturnsNotFound(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	admin := seedProvider(t, store, kr, "super2@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	svc, _ := newTotpService(t, store)

	err := svc.Reset(context.Background(), providerCaller(admin, model.RoleProviderSuperAdmin), uuid.New())
	assert.ErrorIs(t, err, model.ErrUserNotFound)
}
