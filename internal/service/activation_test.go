package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func adminCaller() service.Caller {
	return service.Caller{UserID: uuid.New(), TenantID: tenantA, Role: model.RolePracticeAdmin, RequestID: "req-provision"}
}

func TestProvisionAdminCreatesAPendingUserAndAToken(t *testing.T) {
	store := newMockStore()
	audit := &mockAudit{}
	svc := service.NewUserService(store, audit, testKeyring(t))

	res, err := svc.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "new.admin@acme.test", Phone: "+263771234567", DisplayName: "New Admin", Role: model.RolePracticeAdmin,
	})
	require.NoError(t, err)
	assert.Equal(t, "pending_activation", res.User.Status)
	assert.Equal(t, "new.admin@acme.test", res.User.Email)
	assert.NotEmpty(t, res.RawToken)
	assert.True(t, res.ExpiresAt.After(time.Now()), "the token expiry is in the future")
	require.Len(t, audit.events, 1)
	assert.Equal(t, "identity.user.provision", audit.events[0].Action)
}

func TestProvisionAdminRequiresPhone(t *testing.T) {
	svc := service.NewUserService(newMockStore(), &mockAudit{}, testKeyring(t))
	_, err := svc.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "no.phone@acme.test", DisplayName: "No Phone", Role: model.RolePracticeAdmin,
	})
	assert.ErrorIs(t, err, model.ErrValidation)
}

func TestProvisionAdminRequiresACanonicalRole(t *testing.T) {
	svc := service.NewUserService(newMockStore(), &mockAudit{}, testKeyring(t))
	_, err := svc.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "bad.role@acme.test", Phone: "+263771111111", DisplayName: "Bad Role", Role: "not_a_role",
	})
	assert.ErrorIs(t, err, model.ErrValidation)
}

func TestProvisionAdminDuplicateEmailConflicts(t *testing.T) {
	store := newMockStore()
	svc := service.NewUserService(store, &mockAudit{}, testKeyring(t))
	in := model.NewPendingUser{Email: "dupe.pending@acme.test", Phone: "+263772222222", DisplayName: "Dupe", Role: model.RolePracticeAdmin}
	_, err := svc.ProvisionAdmin(context.Background(), adminCaller(), in)
	require.NoError(t, err)
	_, err = svc.ProvisionAdmin(context.Background(), adminCaller(), in)
	assert.ErrorIs(t, err, model.ErrEmailTaken)
}

// activateService builds an AuthService plus the UserService over the SAME
// mock store, mirroring how main.go wires both services onto one repository.
func activateService(t *testing.T) (*service.AuthService, *service.UserService, *mockStore, *mockAudit) {
	t.Helper()
	store := newMockStore()
	audit := &mockAudit{}
	kr := testKeyring(t)
	auth := service.NewAuthService(store, audit, kr, secret, time.Hour)
	users := service.NewUserService(store, audit, kr)
	return auth, users, store, audit
}

func TestActivateHappyPathSetsPasswordActivatesAndMintsASession(t *testing.T) {
	auth, users, store, audit := activateService(t)
	res, err := users.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "activate.me@acme.test", Phone: "+263773334444", DisplayName: "Activate Me", Role: model.RolePracticeAdmin,
	})
	require.NoError(t, err)
	audit.events = nil // isolate the activate audit assertion below from the provision event

	result, err := auth.Activate(context.Background(), res.RawToken, "BrandNewPassword1!", "req-activate")
	require.NoError(t, err)
	assert.NotEmpty(t, result.Token)
	assert.Equal(t, "active", result.User.Status)
	assert.Equal(t, res.User.ID, result.User.ID)

	claims := mustClaims(t, result.Token)
	assert.Equal(t, res.User.ID.String(), claims.Subject)
	assert.Equal(t, tenantA.String(), claims.TenantID)
	assert.False(t, claims.MFAVerified)
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, claims.ExpiresAt.Time, result.ExpiresAt, time.Second)

	require.Len(t, audit.events, 1)
	assert.Equal(t, "identity.activate", audit.events[0].Action)

	// The user in the underlying store really is active now (not just the
	// returned value), and the same token cannot be replayed.
	stored, ok := store.users[res.User.ID]
	require.True(t, ok)
	assert.Equal(t, "active", stored.Status)

	_, err = auth.Activate(context.Background(), res.RawToken, "AnotherPassword2!", "req-replay")
	assert.ErrorIs(t, err, model.ErrActivationInvalid, "a consumed token cannot activate a second time")
}

func TestActivateUnknownTokenReturnsGenericInvalid(t *testing.T) {
	auth, _, _, audit := activateService(t)
	_, err := auth.Activate(context.Background(), "not-a-real-token-value-at-all-xxxxx", "GoodPassword1!", "req")
	assert.ErrorIs(t, err, model.ErrActivationInvalid)
	assert.Empty(t, audit.events, "a rejected activation writes no audit row")
}

func TestActivateExpiredTokenReturnsGenericInvalid(t *testing.T) {
	auth, users, store, _ := activateService(t)
	res, err := users.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "expired.pending@acme.test", Phone: "+263775556666", DisplayName: "Expired", Role: model.RolePracticeAdmin,
	})
	require.NoError(t, err)

	// Force the token's expiry into the past directly on the store (the
	// service always issues a future expiry; this simulates one that has since
	// lapsed).
	for i, pt := range store.tokens {
		if pt.token.UserID == res.User.ID {
			store.tokens[i].token.ExpiresAt = time.Now().UTC().Add(-time.Minute)
		}
	}

	_, err = auth.Activate(context.Background(), res.RawToken, "GoodPassword1!", "req")
	assert.ErrorIs(t, err, model.ErrActivationInvalid)
}

func TestCredentialTokenIsUsableActivationRejectsExpired(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	tok := model.CredentialToken{Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: past}
	assert.False(t, tok.IsUsableActivation(time.Now().UTC()))
}

func TestCredentialTokenIsUsableActivationRejectsConsumed(t *testing.T) {
	consumedAt := time.Now().UTC()
	tok := model.CredentialToken{Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: time.Now().UTC().Add(time.Hour), ConsumedAt: &consumedAt}
	assert.False(t, tok.IsUsableActivation(time.Now().UTC()))
}

func TestCredentialTokenIsUsableActivationRejectsWrongPurpose(t *testing.T) {
	tok := model.CredentialToken{Purpose: "password_reset", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	assert.False(t, tok.IsUsableActivation(time.Now().UTC()))
}

func TestActivateShortPasswordReturnsValidationBeforeTokenLookup(t *testing.T) {
	auth, _, _, audit := activateService(t)
	// A garbage token combined with a too-short password still returns the
	// validation error, never the token-invalid error: the password shape is
	// checked before any token lookup, so the Contract Smoke Test can exercise
	// this negative case with no real token (provisioning is gRPC-only).
	_, err := auth.Activate(context.Background(), "any-garbage-token-value", "short", "req")
	assert.ErrorIs(t, err, model.ErrValidation)
	assert.Empty(t, audit.events)
}

func TestPendingUserLoginReturnsGenericBadCredentials(t *testing.T) {
	// A pending_activation user must get the exact same generic bad credentials
	// error as a wrong password on Login (HG-B3), never a hint that the account
	// exists but is not yet active.
	store := newMockStore()
	kr := testKeyring(t)
	audit := &mockAudit{}
	auth := service.NewAuthService(store, audit, kr, secret, time.Hour)

	id := uuid.New()
	hash := kr.EmailBlindIndex("still.pending@acme.test")
	pwHash, err := security.HashPassword("some-discard-value-not-real")
	require.NoError(t, err)
	store.auth[hash] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: pwHash, Role: model.RolePracticeAdmin, Status: "pending_activation"}
	store.users[id] = model.User{ID: id, TenantID: tenantA, Email: "still.pending@acme.test", Role: model.RolePracticeAdmin, Status: "pending_activation"}

	_, err = auth.Login(context.Background(), tenantA, "still.pending@acme.test", "some-discard-value-not-real", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Empty(t, audit.events, "a rejected login (including a pending user) writes no audit row")
}

func TestResendActivationInvalidatesPriorAndIssuesANewToken(t *testing.T) {
	auth, users, store, audit := activateService(t)
	provisioned, err := users.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "resend.me@acme.test", Phone: "+263779998888", DisplayName: "Resend Me", Role: model.RolePracticeAdmin,
	})
	require.NoError(t, err)
	audit.events = nil

	resent, err := users.ResendActivation(context.Background(), adminCaller(), provisioned.User.ID)
	require.NoError(t, err)
	assert.NotEqual(t, provisioned.RawToken, resent.RawToken, "resend issues a fresh raw token")
	require.Len(t, audit.events, 1)
	assert.Equal(t, "identity.user.resend_activation", audit.events[0].Action)

	// The prior token no longer activates.
	_, err = auth.Activate(context.Background(), provisioned.RawToken, "IrrelevantPassword1!", "req")
	assert.ErrorIs(t, err, model.ErrActivationInvalid, "the prior token was invalidated by resend")

	// The fresh token activates normally.
	result, err := auth.Activate(context.Background(), resent.RawToken, "FreshPassword1!", "req")
	require.NoError(t, err)
	assert.Equal(t, "active", result.User.Status)
	assert.Equal(t, "active", store.users[provisioned.User.ID].Status)
}

func TestResendActivationRefusesAnAlreadyActiveUser(t *testing.T) {
	auth, users, _, _ := activateService(t)
	res, err := users.ProvisionAdmin(context.Background(), adminCaller(), model.NewPendingUser{
		Email: "already.active@acme.test", Phone: "+263771230000", DisplayName: "Already Active", Role: model.RolePracticeAdmin,
	})
	require.NoError(t, err)
	_, err = auth.Activate(context.Background(), res.RawToken, "GoodPassword1!", "req")
	require.NoError(t, err)

	_, err = users.ResendActivation(context.Background(), adminCaller(), res.User.ID)
	assert.ErrorIs(t, err, model.ErrNotPendingActivation)
}
