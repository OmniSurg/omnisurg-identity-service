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

func TestIssueProviderTokenClaims(t *testing.T) {
	kr := testKeyring(t)
	svc := service.NewAuthService(newMockStore(), &mockAudit{}, kr, secret, time.Hour)

	u := model.User{
		ID:           uuid.New(),
		TenantID:     model.PlatformTenantID,
		Email:        "provider.admin@omnisurg.test",
		ProviderRole: model.RoleProviderSuperAdmin,
		Status:       "active",
	}

	tok, err := svc.IssueProviderToken(u)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	claims := mustClaims(t, tok)
	assert.Empty(t, claims.TenantID, "provider token carries no tenant scope")
	assert.Equal(t, model.RoleProviderSuperAdmin, claims.ProviderRole)
	assert.Empty(t, claims.Role, "provider token carries no tenant role")
	assert.False(t, claims.MFAVerified)
	assert.Equal(t, u.ID.String(), claims.Subject)
	require.NotNil(t, claims.ExpiresAt)
	assert.True(t, claims.ExpiresAt.After(time.Now()), "token expiry is in the future")
}

// seedProvider registers a user under the reserved platform tenant via the same
// store path the seed and provider login use.
func seedProvider(t *testing.T, store *mockStore, kr *security.Keyring, email, password, providerRole, status string) uuid.UUID {
	t.Helper()
	hash, err := security.HashPassword(password)
	require.NoError(t, err)
	id := uuid.New()
	store.auth[kr.EmailBlindIndex(email)] = model.AuthRecord{
		ID:           id,
		TenantID:     model.PlatformTenantID,
		PasswordHash: hash,
		Role:         "",
		ProviderRole: providerRole,
		Status:       status,
	}
	store.users[id] = model.User{
		ID:           id,
		TenantID:     model.PlatformTenantID,
		Email:        email,
		ProviderRole: providerRole,
		Status:       status,
	}
	return id
}

// TestProviderLoginUnenrolledReturnsEnrollRequired confirms a provider with no
// TOTP enrolment receives a partial token (mfa_verified false) and the
// ENROLL_REQUIRED status, steering the client to enrol before getting a full
// session.
func TestProviderLoginUnenrolledReturnsEnrollRequired(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	seedProvider(t, store, kr, "fresh.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	res, err := svc.ProviderLogin(context.Background(), "fresh.admin@omnisurg.test", "password123", "req")
	require.NoError(t, err)
	require.NotEmpty(t, res.Token)
	assert.Equal(t, model.MfaStatusEnrollRequired, res.MfaStatus)
	assert.False(t, mustClaims(t, res.Token).MFAVerified, "an unenrolled provider gets a partial token")
}

// TestProviderLoginEnrolledReturnsTotpRequired confirms an enrolled provider
// receives a partial token and the TOTP_REQUIRED status, steering the client to
// the second factor.
func TestProviderLoginEnrolledReturnsTotpRequired(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	id := seedProvider(t, store, kr, "enrolled.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	store.markEnrolled(id)

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	res, err := svc.ProviderLogin(context.Background(), "enrolled.admin@omnisurg.test", "password123", "req")
	require.NoError(t, err)
	require.NotEmpty(t, res.Token)
	assert.Equal(t, model.MfaStatusTotpRequired, res.MfaStatus)
	assert.False(t, mustClaims(t, res.Token).MFAVerified, "the login step never mints a verified token")
}

func TestProviderLoginHappyPath(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	audit := &mockAudit{}
	id := seedProvider(t, store, kr, "provider.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")

	svc := service.NewAuthService(store, audit, kr, secret, time.Hour)
	res, err := svc.ProviderLogin(context.Background(), "provider.admin@omnisurg.test", "password123", "req-prov")
	require.NoError(t, err)
	require.NotEmpty(t, res.Token)

	claims := mustClaims(t, res.Token)
	assert.Equal(t, id.String(), claims.Subject)
	assert.Equal(t, model.RoleProviderSuperAdmin, claims.ProviderRole)
	assert.Empty(t, claims.TenantID)
	assert.Empty(t, claims.Role)

	// ExpiresAt is computed once at signing time and matches the token's exp,
	// not a drifting wall clock recompute in the handler.
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, claims.ExpiresAt.Time, res.ExpiresAt, time.Second)

	// A successful provider login writes a provider_login audit row under the
	// reserved platform tenant, with the provider user as the actor.
	require.Len(t, audit.events, 1)
	ev := audit.events[0]
	assert.Equal(t, "identity.provider_login", ev.Action)
	assert.Equal(t, model.PlatformTenantID, ev.TenantID)
	require.NotNil(t, ev.ActorID)
	assert.Equal(t, id, *ev.ActorID)
}

func TestProviderLoginWrongPassword(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	audit := &mockAudit{}
	seedProvider(t, store, kr, "provider.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")

	svc := service.NewAuthService(store, audit, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "provider.admin@omnisurg.test", "wrong", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Empty(t, audit.events, "a rejected login writes no audit row")
}

func TestProviderLoginInactiveUserRejected(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	audit := &mockAudit{}
	// An inactive provider user (status != active) is rejected with the same
	// generic error as every other negative case.
	seedProvider(t, store, kr, "suspended.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "suspended")

	svc := service.NewAuthService(store, audit, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "suspended.admin@omnisurg.test", "password123", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Empty(t, audit.events, "a rejected login writes no audit row")
}

func TestProviderLoginTenantUserUnderPlatformTenantRejected(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	// A user that lives under the platform tenant but carries no provider role
	// must be rejected with the same generic error as a bad password.
	seedProvider(t, store, kr, "tenant.user@omnisurg.test", "password123", "", "active")

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "tenant.user@omnisurg.test", "password123", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
}

func TestProviderLoginUnknownEmailRejected(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "ghost@omnisurg.test", "password123", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
}

// countDummyCompare swaps the dummyCompare seam for a counting wrapper that
// still runs the real compare, and restores it on cleanup. It returns a pointer
// to the call count so a test can assert the not-found path spent a bcrypt
// compare (HG-B3) deterministically, without a flaky wall-clock probe.
func countDummyCompare(t *testing.T) *int {
	t.Helper()
	var calls int
	restore := service.SwapDummyCompareForTest(func(pw string) bool {
		calls++
		return security.DummyPasswordCompare(pw)
	})
	t.Cleanup(restore)
	return &calls
}

// TestLoginUnknownEmailRunsDummyCompare proves the unknown-email path spends one
// bcrypt compare so its latency matches a wrong-password login (no enumeration
// timing oracle), and still returns the generic ErrBadCredentials.
func TestLoginUnknownEmailRunsDummyCompare(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	calls := countDummyCompare(t)

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.Login(context.Background(), tenantA, "ghost@acme.test", "password123", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Equal(t, 1, *calls, "the unknown-email path must spend exactly one bcrypt compare")
}

// TestLoginInactiveUserRunsDummyCompare proves the inactive-user path spends one
// bcrypt compare before returning the generic error.
func TestLoginInactiveUserRunsDummyCompare(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	hash, _ := security.HashPassword("password123")
	id := uuid.New()
	store.auth[kr.EmailBlindIndex("susp@acme.test")] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: hash, Role: model.RoleReception, Status: "suspended"}
	calls := countDummyCompare(t)

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.Login(context.Background(), tenantA, "susp@acme.test", "password123", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Equal(t, 1, *calls, "the inactive-user path must spend exactly one bcrypt compare")
}

// TestProviderLoginUnknownEmailRunsDummyCompare mirrors the tenant path for
// provider login: the unknown-email branch spends one bcrypt compare.
func TestProviderLoginUnknownEmailRunsDummyCompare(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	calls := countDummyCompare(t)

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "ghost@omnisurg.test", "password123", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Equal(t, 1, *calls, "the unknown-email provider path must spend exactly one bcrypt compare")
}

// TestProviderLoginInactiveUserRunsDummyCompare proves the inactive provider
// path spends one bcrypt compare before returning the generic error.
func TestProviderLoginInactiveUserRunsDummyCompare(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	seedProvider(t, store, kr, "suspended.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "suspended")
	calls := countDummyCompare(t)

	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.ProviderLogin(context.Background(), "suspended.admin@omnisurg.test", "password123", "req-prov")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
	assert.Equal(t, 1, *calls, "the inactive-user provider path must spend exactly one bcrypt compare")
}

// TestProviderLoginNegativeCasesReturnIdenticalError proves no enumeration: the
// wrong password, the no-provider-role, and the unknown-email paths all return
// the exact same error value and message so a caller cannot tell them apart.
func TestProviderLoginNegativeCasesReturnIdenticalError(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	seedProvider(t, store, kr, "provider.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin, "active")
	seedProvider(t, store, kr, "tenant.user@omnisurg.test", "password123", "", "active")
	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)

	_, errWrong := svc.ProviderLogin(context.Background(), "provider.admin@omnisurg.test", "wrong", "req-prov")
	_, errNoRole := svc.ProviderLogin(context.Background(), "tenant.user@omnisurg.test", "password123", "req-prov")
	_, errUnknown := svc.ProviderLogin(context.Background(), "ghost@omnisurg.test", "password123", "req-prov")

	require.Error(t, errWrong)
	assert.Equal(t, errWrong.Error(), errNoRole.Error())
	assert.Equal(t, errWrong.Error(), errUnknown.Error())
}
