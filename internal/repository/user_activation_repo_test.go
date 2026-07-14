package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustProvision provisions a pending admin through the real repository and
// returns the created user plus its raw activation token and hash, so tests
// can drive the token straight through ActivateWithToken.
func mustProvision(t *testing.T, repo *repository.UserRepository, kr *security.Keyring, tenant uuid.UUID, email, phone string) (model.User, string, []byte, time.Time) {
	t.Helper()
	enc, err := kr.Cipher().Encrypt([]byte(email))
	require.NoError(t, err)
	encPhone, err := kr.Cipher().Encrypt([]byte(phone))
	require.NoError(t, err)
	pw, err := security.RandomUnusablePassword()
	require.NoError(t, err)
	pwHash, err := security.HashPassword(pw)
	require.NoError(t, err)
	rawToken, tokenHash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	expiresAt := time.Now().UTC().Add(72 * time.Hour)

	user, err := repo.ProvisionPendingAdmin(context.Background(), tenant, model.NewPendingUser{
		TenantID:    tenant,
		Email:       email,
		Phone:       phone,
		DisplayName: "Pending Admin",
		Role:        model.RolePracticeAdmin,
	}, string(enc), encPhone, pwHash, tokenHash, expiresAt)
	require.NoError(t, err)
	return user, rawToken, tokenHash, expiresAt
}

func TestProvisionPendingAdminCreatesAPendingUserAndABoundToken(t *testing.T) {
	repo, kr := setup(t)
	user, _, tokenHash, expiresAt := mustProvision(t, repo, kr, tenantA, "pending.admin@acme.test", "+263771234567")

	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.Equal(t, "pending_activation", user.Status, "a provisioned user starts pending, never active")
	assert.Equal(t, model.RolePracticeAdmin, user.Role)

	got, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.Equal(t, tenantA, got.TenantID)
	assert.Equal(t, user.ID, got.UserID)
	assert.Equal(t, model.CredentialTokenPurposeActivation, got.Purpose)
	assert.Nil(t, got.ConsumedAt)
	assert.WithinDuration(t, expiresAt, got.ExpiresAt, time.Second)
}

func TestProvisionPendingAdminDuplicateEmailInTenantConflicts(t *testing.T) {
	repo, kr := setup(t)
	mustProvision(t, repo, kr, tenantA, "dupe.pending@acme.test", "+263771111111")

	enc, err := kr.Cipher().Encrypt([]byte("dupe.pending@acme.test"))
	require.NoError(t, err)
	encPhone, err := kr.Cipher().Encrypt([]byte("+263772222222"))
	require.NoError(t, err)
	pwHash, err := security.HashPassword("whatever-not-used-1")
	require.NoError(t, err)
	_, tokenHash, err := security.GenerateActivationToken()
	require.NoError(t, err)

	_, err = repo.ProvisionPendingAdmin(context.Background(), tenantA, model.NewPendingUser{
		TenantID: tenantA, Email: "dupe.pending@acme.test", Phone: "+263772222222", DisplayName: "Second", Role: model.RolePracticeAdmin,
	}, string(enc), encPhone, pwHash, tokenHash, time.Now().UTC().Add(72*time.Hour))
	assert.ErrorIs(t, err, model.ErrEmailTaken)
}

func TestActivateWithTokenSetsPasswordActivatesAndConsumesToken(t *testing.T) {
	repo, kr := setup(t)
	user, _, tokenHash, _ := mustProvision(t, repo, kr, tenantA, "activate.me@acme.test", "+263773334444")

	tok, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)

	newHash, err := security.HashPassword("BrandNewPassword1!")
	require.NoError(t, err)
	activated, err := repo.ActivateWithToken(context.Background(), tenantA, tok.ID, user.ID, newHash)
	require.NoError(t, err)
	assert.Equal(t, "active", activated.Status)
	assert.Equal(t, user.ID, activated.ID)

	// The token is now consumed: a second activate attempt with the same token
	// id fails closed, and never re-mutates the user.
	_, err = repo.ActivateWithToken(context.Background(), tenantA, tok.ID, user.ID, newHash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid, "a consumed token cannot activate a second time")

	// The auth record now carries the new password hash (proving the write
	// actually landed), and login by blind index resolves the active user.
	rec, err := repo.AuthByEmailHash(context.Background(), tenantA, kr.EmailBlindIndex("activate.me@acme.test"))
	require.NoError(t, err)
	assert.Equal(t, "active", rec.Status)
	assert.True(t, security.VerifyPassword(rec.PasswordHash, "BrandNewPassword1!"))
}

func TestActivateWithTokenUnknownTokenIDReturnsActivationInvalid(t *testing.T) {
	repo, kr := setup(t)
	user, _, _, _ := mustProvision(t, repo, kr, tenantA, "noone.provisioned@acme.test", "+263775556666")

	newHash, err := security.HashPassword("AnotherPassword1!")
	require.NoError(t, err)
	_, err = repo.ActivateWithToken(context.Background(), tenantA, uuid.New(), user.ID, newHash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid)

	// The user is left untouched: still pending.
	got, err := repo.Get(context.Background(), tenantA, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending_activation", got.Status, "a failed activate must not partially mutate the user")
}

// TestActivateWithTokenBindsExactlyOneTenant is the mandatory tenant isolation
// path test: a token minted for tenant A's user cannot activate anything
// under tenant B's RLS scope, even though credential_tokens itself carries no
// RLS. The tenant used for the write transaction always comes FROM the
// resolved token (tok.TenantID), never from an untrusted caller-supplied
// value, so this test drives the repository the same way a compromised or
// mistaken caller would: passing tenant B explicitly. The user row is only
// visible under tenant A's RLS scope, so the activating UPDATE (scoped to
// tenant B) matches no row and fails closed.
func TestActivateWithTokenBindsExactlyOneTenant(t *testing.T) {
	repo, kr := setup(t)
	user, _, tokenHash, _ := mustProvision(t, repo, kr, tenantA, "isolated.pending@acme.test", "+263779998888")
	tok, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.Equal(t, tenantA, tok.TenantID, "the token resolves the tenant it was provisioned under, never a caller-supplied one")

	newHash, err := security.HashPassword("CrossTenantAttempt1!")
	require.NoError(t, err)

	// Attempting to run the activation write under tenant B's RLS scope (as if
	// a caller ignored the token's own resolved tenant) finds no visible user
	// row and fails closed with the generic activation error, never activating
	// tenant A's user under the wrong scope.
	_, err = repo.ActivateWithToken(context.Background(), tenantB, tok.ID, user.ID, newHash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid)

	// Tenant A's user is untouched: still pending, and the token is NOT
	// consumed by the failed cross tenant attempt (ConsumeCredentialToken and
	// SetPasswordAndActivate run in the SAME transaction, so a failure on
	// either rolls back both).
	got, err := repo.Get(context.Background(), tenantA, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "pending_activation", got.Status)

	stillGood, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.Nil(t, stillGood.ConsumedAt, "a failed cross tenant activation attempt must not consume the token")

	// The real tenant (resolved from the token) can still activate normally.
	activated, err := repo.ActivateWithToken(context.Background(), tenantA, tok.ID, user.ID, newHash)
	require.NoError(t, err)
	assert.Equal(t, "active", activated.Status)
}

// TestActivateWithTokenSoftDeletedUserReturnsActivationInvalid is the security
// audit gate for the resurrection gap: a pending user who is soft-deleted must
// NOT be reachable through their still-live activation token. SetPasswordAndActivate
// carries a status = 'pending_activation' predicate, so a deleted row matches no
// rows and the whole transaction fails closed with the SAME generic
// model.ErrActivationInvalid every other negative activation case returns (no
// new distinguishable error, preserving the anti-enumeration posture). The user
// must be left exactly as the delete left it: status 'deleted', never flipped
// back to active by an attacker who still holds the activation link.
func TestActivateWithTokenSoftDeletedUserReturnsActivationInvalid(t *testing.T) {
	repo, kr := setup(t)
	user, _, tokenHash, _ := mustProvision(t, repo, kr, tenantA, "deleted.pending@acme.test", "+263771230000")
	tok, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)

	require.NoError(t, repo.SoftDelete(context.Background(), tenantA, user.ID))

	newHash, err := security.HashPassword("ResurrectMe1!")
	require.NoError(t, err)
	_, err = repo.ActivateWithToken(context.Background(), tenantA, tok.ID, user.ID, newHash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid, "activating a soft-deleted user's token must fail with the generic activation error")

	got, err := repo.Get(context.Background(), tenantA, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "deleted", got.Status, "a failed activate against a deleted user must never resurrect it to active")
}

// TestSoftDeleteInvalidatesOutstandingActivationTokens is the gate for the
// second half of the same audit finding: soft-deleting a pending user must
// invalidate its outstanding activation tokens in the SAME transaction that
// flips status to deleted, so the token cannot be used by whoever still holds
// the activation link, independent of the status guard added in part A.
func TestSoftDeleteInvalidatesOutstandingActivationTokens(t *testing.T) {
	repo, kr := setup(t)
	user, _, tokenHash, _ := mustProvision(t, repo, kr, tenantA, "revoke.on.delete@acme.test", "+263771230001")
	tok, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.Nil(t, tok.ConsumedAt, "the freshly issued token starts unconsumed")

	require.NoError(t, repo.SoftDelete(context.Background(), tenantA, user.ID))

	stillThere, err := repo.GetCredentialTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	assert.NotNil(t, stillThere.ConsumedAt, "soft-deleting the user must invalidate its outstanding activation token")

	newHash, err := security.HashPassword("RevokedToken1!")
	require.NoError(t, err)
	_, err = repo.ActivateWithToken(context.Background(), tenantA, tok.ID, user.ID, newHash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid, "a token invalidated by soft-delete can never activate the account")
}
