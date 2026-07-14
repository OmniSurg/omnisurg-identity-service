package repository_test

import (
	"context"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/test/harness"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupCredentialTokens builds a CredentialTokenRepo plus a UserRepository
// over the SAME tenant-isolated pool, and a real user row to bind tokens to
// (credential_tokens.user_id references users.id).
func setupCredentialTokens(t *testing.T) (*repository.CredentialTokenRepo, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn, stop := harness.StartPostgres(t)
	t.Cleanup(stop)
	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	kek, _ := crypto.GenerateDEK()
	kr, err := security.LoadKeyring(ctx, pool, kek)
	require.NoError(t, err)

	userRepo := repository.NewUserRepository(pool, kr)
	user := mustCreate(t, userRepo, kr, tenantA, "activation-target@acme.test", model.RolePracticeAdmin)

	return repository.NewCredentialTokenRepo(pool), tenantA, user.ID
}

func TestCredentialTokenGetByHashResolvesWithNoTenantContext(t *testing.T) {
	tokens, tenant, userID := setupCredentialTokens(t)
	raw, hash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	expiresAt := time.Now().UTC().Add(72 * time.Hour)

	inserted, err := tokens.Insert(context.Background(), tenant, userID, hash, model.CredentialTokenPurposeActivation, expiresAt)
	require.NoError(t, err)
	_ = raw

	// GetByHash is called with NO tenant context anywhere in this test (it
	// resolves on the bare pool), proving the service-global, pre-auth lookup
	// really works without app.tenant_id ever being set.
	got, err := tokens.GetByHash(context.Background(), hash)
	require.NoError(t, err)
	assert.Equal(t, inserted.ID, got.ID)
	assert.Equal(t, tenant, got.TenantID)
	assert.Equal(t, userID, got.UserID)
	assert.Equal(t, model.CredentialTokenPurposeActivation, got.Purpose)
	assert.Nil(t, got.ConsumedAt)
	assert.WithinDuration(t, expiresAt, got.ExpiresAt, time.Second)
}

func TestCredentialTokenGetByHashUnknownReturnsActivationInvalid(t *testing.T) {
	tokens, _, _ := setupCredentialTokens(t)
	_, hash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	_, err = tokens.GetByHash(context.Background(), hash)
	assert.ErrorIs(t, err, model.ErrActivationInvalid)
}

func TestCredentialTokenConsumeIsSingleShot(t *testing.T) {
	tokens, tenant, userID := setupCredentialTokens(t)
	_, hash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	inserted, err := tokens.Insert(context.Background(), tenant, userID, hash, model.CredentialTokenPurposeActivation, time.Now().UTC().Add(72*time.Hour))
	require.NoError(t, err)

	first, err := tokens.Consume(context.Background(), tenant, inserted.ID)
	require.NoError(t, err)
	assert.True(t, first, "the first consume of an unconsumed token succeeds")

	second, err := tokens.Consume(context.Background(), tenant, inserted.ID)
	require.NoError(t, err)
	assert.False(t, second, "a second consume of the same token reports not-affected, never an error")

	// The row itself now shows consumed_at set.
	got, err := tokens.GetByHash(context.Background(), hash)
	require.NoError(t, err)
	require.NotNil(t, got.ConsumedAt)
}

func TestCredentialTokenInvalidateForUserMarksOutstandingTokensConsumed(t *testing.T) {
	tokens, tenant, userID := setupCredentialTokens(t)
	_, hashA, err := security.GenerateActivationToken()
	require.NoError(t, err)
	_, hashB, err := security.GenerateActivationToken()
	require.NoError(t, err)
	_, err = tokens.Insert(context.Background(), tenant, userID, hashA, model.CredentialTokenPurposeActivation, time.Now().UTC().Add(72*time.Hour))
	require.NoError(t, err)
	_, err = tokens.Insert(context.Background(), tenant, userID, hashB, model.CredentialTokenPurposeActivation, time.Now().UTC().Add(72*time.Hour))
	require.NoError(t, err)

	require.NoError(t, tokens.InvalidateForUser(context.Background(), tenant, userID))

	gotA, err := tokens.GetByHash(context.Background(), hashA)
	require.NoError(t, err)
	assert.NotNil(t, gotA.ConsumedAt, "invalidate marks every outstanding token for the user consumed")

	gotB, err := tokens.GetByHash(context.Background(), hashB)
	require.NoError(t, err)
	assert.NotNil(t, gotB.ConsumedAt)
}
