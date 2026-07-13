package repository_test

import (
	"context"
	"testing"

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

var (
	tenantA = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	tenantB = uuid.MustParse("00000000-0000-0000-0000-000000000002")
)

func setup(t *testing.T) (*repository.UserRepository, *security.Keyring) {
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
	return repository.NewUserRepository(pool, kr), kr
}

func mustCreate(t *testing.T, repo *repository.UserRepository, kr *security.Keyring, tenant uuid.UUID, email, role string) model.User {
	t.Helper()
	hash, err := security.HashPassword("password123")
	require.NoError(t, err)
	enc, err := kr.Cipher().Encrypt([]byte(email))
	require.NoError(t, err)
	u, err := repo.Create(context.Background(), tenant, model.NewUser{
		TenantID: tenant, Email: email, DisplayName: "Test", Role: role,
	}, string(enc), hash)
	require.NoError(t, err)
	return u
}

func TestCreateAndGetUser(t *testing.T) {
	repo, kr := setup(t)
	created := mustCreate(t, repo, kr, tenantA, "admin@acme.test", model.RolePracticeAdmin)
	assert.NotEqual(t, uuid.Nil, created.ID)
	assert.Equal(t, "admin@acme.test", created.Email)

	got, err := repo.Get(context.Background(), tenantA, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "admin@acme.test", got.Email)
}

func TestCreateProviderUserStoresProviderRole(t *testing.T) {
	repo, kr := setup(t)
	hash, err := security.HashPassword("password123")
	require.NoError(t, err)
	enc, err := kr.Cipher().Encrypt([]byte("provider@omnisurg.test"))
	require.NoError(t, err)

	created, err := repo.Create(context.Background(), model.PlatformTenantID, model.NewUser{
		TenantID:     model.PlatformTenantID,
		Email:        "provider@omnisurg.test",
		DisplayName:  "Provider Admin",
		Role:         "",
		ProviderRole: model.RoleProviderSuperAdmin,
	}, string(enc), hash)
	require.NoError(t, err)
	assert.Equal(t, model.RoleProviderSuperAdmin, created.ProviderRole)
	assert.Empty(t, created.Role)

	got, err := repo.Get(context.Background(), model.PlatformTenantID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, model.RoleProviderSuperAdmin, got.ProviderRole)
}

func TestCreateRejectsBothTenantAndProviderRole(t *testing.T) {
	repo, kr := setup(t)
	hash, err := security.HashPassword("password123")
	require.NoError(t, err)
	enc, err := kr.Cipher().Encrypt([]byte("mixed@omnisurg.test"))
	require.NoError(t, err)

	_, err = repo.Create(context.Background(), model.PlatformTenantID, model.NewUser{
		TenantID:     model.PlatformTenantID,
		Email:        "mixed@omnisurg.test",
		DisplayName:  "Mixed",
		Role:         model.RolePracticeAdmin,
		ProviderRole: model.RoleProviderSuperAdmin,
	}, string(enc), hash)
	assert.ErrorIs(t, err, model.ErrValidation)
}

func TestGetUnknownReturnsNotFound(t *testing.T) {
	repo, _ := setup(t)
	_, err := repo.Get(context.Background(), tenantA, uuid.New())
	assert.ErrorIs(t, err, model.ErrUserNotFound)
}

func TestDuplicateEmailInTenantConflicts(t *testing.T) {
	repo, kr := setup(t)
	mustCreate(t, repo, kr, tenantA, "dupe@acme.test", model.RoleReception)
	hash, _ := security.HashPassword("password123")
	enc, _ := kr.Cipher().Encrypt([]byte("dupe@acme.test"))
	_, err := repo.Create(context.Background(), tenantA, model.NewUser{
		TenantID: tenantA, Email: "dupe@acme.test", DisplayName: "x", Role: model.RoleReception,
	}, string(enc), hash)
	assert.ErrorIs(t, err, model.ErrEmailTaken)
}

func TestSameEmailDifferentTenantsAllowed(t *testing.T) {
	repo, kr := setup(t)
	mustCreate(t, repo, kr, tenantA, "shared@x.test", model.RoleReception)
	// Same email in tenant B must succeed because the unique index is per tenant.
	mustCreate(t, repo, kr, tenantB, "shared@x.test", model.RoleReception)
}

func TestAuthByEmailFindsOnlyOwnTenant(t *testing.T) {
	repo, kr := setup(t)
	created := mustCreate(t, repo, kr, tenantA, "login@acme.test", model.RolePracticeAdmin)

	hash := kr.EmailBlindIndex("login@acme.test")
	rec, err := repo.AuthByEmailHash(context.Background(), tenantA, hash)
	require.NoError(t, err)
	assert.Equal(t, created.ID, rec.ID)

	// Tenant B blind index of the same email finds nothing under tenant B scope.
	_, err = repo.AuthByEmailHash(context.Background(), tenantB, hash)
	assert.ErrorIs(t, err, model.ErrUserNotFound)
}

// TestTenantIsolationLeak is the mandatory leak path test from the standard.
// Insert a tenant A row, read as tenant B, expect it invisible, on the same pool.
func TestTenantIsolationLeak(t *testing.T) {
	repo, kr := setup(t)
	a := mustCreate(t, repo, kr, tenantA, "secret@acme.test", model.RolePracticeAdmin)

	// As tenant B: the row is invisible.
	_, err := repo.Get(context.Background(), tenantB, a.ID)
	assert.ErrorIs(t, err, model.ErrUserNotFound)

	// List as tenant B returns zero rows even though tenant A has one.
	usersB, total, err := repo.List(context.Background(), tenantB, 50, 0)
	require.NoError(t, err)
	assert.Empty(t, usersB)
	assert.Equal(t, int64(0), total)

	// List as tenant A returns exactly the one row.
	usersA, totalA, err := repo.List(context.Background(), tenantA, 50, 0)
	require.NoError(t, err)
	assert.Len(t, usersA, 1)
	assert.Equal(t, int64(1), totalA)
}

// TestGetReturnsErrorWhenEmailUndecryptable proves that a read fails closed
// when the stored ciphertext cannot be decrypted under the active keyring. The
// row is created under keyring A (whose DEK is persisted in crypto_keys), then
// read through a second repository built over the same pool but with a keyring
// derived from a different raw DEK. The GCM authentication tag mismatch makes
// decryption fail rather than returning garbage plaintext.
func TestGetReturnsErrorWhenEmailUndecryptable(t *testing.T) {
	dsn, stop := harness.StartPostgres(t)
	t.Cleanup(stop)
	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	kek, _ := crypto.GenerateDEK()
	krA, err := security.LoadKeyring(ctx, pool, kek)
	require.NoError(t, err)
	repo := repository.NewUserRepository(pool, krA)

	created := mustCreate(t, repo, krA, tenantA, "encrypted@acme.test", model.RolePracticeAdmin)

	// Build a second repository over the same pool but with a keyring derived
	// from a different raw DEK. The GCM authentication tag mismatch makes the
	// read fail closed rather than returning garbage plaintext.
	divergentDEK, err := crypto.GenerateDEK()
	require.NoError(t, err)
	wrongKR, err := security.NewKeyringFromDEK(divergentDEK)
	require.NoError(t, err)
	wrongRepo := repository.NewUserRepository(pool, wrongKR)

	_, err = wrongRepo.Get(context.Background(), tenantA, created.ID)
	require.Error(t, err)
}

func TestCountProviderSuperAdmins(t *testing.T) {
	repo, kr := setup(t)
	ctx := context.Background()

	// Empty platform tenant: no operators yet.
	count, err := repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// One provider super-admin under the platform tenant.
	hash, err := security.HashPassword("password123")
	require.NoError(t, err)
	enc, err := kr.Cipher().Encrypt([]byte("operator@omnisurg.test"))
	require.NoError(t, err)
	op, err := repo.Create(ctx, model.PlatformTenantID, model.NewUser{
		TenantID:     model.PlatformTenantID,
		Email:        "operator@omnisurg.test",
		DisplayName:  "Operator",
		ProviderRole: model.RoleProviderSuperAdmin,
	}, string(enc), hash)
	require.NoError(t, err)

	count, err = repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// A tenant user with a normal role under a real tenant is not counted.
	mustCreate(t, repo, kr, tenantA, "reception@acme.test", model.RoleReception)
	count, err = repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// A soft-deleted provider super-admin drops out of the count.
	require.NoError(t, repo.SoftDelete(ctx, model.PlatformTenantID, op.ID))
	count, err = repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestUpdateAndSoftDelete(t *testing.T) {
	repo, kr := setup(t)
	u := mustCreate(t, repo, kr, tenantA, "edit@acme.test", model.RoleReception)

	newName := "Edited Name"
	updated, err := repo.Update(context.Background(), tenantA, u.ID, model.UserUpdate{DisplayName: &newName})
	require.NoError(t, err)
	assert.Equal(t, "Edited Name", updated.DisplayName)

	require.NoError(t, repo.SoftDelete(context.Background(), tenantA, u.ID))
	got, err := repo.Get(context.Background(), tenantA, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "deleted", got.Status)
}
