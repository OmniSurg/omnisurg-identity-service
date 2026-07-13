package bootstrap_test

import (
	"context"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/bootstrap"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/test/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestRunCreatesExactlyOneOperator(t *testing.T) {
	repo, kr := setup(t)
	ctx := context.Background()

	result, err := bootstrap.Run(ctx, repo, kr, bootstrap.Params{
		Email:       "operator@omnisurg.test",
		Password:    "correct horse battery",
		DisplayName: "Platform Operator",
	})
	require.NoError(t, err)

	assert.True(t, result.Created, "first run must create an operator")
	assert.Equal(t, "operator@omnisurg.test", result.Email)
	assert.NotEmpty(t, result.Secret, "a fresh base32 secret must be returned")
	assert.NotEmpty(t, result.OtpauthURI, "an otpauth uri must be returned")

	// Exactly one provider super-admin now exists under the platform tenant.
	count, err := repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// It is stored as a provider super-admin with an empty tenant role, enrolled
	// for two factor, under the platform tenant.
	hashIdx := kr.EmailBlindIndex("operator@omnisurg.test")
	rec, err := repo.AuthByEmailHash(ctx, model.PlatformTenantID, hashIdx)
	require.NoError(t, err)
	assert.Equal(t, model.RoleProviderSuperAdmin, rec.ProviderRole)
	assert.Empty(t, rec.Role)
	assert.True(t, rec.MfaEnrolled, "operator must be enrolled so login lands in TOTP_REQUIRED")

	// The stored secret round-trips to the returned base32 secret.
	stored, enrolled, err := repo.GetTotpSecret(ctx, model.PlatformTenantID, rec.ID)
	require.NoError(t, err)
	assert.True(t, enrolled)
	assert.Equal(t, result.Secret, stored)
}

func TestRunIsIdempotent(t *testing.T) {
	repo, kr := setup(t)
	ctx := context.Background()

	first, err := bootstrap.Run(ctx, repo, kr, bootstrap.Params{
		Email:       "operator@omnisurg.test",
		Password:    "correct horse battery",
		DisplayName: "Platform Operator",
	})
	require.NoError(t, err)
	require.True(t, first.Created)

	// A second run, even with different credentials, no-ops: it must not mint a
	// second operator nor re-issue a secret (that would break an enrolled one).
	second, err := bootstrap.Run(ctx, repo, kr, bootstrap.Params{
		Email:       "someone.else@omnisurg.test",
		Password:    "another long password",
		DisplayName: "Someone Else",
	})
	require.NoError(t, err)
	assert.False(t, second.Created, "second run must report an existing operator")
	assert.Empty(t, second.Secret, "no secret is returned on the no-op path")

	// Still exactly one operator, and its secret is unchanged from the first run.
	count, err := repo.CountProviderSuperAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	hashIdx := kr.EmailBlindIndex("operator@omnisurg.test")
	rec, err := repo.AuthByEmailHash(ctx, model.PlatformTenantID, hashIdx)
	require.NoError(t, err)
	stored, _, err := repo.GetTotpSecret(ctx, model.PlatformTenantID, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, first.Secret, stored, "the first operator's secret must be untouched")
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"valid", "op@omnisurg.test", "op@omnisurg.test", false},
		{"trims surrounding space", "  op@omnisurg.test  ", "op@omnisurg.test", false},
		{"blank", "", "", true},
		{"whitespace only", "   ", "", true},
		{"no at sign", "op.omnisurg.test", "", true},
		{"no domain dot", "op@localhost", "", true},
		{"nothing before at", "@omnisurg.test", "", true},
		{"nothing after at", "op@", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bootstrap.ValidateEmail(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid twelve chars", "abcdef123456", false},
		{"valid long", "correct horse battery staple", false},
		{"blank", "", true},
		{"whitespace only", "            ", true},
		{"too short", "short", true},
		{"eleven chars", "abcdef12345", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bootstrap.ValidatePassword(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.in, got)
		})
	}
}

func TestDisplayNameOrDefault(t *testing.T) {
	assert.Equal(t, "Platform Operator", bootstrap.DisplayNameOrDefault(""))
	assert.Equal(t, "Platform Operator", bootstrap.DisplayNameOrDefault("   "))
	assert.Equal(t, "Jane Operator", bootstrap.DisplayNameOrDefault("  Jane Operator  "))
}
