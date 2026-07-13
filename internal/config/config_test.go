package config_test

import (
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setRequired(t *testing.T) {
	t.Setenv("OMNISURG_DATABASE_URL", "postgres://u:p@localhost:5432/omnisurg_identity?sslmode=disable")
	t.Setenv("OMNISURG_JWT_SECRET", "secret")
	t.Setenv("OMNISURG_INTERNAL_API_KEY", "internal")
	t.Setenv("OMNISURG_KEK_BASE64", "bG9jYWwtZGV2LWtlay0wMDAwMDAwMDAwMDAwMDAwMDA=")
}

func TestLoadAppliesDefaults(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Equal(t, 8081, cfg.HTTPPort)
	assert.Equal(t, 9081, cfg.GRPCPort)
	assert.Equal(t, 60, cfg.JWTTTLMinutes)
	assert.Equal(t, "local", cfg.Env)
	assert.True(t, cfg.IsLocal())
	assert.False(t, cfg.IsProduction())
}

func TestLoadFailsWithoutRequired(t *testing.T) {
	t.Setenv("OMNISURG_DATABASE_URL", "")
	_, err := config.Load("")
	require.Error(t, err)
}

func TestLoadSucceedsWithoutInternalAPIKey(t *testing.T) {
	t.Setenv("OMNISURG_DATABASE_URL", "postgres://u:p@localhost:5432/omnisurg_identity?sslmode=disable")
	t.Setenv("OMNISURG_JWT_SECRET", "secret")
	t.Setenv("OMNISURG_KEK_BASE64", "bG9jYWwtZGV2LWtlay0wMDAwMDAwMDAwMDAwMDAwMDA=")
	t.Setenv("OMNISURG_INTERNAL_API_KEY", "")
	cfg, err := config.Load("")
	require.NoError(t, err)
	assert.Empty(t, cfg.InternalAPIKey)
}

func TestDecodeKEKReturns32Bytes(t *testing.T) {
	setRequired(t)
	cfg, err := config.Load("")
	require.NoError(t, err)
	kek, err := cfg.DecodeKEK()
	require.NoError(t, err)
	assert.Len(t, kek, 32)
}

func TestDecodeKEKRejectsWrongLength(t *testing.T) {
	setRequired(t)
	t.Setenv("OMNISURG_KEK_BASE64", "c2hvcnQ=") // "short", 5 bytes
	cfg, err := config.Load("")
	require.NoError(t, err)
	_, err = cfg.DecodeKEK()
	require.Error(t, err)
}
