package security_test

import (
	"context"
	"testing"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/test/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyringCreatesThenLoadsSameDEK(t *testing.T) {
	dsn, stop := harness.StartPostgres(t)
	defer stop()
	ctx := context.Background()

	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer pool.Close()

	kek, err := crypto.GenerateDEK()
	require.NoError(t, err)

	// First boot creates and wraps a DEK.
	kr1, err := security.LoadKeyring(ctx, pool, kek)
	require.NoError(t, err)

	// Second boot must load and unwrap the exact same DEK, so encryption with
	// one keyring decrypts with the other.
	kr2, err := security.LoadKeyring(ctx, pool, kek)
	require.NoError(t, err)

	blob, err := kr1.Cipher().Encrypt([]byte("ophthal@acme.test"))
	require.NoError(t, err)
	out, err := kr2.Cipher().Decrypt(blob)
	require.NoError(t, err)
	assert.Equal(t, "ophthal@acme.test", string(out))

	// Blind index is stable across boots.
	assert.Equal(t, kr1.EmailBlindIndex("a@b.test"), kr2.EmailBlindIndex("a@b.test"))
}

func TestKeyringRejectsWrongKEK(t *testing.T) {
	dsn, stop := harness.StartPostgres(t)
	defer stop()
	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer pool.Close()

	kek1, _ := crypto.GenerateDEK()
	_, err = security.LoadKeyring(ctx, pool, kek1)
	require.NoError(t, err)

	kek2, _ := crypto.GenerateDEK()
	_, err = security.LoadKeyring(ctx, pool, kek2)
	require.Error(t, err, "loading with the wrong KEK must fail to unwrap")
}

// TestCryptoKeysSingleActiveConstraint proves the partial unique index rejects a
// second active DEK. Without it, two concurrent first boots could each insert an
// active DEK and rows encrypted under the losing DEK would be undecryptable.
func TestCryptoKeysSingleActiveConstraint(t *testing.T) {
	dsn, stop := harness.StartPostgres(t)
	defer stop()
	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	defer pool.Close()

	q := db.New(pool)
	_, err = q.InsertDEK(ctx, []byte("first-wrapped-dek"))
	require.NoError(t, err)
	_, err = q.InsertDEK(ctx, []byte("second-wrapped-dek"))
	require.Error(t, err, "a second active DEK must violate the single-active unique index")
}
