// Package security wires the data encryption key lifecycle and password
// hashing for the identity service.
package security

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// emailBlindIndexInfo is the HKDF label that derives the email blind index key
// from the DEK. Distinct labels yield distinct subkeys.
const emailBlindIndexInfo = "omnisurg-identity-email-blind-index"

// Keyring holds the unwrapped DEK derived cipher and blind index key for the
// life of the process.
type Keyring struct {
	cipher    *crypto.Cipher
	emailHKey []byte
}

// LoadKeyring loads the active wrapped DEK from crypto_keys and unwraps it with
// the KEK. On first boot, when no DEK exists, it generates one, wraps it, and
// stores it. crypto_keys has no RLS so these queries run on the bare pool.
func LoadKeyring(ctx context.Context, pool *pgxpool.Pool, kek []byte) (*Keyring, error) {
	q := db.New(pool)

	wrapped, err := q.GetActiveDEK(ctx)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		dek, genErr := crypto.GenerateDEK()
		if genErr != nil {
			return nil, fmt.Errorf("security.LoadKeyring: generate dek: %w", genErr)
		}
		newWrapped, wrapErr := crypto.WrapKey(kek, dek)
		if wrapErr != nil {
			return nil, fmt.Errorf("security.LoadKeyring: wrap dek: %w", wrapErr)
		}
		if _, insErr := q.InsertDEK(ctx, newWrapped); insErr != nil {
			if isUniqueViolation(insErr) {
				// Lost the bootstrap race: another process inserted the winning
				// active DEK first. Reload and unwrap it so both processes share
				// the same key and no row is encrypted under a discarded DEK.
				wrapped, getErr := q.GetActiveDEK(ctx)
				if getErr != nil {
					return nil, fmt.Errorf("security.LoadKeyring: reload after bootstrap race: %w", getErr)
				}
				winner, unwrapErr := crypto.UnwrapKey(kek, wrapped)
				if unwrapErr != nil {
					return nil, fmt.Errorf("security.LoadKeyring: unwrap after bootstrap race: %w", unwrapErr)
				}
				return newKeyring(winner)
			}
			return nil, fmt.Errorf("security.LoadKeyring: persist dek: %w", insErr)
		}
		return newKeyring(dek)
	case err != nil:
		return nil, fmt.Errorf("security.LoadKeyring: load dek: %w", err)
	default:
		dek, unwrapErr := crypto.UnwrapKey(kek, wrapped)
		if unwrapErr != nil {
			return nil, fmt.Errorf("security.LoadKeyring: unwrap dek (wrong KEK?): %w", unwrapErr)
		}
		return newKeyring(dek)
	}
}

// isUniqueViolation reports whether err is a Postgres unique constraint error
// (SQLSTATE 23505). Defined locally rather than reusing the repository helper to
// avoid an import cycle between security and repository.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// NewKeyringFromDEK builds a Keyring directly from a raw DEK. Used by unit
// tests and by callers that already hold an unwrapped DEK.
func NewKeyringFromDEK(dek []byte) (*Keyring, error) {
	return newKeyring(dek)
}

func newKeyring(dek []byte) (*Keyring, error) {
	cipher, err := crypto.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("security.newKeyring: cipher: %w", err)
	}
	hkey, err := crypto.DeriveSubkey(dek, emailBlindIndexInfo)
	if err != nil {
		return nil, fmt.Errorf("security.newKeyring: derive blind index key: %w", err)
	}
	return &Keyring{cipher: cipher, emailHKey: hkey}, nil
}

// Cipher returns the AES-256-GCM cipher for column encryption.
func (k *Keyring) Cipher() *crypto.Cipher { return k.cipher }

// EmailBlindIndex returns the deterministic lookup hash for an email. Email is
// lowercased so lookups are case insensitive.
func (k *Keyring) EmailBlindIndex(email string) string {
	return crypto.BlindIndex(k.emailHKey, normaliseEmail(email))
}

func normaliseEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
