package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CredentialTokenRepo persists and resolves credential_tokens rows.
// credential_tokens is SERVICE-GLOBAL (no RLS), exactly like crypto_keys: the
// pre-auth activate lookup has no app.tenant_id to scope by, so GetByHash runs
// on the bare pool. The writes (Insert, Consume, InvalidateForUser) run under
// WithTenant purely to share connection lifecycle discipline with the sibling
// user writes; the GUC has no bearing on this table's own visibility.
type CredentialTokenRepo struct {
	pool *pgxpool.Pool
}

// NewCredentialTokenRepo builds a CredentialTokenRepo.
func NewCredentialTokenRepo(pool *pgxpool.Pool) *CredentialTokenRepo {
	return &CredentialTokenRepo{pool: pool}
}

// GetByHash resolves a credential token by its hash on the BARE pool, with NO
// tenant context set. Isolation comes from the token's 256-bit entropy: only
// the holder of the raw token can resolve its row, and the row binds exactly
// one tenant and user. An unknown hash maps to model.ErrActivationInvalid
// (the same generic error every negative activation case returns).
func (r *CredentialTokenRepo) GetByHash(ctx context.Context, hash []byte) (model.CredentialToken, error) {
	row, err := db.New(r.pool).GetCredentialTokenByHash(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.CredentialToken{}, model.ErrActivationInvalid
	}
	if err != nil {
		return model.CredentialToken{}, fmt.Errorf("get credential token by hash: %w", err)
	}
	return toDomainToken(row.ID, row.TenantID, row.UserID, row.Purpose, row.ExpiresAt, row.ConsumedAt), nil
}

// Insert stores a fresh credential token bound to tenantID and userID.
func (r *CredentialTokenRepo) Insert(ctx context.Context, tenantID, userID uuid.UUID, tokenHash []byte, purpose string, expiresAt time.Time) (model.CredentialToken, error) {
	var out model.CredentialToken
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).InsertCredentialToken(ctx, db.InsertCredentialTokenParams{
			TenantID:  pgUUID(tenantID),
			UserID:    pgUUID(userID),
			Purpose:   purpose,
			TokenHash: tokenHash,
			ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		})
		if qerr != nil {
			return fmt.Errorf("insert credential token: %w", qerr)
		}
		out = toDomainToken(row.ID, row.TenantID, row.UserID, row.Purpose, row.ExpiresAt, row.ConsumedAt)
		return nil
	})
	if err != nil {
		return model.CredentialToken{}, err
	}
	return out, nil
}

// Consume marks the named token consumed, but only if it is not already
// consumed (a single-shot conditional update). It reports false, not an
// error, when the token was already consumed or does not exist, so a caller
// can distinguish "lost the race" from a hard failure.
func (r *CredentialTokenRepo) Consume(ctx context.Context, tenantID, tokenID uuid.UUID) (bool, error) {
	var accepted bool
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		_, qerr := db.New(conn).ConsumeCredentialToken(ctx, pgUUID(tokenID))
		if errors.Is(qerr, pgx.ErrNoRows) {
			accepted = false
			return nil
		}
		if qerr != nil {
			return fmt.Errorf("consume credential token: %w", qerr)
		}
		accepted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return accepted, nil
}

// InvalidateForUser marks every outstanding (unconsumed) activation token for
// the user consumed, so a fresh resend cannot be joined by a still-live prior
// link.
func (r *CredentialTokenRepo) InvalidateForUser(ctx context.Context, tenantID, userID uuid.UUID) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		if qerr := db.New(conn).InvalidateActivationTokensForUser(ctx, pgUUID(userID)); qerr != nil {
			return fmt.Errorf("invalidate activation tokens: %w", qerr)
		}
		return nil
	})
}

// toDomainToken converts the raw pgtype projection common to every
// credential_tokens read into the domain view. ConsumedAt is nil when the
// column is null (the token has not been consumed).
func toDomainToken(id, tenantID, userID pgtype.UUID, purpose string, expiresAt, consumedAt pgtype.Timestamptz) model.CredentialToken {
	tok := model.CredentialToken{
		ID:        fromPgUUID(id),
		TenantID:  fromPgUUID(tenantID),
		UserID:    fromPgUUID(userID),
		Purpose:   purpose,
		ExpiresAt: expiresAt.Time,
	}
	if consumedAt.Valid {
		t := consumedAt.Time
		tok.ConsumedAt = &t
	}
	return tok
}
