package repository

import (
	"context"
	"errors"
	"fmt"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// StoredResponse is a cached idempotent response.
type StoredResponse struct {
	StatusCode int
	Body       []byte
}

// IdempotencyRepository persists POST responses keyed by tenant, key, and route.
type IdempotencyRepository struct {
	pool *pgxpool.Pool
}

// NewIdempotencyRepository builds an IdempotencyRepository.
func NewIdempotencyRepository(pool *pgxpool.Pool) *IdempotencyRepository {
	return &IdempotencyRepository{pool: pool}
}

// Lookup returns the cached response for a key and route, or false if none.
func (r *IdempotencyRepository) Lookup(ctx context.Context, tenantID uuid.UUID, key, route string) (StoredResponse, bool, error) {
	var out StoredResponse
	found := false
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).GetIdempotentResponse(ctx, db.GetIdempotentResponseParams{IdemKey: key, Route: route})
		if errors.Is(qerr, pgx.ErrNoRows) {
			return nil
		}
		if qerr != nil {
			return fmt.Errorf("lookup idempotency: %w", qerr)
		}
		out = StoredResponse{StatusCode: int(row.StatusCode), Body: row.ResponseBody}
		found = true
		return nil
	})
	return out, found, err
}

// Save stores a response. Concurrent duplicate inserts are ignored (DO NOTHING).
func (r *IdempotencyRepository) Save(ctx context.Context, tenantID uuid.UUID, key, route string, status int, body []byte) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		err := db.New(conn).SaveIdempotentResponse(ctx, db.SaveIdempotentResponseParams{
			TenantID:     pgUUID(tenantID),
			IdemKey:      key,
			Route:        route,
			StatusCode:   int32(status),
			ResponseBody: body,
		})
		if err != nil {
			return fmt.Errorf("save idempotency: %w", err)
		}
		return nil
	})
}
