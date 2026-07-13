package repository

import (
	"context"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/google/uuid"
)

// UserStore is the persistence contract the service layer depends on. Declared
// here so the service package can mock it without importing pgx.
type UserStore interface {
	Create(ctx context.Context, tenantID uuid.UUID, in model.NewUser, emailEncrypted string, passwordHash string) (model.User, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (model.User, error)
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]model.User, int64, error)
	Update(ctx context.Context, tenantID, id uuid.UUID, upd model.UserUpdate) (model.User, error)
	SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error
	AuthByEmailHash(ctx context.Context, tenantID uuid.UUID, emailHash string) (model.AuthRecord, error)
}
