// Package service holds the identity service business logic for authentication
// and user lifecycle management.
package service

import (
	"context"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/google/uuid"
)

// UserStore is the persistence contract (consumer side interface). The
// repository.UserRepository satisfies it structurally.
type UserStore interface {
	Create(ctx context.Context, tenantID uuid.UUID, in model.NewUser, emailEncrypted string, passwordHash string) (model.User, error)
	Get(ctx context.Context, tenantID, id uuid.UUID) (model.User, error)
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]model.User, int64, error)
	Update(ctx context.Context, tenantID, id uuid.UUID, upd model.UserUpdate) (model.User, error)
	SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error
	AuthByEmailHash(ctx context.Context, tenantID uuid.UUID, emailHash string) (model.AuthRecord, error)
	SetTotpSecret(ctx context.Context, tenantID, id uuid.UUID, plainSecret string) error
	GetTotpSecret(ctx context.Context, tenantID, id uuid.UUID) (secret string, enrolled bool, err error)
	SetMfaEnrolled(ctx context.Context, tenantID, id uuid.UUID, enrolled bool) error
	ClearTotp(ctx context.Context, tenantID, id uuid.UUID) error
	AcceptTotpStep(ctx context.Context, tenantID, id uuid.UUID, step int64) (accepted bool, err error)
}

// AuditEmitter records audit events. repository.AuditRepository satisfies it.
type AuditEmitter interface {
	Emit(ctx context.Context, ev model.AuditEvent) error
}

// Caller is the authenticated identity passed from the handler into the service.
// ProviderRole carries the platform scope for provider (tenant less) callers; it
// is empty for tenant users. TenantID is the platform tenant for a provider
// caller.
type Caller struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	BranchID     *uuid.UUID
	Role         string
	ProviderRole string
	RequestID    string
}
