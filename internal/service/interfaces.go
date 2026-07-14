// Package service holds the identity service business logic for authentication
// and user lifecycle management.
package service

import (
	"context"
	"time"

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

	// ProvisionPendingAdmin creates a user in the pending_activation state plus
	// a bound activation credential token, in ONE atomic transaction. It never
	// accepts a caller supplied password: the repository stores a random,
	// unusable hash so the row is valid until Activate sets a real one.
	ProvisionPendingAdmin(ctx context.Context, tenantID uuid.UUID, in model.NewPendingUser, emailEncrypted string, phoneEncrypted []byte, passwordHash string, tokenHash []byte, expiresAt time.Time) (model.User, error)
	// GetCredentialTokenByHash resolves a credential token by its hash with NO
	// tenant context (credential_tokens is service-global, like crypto_keys);
	// the pre-auth activate lookup has no app.tenant_id to scope by.
	GetCredentialTokenByHash(ctx context.Context, hash []byte) (model.CredentialToken, error)
	// ActivateWithToken atomically consumes the named credential token
	// (failing closed on a lost race) and sets the user's password and status
	// active, both under WithTenant(tenantID) so the RLS-scoped user write and
	// the token consume are one transaction.
	ActivateWithToken(ctx context.Context, tenantID, tokenID, userID uuid.UUID, passwordHash string) (model.User, error)
	// InvalidateActivationTokens marks every outstanding (unconsumed)
	// activation token for the user consumed, used before ResendActivation
	// issues a fresh one.
	InvalidateActivationTokens(ctx context.Context, tenantID, userID uuid.UUID) error
	// InsertActivationToken stores a fresh activation token for an already
	// existing pending user, used by ResendActivation.
	InsertActivationToken(ctx context.Context, tenantID, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (model.CredentialToken, error)
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
