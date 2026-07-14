package model

import (
	"time"

	"github.com/google/uuid"
)

// Credential token purposes. Activation is the only purpose Phase 1 issues;
// the taxonomy is extensible to a future password_reset without a schema
// change.
const (
	CredentialTokenPurposeActivation = "activation"
)

// CredentialToken is the domain view of a credential_tokens row resolved by
// its hash. credential_tokens is service-global (no RLS, like crypto_keys):
// TenantID and UserID are plain data columns, not an RLS key, carried so the
// write that follows a successful lookup (consume the token, set the
// password, activate the user) can run under WithTenant(TenantID).
type CredentialToken struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	UserID     uuid.UUID
	Purpose    string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

// IsUsableActivation reports whether the token is an unconsumed, unexpired
// activation token as of now. Any other state (wrong purpose, already
// consumed, expired) is not usable and must map to the same generic error the
// caller returns for every negative case, so a failed activate attempt never
// reveals which specific condition failed.
func (c CredentialToken) IsUsableActivation(now time.Time) bool {
	return c.Purpose == CredentialTokenPurposeActivation && c.ConsumedAt == nil && now.Before(c.ExpiresAt)
}

// NewPendingUser is the input to provision a pending (not yet activated)
// admin user. It mirrors NewUser but carries Phone (PII, encrypted at rest,
// the activation SMS recipient) and never a caller supplied password: the
// repository sets a random, unusable hash and the real password is set later
// through Activate. A pending user is always tenant scoped (practice admin
// provisioning only in Phase 1), so there is no ProviderRole field.
type NewPendingUser struct {
	TenantID    uuid.UUID
	BranchID    *uuid.UUID
	Email       string
	Phone       string
	DisplayName string
	Role        string
}
