package model

import (
	"time"

	"github.com/google/uuid"
)

// Canonical RBAC roles. Mirrors design spec section 10.1. Kept here as the
// service's view of the canonical list; the source of truth is the Role enum
// in omnisurg-proto common.v1.
const (
	RolePracticeAdmin            = "practice_admin"
	RoleClinicianOphthalmologist = "clinician_ophthalmologist"
	RoleClinicianLocum           = "clinician_locum"
	RoleOphthalmicAssistant      = "ophthalmic_assistant"
	RoleReception                = "reception"

	// Platform scoped provider roles. Provider users operate cross tenant (eg a
	// provider_super_admin provisioning the first practice_admin for a new
	// tenant). These mirror the canonical list in common.v1 Role.
	RoleProviderSuperAdmin = "provider_super_admin"
	RoleProviderSupport    = "provider_support"
	RoleProviderBilling    = "provider_billing"
)

// MFA status values returned by provider login. They tell the client whether
// the provider must first enrol a second factor or supply a code from an
// already enrolled one. The login token is always partial (mfa_verified false);
// a full token is minted only by confirm or verify.
const (
	MfaStatusEnrollRequired = "ENROLL_REQUIRED"
	MfaStatusTotpRequired   = "TOTP_REQUIRED"
)

// PlatformTenantID is the reserved tenant id under which provider (platform)
// users are stored in the tenant scoped users table. It is never a real
// practice and never appears as a usable scope in a provider JWT.
var PlatformTenantID = uuid.MustParse("00000000-0000-0000-0000-0000000000aa")

// User is the decrypted domain view of a user row. Email is plaintext here; it
// is only ever decrypted for an authorised response.
type User struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	BranchID     *uuid.UUID
	Email        string
	DisplayName  string
	Role         string
	ProviderRole string
	Status       string
	MFAEnrolled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewUser is the input to create a user. Email and Password are plaintext; the
// repository encrypts and hashes before persistence. Exactly one of Role
// (tenant scoped) or ProviderRole (platform scoped) is set; a provider user
// carries an empty Role, a tenant user carries an empty ProviderRole.
type NewUser struct {
	TenantID     uuid.UUID
	BranchID     *uuid.UUID
	Email        string
	Password     string
	DisplayName  string
	Role         string
	ProviderRole string
}

// ValidateRoleExclusivity rejects a user that carries both a tenant Role and a
// platform ProviderRole. The two scopes are mutually exclusive: a user is
// either a tenant user or a provider (platform) user, never both. It is called
// by every creation path (the repository and the user service) so a direct
// repository write (seed, provider login test setup) is guarded too.
func ValidateRoleExclusivity(in NewUser) error {
	if in.Role != "" && in.ProviderRole != "" {
		return ErrValidation.WithDetails([]map[string]string{
			{"field": "role", "issue": "a user has either a tenant role or a provider role, not both"},
		})
	}
	return nil
}

// AuthRecord is the minimal projection login needs after the blind index match.
// MfaEnrolled lets provider login decide between an enrol-required and a
// second-factor-required state without a second read.
type AuthRecord struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	BranchID     *uuid.UUID
	PasswordHash string
	Role         string
	ProviderRole string
	Status       string
	MfaEnrolled  bool
}

// UserUpdate carries the optional mutable fields for a PATCH.
type UserUpdate struct {
	DisplayName *string
	Status      *string
}
