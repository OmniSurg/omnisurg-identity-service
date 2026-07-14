package service

import (
	"context"
	"errors"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// dummyCompare is a seam so tests can assert the not-found path spends a bcrypt
// compare (HG-B3). It is the real dummy compare in production.
var dummyCompare = security.DummyPasswordCompare

// AuthService authenticates users and issues JWTs.
type AuthService struct {
	store   UserStore
	audit   AuditEmitter
	keyring *security.Keyring
	secret  string
	ttl     time.Duration
}

// NewAuthService builds an AuthService.
func NewAuthService(store UserStore, audit AuditEmitter, keyring *security.Keyring, secret string, ttl time.Duration) *AuthService {
	return &AuthService{store: store, audit: audit, keyring: keyring, secret: secret, ttl: ttl}
}

// LoginResult is the successful login payload.
type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	User      model.User
}

// ProviderLoginResult is the successful provider login payload. ExpiresAt is
// computed once at signing time so the reported expiry never drifts from the
// token's real exp, mirroring LoginResult. The token is always partial
// (mfa_verified false); MfaStatus tells the client whether to enrol a second
// factor (ENROLL_REQUIRED) or supply a code from an enrolled one
// (TOTP_REQUIRED).
type ProviderLoginResult struct {
	Token     string
	ExpiresAt time.Time
	MfaStatus string
}

// IssueProviderToken mints a tenant less JWT for a provider (platform) user.
// Unlike a tenant token the tenant_id and role claims are empty and the
// provider_role claim carries the platform scope; tenant_id is authoritative
// from the verified claim, so an empty value here means the caller has no
// practice scope. MFAVerified is false in Phase 1.
func (s *AuthService) IssueProviderToken(user model.User) (string, error) {
	return ojwt.Sign(ojwt.Claims{
		Subject:      user.ID.String(),
		TenantID:     "",
		BranchID:     "",
		Role:         "",
		ProviderRole: user.ProviderRole,
		MFAVerified:  false,
	}, s.secret, s.ttl)
}

// ProviderLogin authenticates a provider (platform) user. Provider users are
// stored under the reserved platform tenant and carry no practice scope. It
// returns ErrBadCredentials for every failure mode (unknown email, wrong
// password, inactive user, or a user under the platform tenant that has no
// provider role) so the response never leaks which emails exist or whether an
// account has provider access. On success it emits an identity.provider_login
// audit row under the reserved platform tenant.
func (s *AuthService) ProviderLogin(ctx context.Context, email, password, requestID string) (ProviderLoginResult, error) {
	hash := s.keyring.EmailBlindIndex(email)
	rec, err := s.store.AuthByEmailHash(ctx, model.PlatformTenantID, hash)
	if errors.Is(err, model.ErrUserNotFound) {
		// Spend one bcrypt compare so an unknown email is not faster than a
		// known one with a wrong password (HG-B3 timing oracle).
		dummyCompare(password)
		return ProviderLoginResult{}, model.ErrBadCredentials
	}
	if err != nil {
		return ProviderLoginResult{}, err
	}
	if rec.Status != "active" {
		// Spend one bcrypt compare so an inactive user is not faster than an
		// active one with a wrong password (HG-B3 timing oracle).
		dummyCompare(password)
		return ProviderLoginResult{}, model.ErrBadCredentials
	}
	if !security.VerifyPassword(rec.PasswordHash, password) {
		return ProviderLoginResult{}, model.ErrBadCredentials
	}
	// This check MUST stay after VerifyPassword so this path also pays exactly
	// one bcrypt compare (HG-B3). Hoisting it above the password compare would
	// reintroduce the enumeration timing oracle for platform-tenant users
	// without a provider role.
	if rec.ProviderRole == "" {
		return ProviderLoginResult{}, model.ErrBadCredentials
	}

	now := time.Now().UTC()
	token, err := s.IssueProviderToken(model.User{ID: rec.ID, ProviderRole: rec.ProviderRole})
	if err != nil {
		return ProviderLoginResult{}, err
	}

	// The login token is always partial. The status steers the client: enrol a
	// second factor first, or supply a code from an already enrolled one.
	status := model.MfaStatusEnrollRequired
	if rec.MfaEnrolled {
		status = model.MfaStatusTotpRequired
	}

	actor := rec.ID
	if aerr := s.audit.Emit(ctx, model.AuditEvent{
		TenantID:   model.PlatformTenantID,
		ActorID:    &actor,
		Action:     "identity.provider_login",
		TargetType: "user",
		TargetID:   &actor,
		RequestID:  requestID,
	}); aerr != nil {
		// Audit write failure is alertable but must not block a valid login.
		log.Error().Err(aerr).Str("action", "identity.provider_login").Msg("audit emit failed")
	}

	return ProviderLoginResult{Token: token, ExpiresAt: now.Add(s.ttl), MfaStatus: status}, nil
}

// Login verifies credentials within a tenant and issues a token. It returns
// ErrBadCredentials for every failure mode (unknown email, wrong password,
// inactive user) so the response never leaks which emails exist.
func (s *AuthService) Login(ctx context.Context, tenantID uuid.UUID, email, password, requestID string) (LoginResult, error) {
	hash := s.keyring.EmailBlindIndex(email)
	rec, err := s.store.AuthByEmailHash(ctx, tenantID, hash)
	if errors.Is(err, model.ErrUserNotFound) {
		// Spend one bcrypt compare so an unknown email is not faster than a
		// known one with a wrong password (HG-B3 timing oracle).
		dummyCompare(password)
		return LoginResult{}, model.ErrBadCredentials
	}
	if err != nil {
		return LoginResult{}, err
	}
	if rec.Status != "active" {
		// Spend one bcrypt compare so an inactive user is not faster than an
		// active one with a wrong password (HG-B3 timing oracle). This also
		// covers a pending_activation user: they get the exact same generic
		// error as a bad password, never a hint that the account exists but is
		// not yet usable.
		dummyCompare(password)
		return LoginResult{}, model.ErrBadCredentials
	}
	if !security.VerifyPassword(rec.PasswordHash, password) {
		return LoginResult{}, model.ErrBadCredentials
	}

	token, expiresAt, err := s.mintSession(tenantID, rec.ID, rec.BranchID, rec.Role, rec.ProviderRole)
	if err != nil {
		return LoginResult{}, err
	}

	user, err := s.store.Get(ctx, tenantID, rec.ID)
	if err != nil {
		return LoginResult{}, err
	}

	actor := rec.ID
	if aerr := s.audit.Emit(ctx, model.AuditEvent{
		TenantID:   tenantID,
		ActorID:    &actor,
		Action:     "identity.login",
		TargetType: "user",
		TargetID:   &actor,
		RequestID:  requestID,
	}); aerr != nil {
		// Audit write failure is alertable but must not block a valid login.
		log.Error().Err(aerr).Str("action", "identity.login").Msg("audit emit failed")
	}

	return LoginResult{Token: token, ExpiresAt: expiresAt, User: user}, nil
}

// mintSession signs a tenant scoped session JWT and returns its expiry
// (computed once at signing time, so the reported expiry never drifts from
// the token's real exp). Both Login and Activate call this SAME helper so the
// session claims and expiry semantics never diverge between the two paths
// that auto sign a user in.
func (s *AuthService) mintSession(tenantID, userID uuid.UUID, branchID *uuid.UUID, role, providerRole string) (token string, expiresAt time.Time, err error) {
	bID := ""
	if branchID != nil {
		bID = branchID.String()
	}
	now := time.Now().UTC()
	token, err = ojwt.Sign(ojwt.Claims{
		Subject:      userID.String(),
		TenantID:     tenantID.String(),
		BranchID:     bID,
		Role:         role,
		ProviderRole: providerRole,
		MFAVerified:  false,
	}, s.secret, s.ttl)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, now.Add(s.ttl), nil
}

// Activate consumes a one time activation token, sets the caller's chosen
// password, activates the account, and auto signs the user in exactly like
// Login (the same mintSession claims, the same LoginResult shape). Every
// negative case (an unknown, wrong purpose, expired, or already consumed
// token, or a lost consume race) returns the SAME generic
// model.ErrActivationInvalid so a failed attempt never reveals which
// condition failed. The new password is validated up front, before the token
// is even looked up, so a short password is rejected identically regardless
// of whether the supplied token happens to be valid (this also lets the
// Contract Smoke Test exercise the 422 case with no real token).
func (s *AuthService) Activate(ctx context.Context, rawToken, newPassword, requestID string) (LoginResult, error) {
	if len(newPassword) < 8 {
		return LoginResult{}, model.ErrValidation.WithDetails([]map[string]string{{"field": "new_password", "issue": "must be at least 8 characters"}})
	}

	tok, err := s.store.GetCredentialTokenByHash(ctx, security.HashToken(rawToken))
	if err != nil {
		return LoginResult{}, err
	}
	if !tok.IsUsableActivation(time.Now().UTC()) {
		return LoginResult{}, model.ErrActivationInvalid
	}

	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return LoginResult{}, err
	}

	user, err := s.store.ActivateWithToken(ctx, tok.TenantID, tok.ID, tok.UserID, newHash)
	if err != nil {
		return LoginResult{}, err
	}

	token, expiresAt, err := s.mintSession(tok.TenantID, user.ID, user.BranchID, user.Role, user.ProviderRole)
	if err != nil {
		return LoginResult{}, err
	}

	actor := user.ID
	if aerr := s.audit.Emit(ctx, model.AuditEvent{
		TenantID:   tok.TenantID,
		ActorID:    &actor,
		Action:     "identity.activate",
		TargetType: "user",
		TargetID:   &actor,
		RequestID:  requestID,
	}); aerr != nil {
		// Audit write failure is alertable but must not block a valid activation.
		log.Error().Err(aerr).Str("action", "identity.activate").Msg("audit emit failed")
	}

	return LoginResult{Token: token, ExpiresAt: expiresAt, User: user}, nil
}
