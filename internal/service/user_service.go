package service

import (
	"context"
	"strings"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// activationTokenTTL is how long a freshly issued or reissued activation
// token stays valid. Fixed per the account activation design; not
// configurable in Phase 1.
const activationTokenTTL = 72 * time.Hour

// UserService holds user CRUD business logic.
type UserService struct {
	store   UserStore
	audit   AuditEmitter
	keyring *security.Keyring
}

// NewUserService builds a UserService.
func NewUserService(store UserStore, audit AuditEmitter, keyring *security.Keyring) *UserService {
	return &UserService{store: store, audit: audit, keyring: keyring}
}

var assignableRoles = map[string]struct{}{
	model.RolePracticeAdmin:            {},
	model.RoleClinicianOphthalmologist: {},
	model.RoleClinicianLocum:           {},
	model.RoleOphthalmicAssistant:      {},
	model.RoleReception:                {},
}

// Create validates, encrypts the email, hashes the password, persists, and
// emits an audit event. The request ID is taken from caller.RequestID and
// carried into the audit record.
func (s *UserService) Create(ctx context.Context, caller Caller, in model.NewUser) (model.User, error) {
	if err := model.ValidateRoleExclusivity(in); err != nil {
		return model.User{}, err
	}
	if details := validateNewUser(in); details != nil {
		return model.User{}, model.ErrValidation.WithDetails(details)
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.TenantID = caller.TenantID

	enc, err := s.keyring.Cipher().Encrypt([]byte(in.Email))
	if err != nil {
		return model.User{}, err
	}
	pwHash, err := security.HashPassword(in.Password)
	if err != nil {
		return model.User{}, err
	}

	user, err := s.store.Create(ctx, caller.TenantID, in, string(enc), pwHash)
	if err != nil {
		return model.User{}, err
	}
	s.emit(ctx, caller, "identity.user.create", user.ID)
	return user, nil
}

// Get returns a user by id.
func (s *UserService) Get(ctx context.Context, caller Caller, id uuid.UUID) (model.User, error) {
	return s.store.Get(ctx, caller.TenantID, id)
}

// List returns the tenant's users.
func (s *UserService) List(ctx context.Context, caller Caller, limit, offset int32) ([]model.User, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.store.List(ctx, caller.TenantID, limit, offset)
}

// Update mutates display name or status.
func (s *UserService) Update(ctx context.Context, caller Caller, id uuid.UUID, upd model.UserUpdate) (model.User, error) {
	if upd.Status != nil && *upd.Status != "active" && *upd.Status != "suspended" {
		return model.User{}, model.ErrValidation.WithDetails([]map[string]string{{"field": "status", "issue": "must be active or suspended"}})
	}
	if upd.DisplayName != nil && strings.TrimSpace(*upd.DisplayName) == "" {
		return model.User{}, model.ErrValidation.WithDetails([]map[string]string{{"field": "display_name", "issue": "must not be empty"}})
	}
	user, err := s.store.Update(ctx, caller.TenantID, id, upd)
	if err != nil {
		return model.User{}, err
	}
	s.emit(ctx, caller, "identity.user.update", user.ID)
	return user, nil
}

// Delete soft deletes a user.
func (s *UserService) Delete(ctx context.Context, caller Caller, id uuid.UUID) error {
	if err := s.store.SoftDelete(ctx, caller.TenantID, id); err != nil {
		return err
	}
	s.emit(ctx, caller, "identity.user.delete", id)
	return nil
}

func (s *UserService) emit(ctx context.Context, caller Caller, action string, targetID uuid.UUID) {
	actor := caller.UserID
	tid := targetID
	if err := s.audit.Emit(ctx, model.AuditEvent{
		TenantID:   caller.TenantID,
		ActorID:    &actor,
		Action:     action,
		TargetType: "user",
		TargetID:   &tid,
		RequestID:  caller.RequestID,
	}); err != nil {
		log.Error().Err(err).Str("action", action).Msg("audit emit failed")
	}
}

// ProvisionResult carries a freshly provisioned or reissued pending admin's
// raw one time activation token and its expiry. The raw token is returned
// exactly once by ProvisionAdmin and ResendActivation and is never persisted
// or logged; only its hash is stored.
type ProvisionResult struct {
	User      model.User
	RawToken  string
	ExpiresAt time.Time
}

// ProvisionAdmin creates a user in the pending_activation state plus a bound,
// one time activation token, and returns the raw token so the caller (the
// admin-bff) can compose the activation link and send it. It never accepts a
// caller supplied password: the repository stores a random, unusable hash so
// the row is valid until Activate sets a real one. Validates like Create
// (email shape, display name, role) but never validates a password (there is
// none yet) and additionally requires a non-empty phone, the activation SMS
// recipient.
func (s *UserService) ProvisionAdmin(ctx context.Context, caller Caller, in model.NewPendingUser) (ProvisionResult, error) {
	if details := validateNewPendingUser(in); details != nil {
		return ProvisionResult{}, model.ErrValidation.WithDetails(details)
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.TenantID = caller.TenantID

	encEmail, err := s.keyring.Cipher().Encrypt([]byte(in.Email))
	if err != nil {
		return ProvisionResult{}, err
	}
	encPhone, err := s.keyring.Cipher().Encrypt([]byte(in.Phone))
	if err != nil {
		return ProvisionResult{}, err
	}
	// The stored password hash is never used to authenticate: it is a random,
	// cryptographically strong discard value so the column is valid, and login
	// is refused anyway because the user is pending_activation.
	seed, err := security.RandomUnusablePassword()
	if err != nil {
		return ProvisionResult{}, err
	}
	pwHash, err := security.HashPassword(seed)
	if err != nil {
		return ProvisionResult{}, err
	}
	rawToken, tokenHash, err := security.GenerateActivationToken()
	if err != nil {
		return ProvisionResult{}, err
	}
	expiresAt := time.Now().UTC().Add(activationTokenTTL)

	user, err := s.store.ProvisionPendingAdmin(ctx, caller.TenantID, in, string(encEmail), encPhone, pwHash, tokenHash, expiresAt)
	if err != nil {
		return ProvisionResult{}, err
	}
	s.emit(ctx, caller, "identity.user.provision", user.ID)
	return ProvisionResult{User: user, RawToken: rawToken, ExpiresAt: expiresAt}, nil
}

// ResendActivation invalidates any outstanding activation token for the named
// pending user and issues a fresh one. Only valid while the user is still
// pending_activation; an already active user has nothing to resend.
func (s *UserService) ResendActivation(ctx context.Context, caller Caller, userID uuid.UUID) (ProvisionResult, error) {
	user, err := s.store.Get(ctx, caller.TenantID, userID)
	if err != nil {
		return ProvisionResult{}, err
	}
	if user.Status != "pending_activation" {
		return ProvisionResult{}, model.ErrNotPendingActivation
	}
	if err := s.store.InvalidateActivationTokens(ctx, caller.TenantID, userID); err != nil {
		return ProvisionResult{}, err
	}
	rawToken, tokenHash, err := security.GenerateActivationToken()
	if err != nil {
		return ProvisionResult{}, err
	}
	expiresAt := time.Now().UTC().Add(activationTokenTTL)
	if _, err := s.store.InsertActivationToken(ctx, caller.TenantID, userID, tokenHash, expiresAt); err != nil {
		return ProvisionResult{}, err
	}
	s.emit(ctx, caller, "identity.user.resend_activation", userID)
	return ProvisionResult{User: user, RawToken: rawToken, ExpiresAt: expiresAt}, nil
}

// validateNewPendingUser mirrors validateNewUser but for a pending admin: no
// password (there is none yet), and phone is required since it is the
// activation SMS recipient.
func validateNewPendingUser(in model.NewPendingUser) []map[string]string {
	var d []map[string]string
	if !strings.Contains(in.Email, "@") {
		d = append(d, map[string]string{"field": "email", "issue": "must be a valid email"})
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		d = append(d, map[string]string{"field": "display_name", "issue": "must not be empty"})
	}
	if _, ok := assignableRoles[in.Role]; !ok {
		d = append(d, map[string]string{"field": "role", "issue": "must be a canonical tenant role"})
	}
	if strings.TrimSpace(in.Phone) == "" {
		d = append(d, map[string]string{"field": "phone", "issue": "must not be empty"})
	}
	return d
}

func validateNewUser(in model.NewUser) []map[string]string {
	var d []map[string]string
	if !strings.Contains(in.Email, "@") {
		d = append(d, map[string]string{"field": "email", "issue": "must be a valid email"})
	}
	if len(in.Password) < 8 {
		d = append(d, map[string]string{"field": "password", "issue": "must be at least 8 characters"})
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		d = append(d, map[string]string{"field": "display_name", "issue": "must not be empty"})
	}
	if _, ok := assignableRoles[in.Role]; !ok {
		d = append(d, map[string]string{"field": "role", "issue": "must be a canonical tenant role"})
	}
	return d
}
