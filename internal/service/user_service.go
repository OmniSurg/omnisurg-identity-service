package service

import (
	"context"
	"strings"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

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
