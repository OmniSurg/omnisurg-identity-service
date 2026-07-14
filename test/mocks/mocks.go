// Package mocks provides in memory test doubles for the identity service
// stores and emitters. Used by handler HTTP layer tests.
package mocks

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/google/uuid"
)

// InMemoryUserStore implements service.UserStore.
type InMemoryUserStore struct {
	mu     sync.Mutex
	Users  map[uuid.UUID]model.User
	Auth   map[string]model.AuthRecord // keyed by emailHash
	Totp   map[uuid.UUID]TotpState     // keyed by user id
	Tokens []PendingToken
}

// PendingToken is an in memory credential_tokens row. The field is exported
// so a test can seed one directly (mirroring how Auth and Users are seeded
// directly for Login tests), since provisioning is a gRPC-only path with no
// REST surface for an HTTP layer test to drive.
type PendingToken struct {
	Token model.CredentialToken
	Hash  []byte
}

// TotpState is the in memory two factor record for a user.
type TotpState struct {
	Secret   string
	Enrolled bool
	LastStep int64
	HasStep  bool
}

// NewUserStore builds an empty store.
func NewUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{Users: map[uuid.UUID]model.User{}, Auth: map[string]model.AuthRecord{}, Totp: map[uuid.UUID]TotpState{}}
}

func (m *InMemoryUserStore) Create(ctx context.Context, tenantID uuid.UUID, in model.NewUser, enc, hash string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := model.ValidateRoleExclusivity(in); err != nil {
		return model.User{}, err
	}
	// Test double: dedupe on plaintext email for convenience; the real repository uses the per-tenant email blind index.
	for _, u := range m.Users {
		if u.TenantID == tenantID && u.Email == in.Email {
			return model.User{}, model.ErrEmailTaken
		}
	}
	id := uuid.New()
	u := model.User{ID: id, TenantID: tenantID, Email: in.Email, DisplayName: in.DisplayName, Role: in.Role, ProviderRole: in.ProviderRole, Status: "active"}
	m.Users[id] = u
	return u, nil
}
func (m *InMemoryUserStore) Get(ctx context.Context, tenantID, id uuid.UUID) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrUserNotFound
	}
	return u, nil
}
func (m *InMemoryUserStore) List(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]model.User, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.User
	for _, u := range m.Users {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, int64(len(out)), nil
}
func (m *InMemoryUserStore) Update(ctx context.Context, tenantID, id uuid.UUID, upd model.UserUpdate) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrUserNotFound
	}
	if upd.DisplayName != nil {
		u.DisplayName = *upd.DisplayName
	}
	if upd.Status != nil {
		u.Status = *upd.Status
	}
	m.Users[id] = u
	return u, nil
}
func (m *InMemoryUserStore) SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	u.Status = "deleted"
	m.Users[id] = u
	return nil
}

// ProvisionPendingAdmin mirrors Create but produces a pending_activation user
// and records a bound token entry in Tokens. It does not populate Auth (Login
// tests seed Auth directly, exactly like the Create path already does), so
// tests that need an activate-then-login round trip seed Auth explicitly.
func (m *InMemoryUserStore) ProvisionPendingAdmin(ctx context.Context, tenantID uuid.UUID, in model.NewPendingUser, emailEncrypted string, phoneEncrypted []byte, passwordHash string, tokenHash []byte, expiresAt time.Time) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.Users {
		if u.TenantID == tenantID && u.Email == in.Email {
			return model.User{}, model.ErrEmailTaken
		}
	}
	id := uuid.New()
	u := model.User{ID: id, TenantID: tenantID, BranchID: in.BranchID, Email: in.Email, DisplayName: in.DisplayName, Role: in.Role, Status: "pending_activation"}
	m.Users[id] = u
	m.Tokens = append(m.Tokens, PendingToken{
		Token: model.CredentialToken{ID: uuid.New(), TenantID: tenantID, UserID: id, Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: expiresAt},
		Hash:  tokenHash,
	})
	return u, nil
}

// GetCredentialTokenByHash resolves a token by hash with no tenant filter,
// mirroring the service-global posture of the real repository.
func (m *InMemoryUserStore) GetCredentialTokenByHash(ctx context.Context, hash []byte) (model.CredentialToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pt := range m.Tokens {
		if bytes.Equal(pt.Hash, hash) {
			return pt.Token, nil
		}
	}
	return model.CredentialToken{}, model.ErrActivationInvalid
}

// ActivateWithToken mirrors the atomic repository behaviour: a single-shot
// consume plus a password and status write, both or neither.
func (m *InMemoryUserStore) ActivateWithToken(ctx context.Context, tenantID, tokenID, userID uuid.UUID, passwordHash string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := -1
	for i, pt := range m.Tokens {
		if pt.Token.ID == tokenID {
			idx = i
			break
		}
	}
	if idx == -1 || m.Tokens[idx].Token.ConsumedAt != nil || m.Tokens[idx].Token.TenantID != tenantID {
		return model.User{}, model.ErrActivationInvalid
	}
	u, ok := m.Users[userID]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrActivationInvalid
	}
	now := time.Now().UTC()
	m.Tokens[idx].Token.ConsumedAt = &now
	u.Status = "active"
	m.Users[userID] = u
	for hash, rec := range m.Auth {
		if rec.ID == userID {
			rec.PasswordHash = passwordHash
			rec.Status = "active"
			m.Auth[hash] = rec
		}
	}
	return u, nil
}

// InvalidateActivationTokens marks every outstanding activation token for the
// user consumed.
func (m *InMemoryUserStore) InvalidateActivationTokens(ctx context.Context, tenantID, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for i, pt := range m.Tokens {
		if pt.Token.UserID == userID && pt.Token.TenantID == tenantID && pt.Token.ConsumedAt == nil {
			m.Tokens[i].Token.ConsumedAt = &now
		}
	}
	return nil
}

// InsertActivationToken stores a fresh token entry for an existing user.
func (m *InMemoryUserStore) InsertActivationToken(ctx context.Context, tenantID, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (model.CredentialToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok := model.CredentialToken{ID: uuid.New(), TenantID: tenantID, UserID: userID, Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: expiresAt}
	m.Tokens = append(m.Tokens, PendingToken{Token: tok, Hash: tokenHash})
	return tok, nil
}

func (m *InMemoryUserStore) AuthByEmailHash(ctx context.Context, tenantID uuid.UUID, hash string) (model.AuthRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.Auth[hash]
	if !ok || rec.TenantID != tenantID {
		return model.AuthRecord{}, model.ErrUserNotFound
	}
	return rec, nil
}

func (m *InMemoryUserStore) SetTotpSecret(ctx context.Context, tenantID, id uuid.UUID, plainSecret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	st := m.Totp[id]
	st.Secret = plainSecret
	m.Totp[id] = st
	return nil
}

func (m *InMemoryUserStore) GetTotpSecret(ctx context.Context, tenantID, id uuid.UUID) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return "", false, model.ErrUserNotFound
	}
	st := m.Totp[id]
	return st.Secret, st.Enrolled, nil
}

func (m *InMemoryUserStore) SetMfaEnrolled(ctx context.Context, tenantID, id uuid.UUID, enrolled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	st := m.Totp[id]
	st.Enrolled = enrolled
	m.Totp[id] = st
	u.MFAEnrolled = enrolled
	m.Users[id] = u
	for hash, rec := range m.Auth {
		if rec.ID == id {
			rec.MfaEnrolled = enrolled
			m.Auth[hash] = rec
		}
	}
	return nil
}

func (m *InMemoryUserStore) ClearTotp(ctx context.Context, tenantID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	delete(m.Totp, id)
	u.MFAEnrolled = false
	m.Users[id] = u
	for hash, rec := range m.Auth {
		if rec.ID == id {
			rec.MfaEnrolled = false
			m.Auth[hash] = rec
		}
	}
	return nil
}

// ResetTotpStep clears the recorded last accepted step for a user. Tests use it
// to simulate a fresh TOTP window: after enrolment (which consumes the current
// step) a later login presents a code for a new step, so clearing the recorded
// step lets that code verify rather than being treated as a replay.
func (m *InMemoryUserStore) ResetTotpStep(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.Totp[id]
	st.LastStep = 0
	st.HasStep = false
	m.Totp[id] = st
}

// AcceptTotpStep mirrors the real conditional update: it advances the stored
// last step only when step is strictly greater than the stored one (or none is
// stored yet), returning true on acceptance and false on a replayed or older
// step. A user invisible under the tenant scope matches no row and returns
// (false, nil), exactly like the RLS scoped query.
func (m *InMemoryUserStore) AcceptTotpStep(ctx context.Context, tenantID, id uuid.UUID, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[id]
	if !ok || u.TenantID != tenantID {
		return false, nil
	}
	st := m.Totp[id]
	if st.HasStep && step <= st.LastStep {
		return false, nil
	}
	st.LastStep = step
	st.HasStep = true
	m.Totp[id] = st
	return true, nil
}

// MockAudit implements service.AuditEmitter and handler audit querying.
type MockAudit struct {
	mu     sync.Mutex
	Events []model.AuditEvent
}

func (m *MockAudit) Emit(ctx context.Context, ev model.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, ev)
	return nil
}
func (m *MockAudit) Query(ctx context.Context, tenantID uuid.UUID, action string, actorID *uuid.UUID) ([]model.AuditRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.AuditRow
	for _, e := range m.Events {
		if e.TenantID == tenantID && e.Action == action {
			out = append(out, model.AuditRow{TenantID: e.TenantID, ActorID: e.ActorID, Action: e.Action})
		}
	}
	return out, nil
}

// MockIdempotency implements handler.IdempotencyStore.
type MockIdempotency struct {
	mu    sync.Mutex
	store map[string]repository.StoredResponse
}

// NewIdempotency builds an empty idempotency mock.
func NewIdempotency() *MockIdempotency {
	return &MockIdempotency{store: map[string]repository.StoredResponse{}}
}
func (m *MockIdempotency) Lookup(ctx context.Context, tenantID uuid.UUID, key, route string) (repository.StoredResponse, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.store[tenantID.String()+key+route]
	return v, ok, nil
}
func (m *MockIdempotency) Save(ctx context.Context, tenantID uuid.UUID, key, route string, status int, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[tenantID.String()+key+route] = repository.StoredResponse{StatusCode: status, Body: body}
	return nil
}
