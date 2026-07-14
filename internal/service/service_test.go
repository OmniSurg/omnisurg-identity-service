package service_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secret = "unit-test-secret"

var tenantA = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// pendingToken is a hand written in memory credential_tokens row.
type pendingToken struct {
	token model.CredentialToken
	hash  []byte
}

// mockStore is a hand written in memory UserStore.
type mockStore struct {
	users     map[uuid.UUID]model.User
	auth      map[string]model.AuthRecord // keyed by emailHash
	totp      map[uuid.UUID]totpState     // keyed by user id
	tokens    []pendingToken
	createErr error
}

type totpState struct {
	secret   string
	enrolled bool
	lastStep int64
	hasStep  bool
}

func newMockStore() *mockStore {
	return &mockStore{users: map[uuid.UUID]model.User{}, auth: map[string]model.AuthRecord{}, totp: map[uuid.UUID]totpState{}}
}

func (m *mockStore) Create(ctx context.Context, tenantID uuid.UUID, in model.NewUser, enc, hash string) (model.User, error) {
	if m.createErr != nil {
		return model.User{}, m.createErr
	}
	if err := model.ValidateRoleExclusivity(in); err != nil {
		return model.User{}, err
	}
	id := uuid.New()
	u := model.User{ID: id, TenantID: tenantID, Email: in.Email, DisplayName: in.DisplayName, Role: in.Role, ProviderRole: in.ProviderRole, Status: "active"}
	m.users[id] = u
	return u, nil
}
func (m *mockStore) Get(ctx context.Context, tenantID, id uuid.UUID) (model.User, error) {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrUserNotFound
	}
	return u, nil
}
func (m *mockStore) List(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]model.User, int64, error) {
	var out []model.User
	for _, u := range m.users {
		if u.TenantID == tenantID {
			out = append(out, u)
		}
	}
	return out, int64(len(out)), nil
}
func (m *mockStore) Update(ctx context.Context, tenantID, id uuid.UUID, upd model.UserUpdate) (model.User, error) {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrUserNotFound
	}
	if upd.DisplayName != nil {
		u.DisplayName = *upd.DisplayName
	}
	if upd.Status != nil {
		u.Status = *upd.Status
	}
	m.users[id] = u
	return u, nil
}
func (m *mockStore) SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	u.Status = "deleted"
	m.users[id] = u
	return nil
}
func (m *mockStore) AuthByEmailHash(ctx context.Context, tenantID uuid.UUID, hash string) (model.AuthRecord, error) {
	rec, ok := m.auth[hash]
	if !ok || rec.TenantID != tenantID {
		return model.AuthRecord{}, model.ErrUserNotFound
	}
	return rec, nil
}

// ProvisionPendingAdmin mirrors Create but produces a pending_activation user
// and records a bound token entry in tokens. It does not populate auth (Login
// tests seed auth directly), so an activate-then-login round trip test seeds
// auth explicitly, exactly like the Create path already requires.
func (m *mockStore) ProvisionPendingAdmin(ctx context.Context, tenantID uuid.UUID, in model.NewPendingUser, emailEncrypted string, phoneEncrypted []byte, passwordHash string, tokenHash []byte, expiresAt time.Time) (model.User, error) {
	for _, u := range m.users {
		if u.TenantID == tenantID && u.Email == in.Email {
			return model.User{}, model.ErrEmailTaken
		}
	}
	id := uuid.New()
	u := model.User{ID: id, TenantID: tenantID, BranchID: in.BranchID, Email: in.Email, DisplayName: in.DisplayName, Role: in.Role, Status: "pending_activation"}
	m.users[id] = u
	m.tokens = append(m.tokens, pendingToken{
		token: model.CredentialToken{ID: uuid.New(), TenantID: tenantID, UserID: id, Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: expiresAt},
		hash:  tokenHash,
	})
	return u, nil
}

// GetCredentialTokenByHash resolves a token by hash with no tenant filter,
// mirroring the service-global posture of the real repository.
func (m *mockStore) GetCredentialTokenByHash(ctx context.Context, hash []byte) (model.CredentialToken, error) {
	for _, pt := range m.tokens {
		if bytes.Equal(pt.hash, hash) {
			return pt.token, nil
		}
	}
	return model.CredentialToken{}, model.ErrActivationInvalid
}

// ActivateWithToken mirrors the atomic repository behaviour: a single-shot
// consume plus a password and status write, both or neither.
func (m *mockStore) ActivateWithToken(ctx context.Context, tenantID, tokenID, userID uuid.UUID, passwordHash string) (model.User, error) {
	idx := -1
	for i, pt := range m.tokens {
		if pt.token.ID == tokenID {
			idx = i
			break
		}
	}
	if idx == -1 || m.tokens[idx].token.ConsumedAt != nil || m.tokens[idx].token.TenantID != tenantID {
		return model.User{}, model.ErrActivationInvalid
	}
	u, ok := m.users[userID]
	if !ok || u.TenantID != tenantID {
		return model.User{}, model.ErrActivationInvalid
	}
	now := time.Now().UTC()
	m.tokens[idx].token.ConsumedAt = &now
	u.Status = "active"
	m.users[userID] = u
	for hash, rec := range m.auth {
		if rec.ID == userID {
			rec.PasswordHash = passwordHash
			rec.Status = "active"
			m.auth[hash] = rec
		}
	}
	return u, nil
}

// InvalidateActivationTokens marks every outstanding activation token for the
// user consumed.
func (m *mockStore) InvalidateActivationTokens(ctx context.Context, tenantID, userID uuid.UUID) error {
	now := time.Now().UTC()
	for i, pt := range m.tokens {
		if pt.token.UserID == userID && pt.token.TenantID == tenantID && pt.token.ConsumedAt == nil {
			m.tokens[i].token.ConsumedAt = &now
		}
	}
	return nil
}

// InsertActivationToken stores a fresh token entry for an existing user.
func (m *mockStore) InsertActivationToken(ctx context.Context, tenantID, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (model.CredentialToken, error) {
	tok := model.CredentialToken{ID: uuid.New(), TenantID: tenantID, UserID: userID, Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: expiresAt}
	m.tokens = append(m.tokens, pendingToken{token: tok, hash: tokenHash})
	return tok, nil
}

// markEnrolled flips MfaEnrolled on the auth record and user with the given id,
// simulating a provider that has confirmed a TOTP secret.
func (m *mockStore) markEnrolled(id uuid.UUID) {
	for hash, rec := range m.auth {
		if rec.ID == id {
			rec.MfaEnrolled = true
			m.auth[hash] = rec
		}
	}
	if u, ok := m.users[id]; ok {
		u.MFAEnrolled = true
		m.users[id] = u
	}
	st := m.totp[id]
	st.enrolled = true
	m.totp[id] = st
}

func (m *mockStore) SetTotpSecret(ctx context.Context, tenantID, id uuid.UUID, plainSecret string) error {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	st := m.totp[id]
	st.secret = plainSecret
	m.totp[id] = st
	return nil
}

func (m *mockStore) GetTotpSecret(ctx context.Context, tenantID, id uuid.UUID) (string, bool, error) {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return "", false, model.ErrUserNotFound
	}
	st := m.totp[id]
	return st.secret, st.enrolled, nil
}

func (m *mockStore) SetMfaEnrolled(ctx context.Context, tenantID, id uuid.UUID, enrolled bool) error {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	st := m.totp[id]
	st.enrolled = enrolled
	m.totp[id] = st
	u.MFAEnrolled = enrolled
	m.users[id] = u
	for hash, rec := range m.auth {
		if rec.ID == id {
			rec.MfaEnrolled = enrolled
			m.auth[hash] = rec
		}
	}
	return nil
}

func (m *mockStore) ClearTotp(ctx context.Context, tenantID, id uuid.UUID) error {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return model.ErrUserNotFound
	}
	delete(m.totp, id)
	u.MFAEnrolled = false
	m.users[id] = u
	for hash, rec := range m.auth {
		if rec.ID == id {
			rec.MfaEnrolled = false
			m.auth[hash] = rec
		}
	}
	return nil
}

// AcceptTotpStep mirrors the real conditional update: it advances the stored
// last step only when step is strictly greater than the stored one (or none is
// stored yet), returning true on acceptance and false on a replayed or older
// step. A user invisible under the tenant scope matches no row and returns
// (false, nil), exactly like the RLS scoped query.
func (m *mockStore) AcceptTotpStep(ctx context.Context, tenantID, id uuid.UUID, step int64) (bool, error) {
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return false, nil
	}
	st := m.totp[id]
	if st.hasStep && step <= st.lastStep {
		return false, nil
	}
	st.lastStep = step
	st.hasStep = true
	m.totp[id] = st
	return true, nil
}

type mockAudit struct{ events []model.AuditEvent }

func (m *mockAudit) Emit(ctx context.Context, ev model.AuditEvent) error {
	m.events = append(m.events, ev)
	return nil
}

func testKeyring(t *testing.T) *security.Keyring {
	t.Helper()
	// Build a keyring directly from a DEK without a database, via the exported
	// constructor used by tests. If LoadKeyring requires a pool, add a
	// security.NewKeyringFromDEK helper (see note in Step 15.2).
	dek, _ := crypto.GenerateDEK()
	kr, err := security.NewKeyringFromDEK(dek)
	require.NoError(t, err)
	return kr
}

func TestLoginHappyPath(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	audit := &mockAudit{}

	password := "password123"
	hash, _ := security.HashPassword(password)
	id := uuid.New()
	emailHash := kr.EmailBlindIndex("admin@acme.test")
	store.auth[emailHash] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: hash, Role: model.RolePracticeAdmin, Status: "active"}
	store.users[id] = model.User{ID: id, TenantID: tenantA, Email: "admin@acme.test", Role: model.RolePracticeAdmin, Status: "active"}

	svc := service.NewAuthService(store, audit, kr, secret, time.Hour)
	res, err := svc.Login(context.Background(), tenantA, "admin@acme.test", password, "req-1")
	require.NoError(t, err)
	assert.NotEmpty(t, res.Token)
	assert.Equal(t, id.String(), mustClaims(t, res.Token).Subject)
	assert.Equal(t, tenantA.String(), mustClaims(t, res.Token).TenantID)
	require.Len(t, audit.events, 1)
	assert.Equal(t, "identity.login", audit.events[0].Action)
}

func TestLoginUnknownEmailReturnsBadCredentials(t *testing.T) {
	store := newMockStore()
	svc := service.NewAuthService(store, &mockAudit{}, testKeyring(t), secret, time.Hour)
	_, err := svc.Login(context.Background(), tenantA, "ghost@acme.test", "x", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
}

func TestLoginWrongPasswordReturnsBadCredentials(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	hash, _ := security.HashPassword("right")
	id := uuid.New()
	store.auth[kr.EmailBlindIndex("u@acme.test")] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: hash, Role: model.RoleReception, Status: "active"}
	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.Login(context.Background(), tenantA, "u@acme.test", "wrong", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
}

func TestLoginSuspendedUserRejected(t *testing.T) {
	store := newMockStore()
	kr := testKeyring(t)
	hash, _ := security.HashPassword("password123")
	id := uuid.New()
	store.auth[kr.EmailBlindIndex("susp@acme.test")] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: hash, Role: model.RoleReception, Status: "suspended"}
	svc := service.NewAuthService(store, &mockAudit{}, kr, secret, time.Hour)
	_, err := svc.Login(context.Background(), tenantA, "susp@acme.test", "password123", "req")
	assert.ErrorIs(t, err, model.ErrBadCredentials)
}

func TestCreateUserValidatesRole(t *testing.T) {
	svc := service.NewUserService(newMockStore(), &mockAudit{}, testKeyring(t))
	_, err := svc.Create(context.Background(), identityFor(model.RolePracticeAdmin), model.NewUser{
		TenantID: tenantA, Email: "x@acme.test", Password: "password123", DisplayName: "X", Role: "not_a_role",
	})
	assert.ErrorIs(t, err, model.ErrValidation)
}

func TestCreateUserValidatesPasswordLength(t *testing.T) {
	svc := service.NewUserService(newMockStore(), &mockAudit{}, testKeyring(t))
	_, err := svc.Create(context.Background(), identityFor(model.RolePracticeAdmin), model.NewUser{
		TenantID: tenantA, Email: "x@acme.test", Password: "short", DisplayName: "X", Role: model.RoleReception,
	})
	assert.ErrorIs(t, err, model.ErrValidation)
}

func TestCreateUserEmitsAudit(t *testing.T) {
	audit := &mockAudit{}
	svc := service.NewUserService(newMockStore(), audit, testKeyring(t))
	_, err := svc.Create(context.Background(), identityFor(model.RolePracticeAdmin), model.NewUser{
		TenantID: tenantA, Email: "new@acme.test", Password: "password123", DisplayName: "New", Role: model.RoleReception,
	})
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	assert.Equal(t, "identity.user.create", audit.events[0].Action)
}

// helpers
func identityFor(role string) service.Caller {
	return service.Caller{UserID: uuid.New(), TenantID: tenantA, Role: role, RequestID: "req"}
}

func mustClaims(t *testing.T, token string) ojwt.Claims {
	t.Helper()
	c, err := ojwt.Verify(token, secret)
	require.NoError(t, err)
	return c
}
