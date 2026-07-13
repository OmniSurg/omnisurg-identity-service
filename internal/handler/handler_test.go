package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	api "github.com/OmniSurg/omnisurg-identity-service/internal/generated/api"
	"github.com/OmniSurg/omnisurg-identity-service/internal/handler"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/OmniSurg/omnisurg-identity-service/test/mocks"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secret = "http-test-secret"

var tenantA = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func newFixture(t *testing.T) (http.Handler, *mocks.InMemoryUserStore, *mocks.MockAudit, *security.Keyring) {
	t.Helper()
	store := mocks.NewUserStore()
	audit := &mocks.MockAudit{}
	kr, err := security.NewKeyringFromDEK(mustDEK(t))
	require.NoError(t, err)

	auth := service.NewAuthService(store, audit, kr, secret, time.Hour)
	users := service.NewUserService(store, audit, kr)
	totpSvc := service.NewTotpService(store, audit, secret, time.Hour)
	r := handler.NewRouter(handler.RouterConfig{
		Auth:      auth,
		Users:     users,
		Totp:      totpSvc,
		Idem:      mocks.NewIdempotency(),
		Audit:     audit,
		JWTSecret: secret,
		Env:       "local",
		Ping:      func(context.Context) error { return nil },
	})
	return r, store, audit, kr
}

func mustDEK(t *testing.T) []byte {
	t.Helper()
	// 32 bytes of deterministic content for the test keyring.
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func seedUser(t *testing.T, store *mocks.InMemoryUserStore, kr *security.Keyring, email, password, role string) uuid.UUID {
	t.Helper()
	hash, err := security.HashPassword(password)
	require.NoError(t, err)
	id := uuid.New()
	store.Auth[kr.EmailBlindIndex(email)] = model.AuthRecord{ID: id, TenantID: tenantA, PasswordHash: hash, Role: role, Status: "active"}
	store.Users[id] = model.User{ID: id, TenantID: tenantA, Email: email, Role: role, Status: "active"}
	return id
}

func token(t *testing.T, userID uuid.UUID, role string) string {
	t.Helper()
	tok, err := ojwt.Sign(ojwt.Claims{Subject: userID.String(), TenantID: tenantA.String(), Role: role}, secret, time.Hour)
	require.NoError(t, err)
	return tok
}

func do(r http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHealthOK(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "GET", "/api/v1/identity/health", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestLoginMissingTenantHeader(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/login",
		map[string]string{"email": "a@acme.test", "password": "password123"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_TENANT_MISSING")
}

func TestLoginValidationFailure(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/login", map[string]string{"email": "a@acme.test"},
		map[string]string{"X-Tenant-ID": tenantA.String()})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

func TestLoginBadCredentials(t *testing.T) {
	r, store, _, kr := newFixture(t)
	seedUser(t, store, kr, "real@acme.test", "password123", model.RoleReception)
	w := do(r, "POST", "/api/v1/identity/login",
		map[string]string{"email": "real@acme.test", "password": "wrong"},
		map[string]string{"X-Tenant-ID": tenantA.String()})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_BAD_CREDENTIALS")
}

func TestLoginHappyPath(t *testing.T) {
	r, store, audit, kr := newFixture(t)
	seedUser(t, store, kr, "admin@acme.test", "password123", model.RolePracticeAdmin)
	w := do(r, "POST", "/api/v1/identity/login",
		map[string]string{"email": "admin@acme.test", "password": "password123"},
		map[string]string{"X-Tenant-ID": tenantA.String()})
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data.Token)
	assert.Len(t, audit.Events, 1)
}

func seedProviderUser(t *testing.T, store *mocks.InMemoryUserStore, kr *security.Keyring, email, password, providerRole string) uuid.UUID {
	t.Helper()
	hash, err := security.HashPassword(password)
	require.NoError(t, err)
	id := uuid.New()
	store.Auth[kr.EmailBlindIndex(email)] = model.AuthRecord{ID: id, TenantID: model.PlatformTenantID, PasswordHash: hash, ProviderRole: providerRole, Status: "active"}
	store.Users[id] = model.User{ID: id, TenantID: model.PlatformTenantID, Email: email, ProviderRole: providerRole, Status: "active"}
	return id
}

func TestProviderLoginHappyPath(t *testing.T) {
	r, store, audit, kr := newFixture(t)
	id := seedProviderUser(t, store, kr, "provider.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin)
	// No X-Tenant-ID header is sent.
	w := do(r, "POST", "/api/v1/identity/provider/login",
		map[string]string{"email": "provider.admin@omnisurg.test", "password": "password123"}, nil)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
			MfaStatus string    `json:"mfa_status"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data.Token)
	// The seeded provider is not enrolled, so login steers it to enrol first and
	// the token is partial.
	assert.Equal(t, model.MfaStatusEnrollRequired, resp.Data.MfaStatus)

	claims, err := ojwt.Verify(resp.Data.Token, secret)
	require.NoError(t, err)
	assert.Equal(t, model.RoleProviderSuperAdmin, claims.ProviderRole)
	assert.Empty(t, claims.TenantID)
	assert.False(t, claims.MFAVerified, "login mints a partial token")

	// The reported expiry matches the token's real exp (computed once at signing
	// time), not a recomputed wall clock that drifts by the bcrypt latency.
	require.NotNil(t, claims.ExpiresAt)
	assert.WithinDuration(t, claims.ExpiresAt.Time, resp.Data.ExpiresAt, time.Second)

	// A successful provider login writes an identity.provider_login audit row
	// under the reserved platform tenant for the provider user.
	require.Len(t, audit.Events, 1)
	assert.Equal(t, "identity.provider_login", audit.Events[0].Action)
	assert.Equal(t, model.PlatformTenantID, audit.Events[0].TenantID)
	require.NotNil(t, audit.Events[0].ActorID)
	assert.Equal(t, id, *audit.Events[0].ActorID)
}

func TestProviderLoginBadPassword(t *testing.T) {
	r, store, _, kr := newFixture(t)
	seedProviderUser(t, store, kr, "provider.admin@omnisurg.test", "password123", model.RoleProviderSuperAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/login",
		map[string]string{"email": "provider.admin@omnisurg.test", "password": "wrong"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_BAD_CREDENTIALS")
}

func TestProviderLoginValidationFailure(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/provider/login",
		map[string]string{"email": "provider.admin@omnisurg.test"}, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

func TestMeRequiresAuth(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "GET", "/api/v1/identity/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_UNAUTHORIZED")
}

func TestMeReturnsCaller(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "me@acme.test", "password123", model.RoleReception)
	w := do(r, "GET", "/api/v1/identity/me", nil,
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RoleReception)})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "me@acme.test")
}

func TestCreateUserForbiddenForReception(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "recep@acme.test", "password123", model.RoleReception)
	w := do(r, "POST", "/api/v1/identity/users",
		map[string]any{"email": "new@acme.test", "password": "password123", "display_name": "New", "role": "reception"},
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RoleReception)})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_FORBIDDEN")
}

func TestCreateUserHappyAsAdmin(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "admin@acme.test", "password123", model.RolePracticeAdmin)
	w := do(r, "POST", "/api/v1/identity/users",
		map[string]any{"email": "new@acme.test", "password": "password123", "display_name": "New", "role": "reception"},
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RolePracticeAdmin)})
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "new@acme.test")
}

func TestCreateUserIdempotentReplay(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "admin@acme.test", "password123", model.RolePracticeAdmin)
	hdr := map[string]string{
		"Authorization":     "Bearer " + token(t, id, model.RolePracticeAdmin),
		"X-Idempotency-Key": "abc-123",
	}
	body := map[string]any{"email": "idem@acme.test", "password": "password123", "display_name": "Idem", "role": "reception"}
	w1 := do(r, "POST", "/api/v1/identity/users", body, hdr)
	require.Equal(t, http.StatusCreated, w1.Code)
	w2 := do(r, "POST", "/api/v1/identity/users", body, hdr)
	require.Equal(t, http.StatusCreated, w2.Code)
	assert.Equal(t, w1.Body.String(), w2.Body.String(), "replay returns the first response byte for byte")

	// Only one user with that email exists.
	count := 0
	for _, u := range store.Users {
		if u.Email == "idem@acme.test" {
			count++
		}
	}
	assert.Equal(t, 1, count, "idempotent replay must not create a second row")
}

func TestCreateUserValidation(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "admin@acme.test", "password123", model.RolePracticeAdmin)
	w := do(r, "POST", "/api/v1/identity/users",
		map[string]any{"email": "bad", "password": "short", "display_name": "", "role": "nope"},
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RolePracticeAdmin)})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

// providerToken mints a partial provider token (mfa_verified false) carrying the
// provider role and an empty tenant scope, as provider login issues.
func providerToken(t *testing.T, userID uuid.UUID, providerRole string) string {
	t.Helper()
	tok, err := ojwt.Sign(ojwt.Claims{Subject: userID.String(), ProviderRole: providerRole, MFAVerified: false}, secret, time.Hour)
	require.NoError(t, err)
	return tok
}

// seedPlatformProvider seeds a provider user under the reserved platform tenant
// so the TOTP service can read its email and store its secret.
func seedPlatformProvider(t *testing.T, store *mocks.InMemoryUserStore, email, providerRole string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	store.Users[id] = model.User{ID: id, TenantID: model.PlatformTenantID, Email: email, ProviderRole: providerRole, Status: "active"}
	return id
}

func TestTotpEnrollRequiresAuth(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_UNAUTHORIZED")
}

func TestTotpEnrollForbiddenForTenantUser(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "tenant@acme.test", "password123", model.RolePracticeAdmin)
	// A tenant token carries no provider_role, so enrol is forbidden.
	w := do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil,
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RolePracticeAdmin)})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_FORBIDDEN")
}

func TestTotpEnrollReturnsSecret(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "enrol@omnisurg.test", model.RoleProviderSuperAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)})
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data struct {
			Secret     string `json:"secret"`
			OtpauthURI string `json:"otpauth_uri"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.Secret)
	assert.Contains(t, resp.Data.OtpauthURI, "otpauth://totp/")
	// The user is not yet enrolled.
	assert.False(t, store.Users[id].MFAEnrolled)
}

func TestTotpConfirmHappyPathReturnsFullToken(t *testing.T) {
	r, store, audit, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "confirm@omnisurg.test", model.RoleProviderSuperAdmin)
	tok := "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)

	enrollW := do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil, map[string]string{"Authorization": tok})
	require.Equal(t, http.StatusOK, enrollW.Code)
	totpSecret := store.Totp[id].Secret
	require.NotEmpty(t, totpSecret)
	code, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)

	w := do(r, "POST", "/api/v1/identity/provider/totp/confirm",
		map[string]string{"code": code}, map[string]string{"Authorization": tok})
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	claims, err := ojwt.Verify(resp.Data.Token, secret)
	require.NoError(t, err)
	assert.True(t, claims.MFAVerified, "confirm returns a full token")
	assert.True(t, store.Users[id].MFAEnrolled, "the provider is now enrolled")

	// A confirm writes an audit row.
	found := false
	for _, e := range audit.Events {
		if e.Action == "identity.provider_totp.confirm" {
			found = true
		}
	}
	assert.True(t, found, "confirm emits an audit row")
}

func TestTotpConfirmWrongCodeRejected(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "badcode@omnisurg.test", model.RoleProviderSuperAdmin)
	tok := "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)
	do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil, map[string]string{"Authorization": tok})

	w := do(r, "POST", "/api/v1/identity/provider/totp/confirm",
		map[string]string{"code": "000000"}, map[string]string{"Authorization": tok})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_INVALID_CODE")
	assert.False(t, store.Users[id].MFAEnrolled)
}

func TestTotpConfirmWithoutEnrollIsConflict(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "noenrol@omnisurg.test", model.RoleProviderSuperAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/totp/confirm",
		map[string]string{"code": "123456"},
		map[string]string{"Authorization": "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_NOT_ENROLLED")
}

func TestTotpConfirmMissingCodeIsValidation(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "missing@omnisurg.test", model.RoleProviderSuperAdmin)
	tok := "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)
	do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil, map[string]string{"Authorization": tok})
	w := do(r, "POST", "/api/v1/identity/provider/totp/confirm", map[string]string{}, map[string]string{"Authorization": tok})
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

func TestEnrollWhenAlreadyEnrolledIsConflict(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "already@omnisurg.test", model.RoleProviderSuperAdmin)
	require.NoError(t, store.SetMfaEnrolled(context.Background(), model.PlatformTenantID, id, true))
	w := do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_ALREADY_ENROLLED")
}

// enrollAndConfirm drives a provider through enrol then confirm and returns the
// stored secret so a verify test can mint a fresh code.
func enrollAndConfirm(t *testing.T, r http.Handler, store *mocks.InMemoryUserStore, id uuid.UUID, tok string) string {
	t.Helper()
	do(r, "POST", "/api/v1/identity/provider/totp/enroll", nil, map[string]string{"Authorization": tok})
	secret := store.Totp[id].Secret
	require.NotEmpty(t, secret)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	w := do(r, "POST", "/api/v1/identity/provider/totp/confirm",
		map[string]string{"code": code}, map[string]string{"Authorization": tok})
	require.Equal(t, http.StatusOK, w.Code)
	return secret
}

func TestTotpVerifyHappyPathReturnsFullToken(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "verify@omnisurg.test", model.RoleProviderSuperAdmin)
	tok := "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)
	totpSecret := enrollAndConfirm(t, r, store, id, tok)
	// A real login happens in a later window than enrolment, so the login code is
	// a fresh step. Clear the step consumed by confirm to simulate that window.
	store.ResetTotpStep(id)

	code, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	w := do(r, "POST", "/api/v1/identity/provider/totp/verify",
		map[string]string{"code": code}, map[string]string{"Authorization": tok})
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	claims, err := ojwt.Verify(resp.Data.Token, secret)
	require.NoError(t, err)
	assert.True(t, claims.MFAVerified, "verify returns a full token")
}

func TestTotpVerifyWrongCodeRejected(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "vbad@omnisurg.test", model.RoleProviderSuperAdmin)
	tok := "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)
	enrollAndConfirm(t, r, store, id, tok)

	w := do(r, "POST", "/api/v1/identity/provider/totp/verify",
		map[string]string{"code": "000000"}, map[string]string{"Authorization": tok})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_INVALID_CODE")
}

func TestTotpVerifyUnenrolledIsConflict(t *testing.T) {
	r, store, _, _ := newFixture(t)
	id := seedPlatformProvider(t, store, "vnoenrol@omnisurg.test", model.RoleProviderSuperAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/totp/verify",
		map[string]string{"code": "123456"},
		map[string]string{"Authorization": "Bearer " + providerToken(t, id, model.RoleProviderSuperAdmin)})
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "MFA_NOT_ENROLLED")
}

func TestTotpVerifyRequiresAuth(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/provider/totp/verify", map[string]string{"code": "123456"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTotpResetBySuperAdminClearsTarget(t *testing.T) {
	r, store, audit, _ := newFixture(t)
	target := seedPlatformProvider(t, store, "target@omnisurg.test", model.RoleProviderSuperAdmin)
	require.NoError(t, store.SetMfaEnrolled(context.Background(), model.PlatformTenantID, target, true))
	admin := seedPlatformProvider(t, store, "super@omnisurg.test", model.RoleProviderSuperAdmin)

	w := do(r, "POST", "/api/v1/identity/provider/users/"+target.String()+"/totp/reset", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, admin, model.RoleProviderSuperAdmin)})
	require.Equal(t, http.StatusOK, w.Code)
	assert.False(t, store.Users[target].MFAEnrolled, "the target is no longer enrolled")

	// The audit row records both the actor and the target.
	var ev *model.AuditEvent
	for i := range audit.Events {
		if audit.Events[i].Action == "identity.provider_totp.reset" {
			ev = &audit.Events[i]
		}
	}
	require.NotNil(t, ev)
	require.NotNil(t, ev.ActorID)
	assert.Equal(t, admin, *ev.ActorID)
	require.NotNil(t, ev.TargetID)
	assert.Equal(t, target, *ev.TargetID)
}

func TestTotpResetForbiddenForProviderSupport(t *testing.T) {
	r, store, _, _ := newFixture(t)
	target := seedPlatformProvider(t, store, "target2@omnisurg.test", model.RoleProviderSuperAdmin)
	support := seedPlatformProvider(t, store, "support@omnisurg.test", model.RoleProviderSupport)
	w := do(r, "POST", "/api/v1/identity/provider/users/"+target.String()+"/totp/reset", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, support, model.RoleProviderSupport)})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_FORBIDDEN")
}

func TestTotpResetForbiddenForProviderBilling(t *testing.T) {
	r, store, _, _ := newFixture(t)
	target := seedPlatformProvider(t, store, "target3@omnisurg.test", model.RoleProviderSuperAdmin)
	billing := seedPlatformProvider(t, store, "billing@omnisurg.test", model.RoleProviderBilling)
	w := do(r, "POST", "/api/v1/identity/provider/users/"+target.String()+"/totp/reset", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, billing, model.RoleProviderBilling)})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTotpResetForbiddenForTenantUser(t *testing.T) {
	r, store, _, kr := newFixture(t)
	target := seedPlatformProvider(t, store, "target4@omnisurg.test", model.RoleProviderSuperAdmin)
	staff := seedUser(t, store, kr, "staff@acme.test", "password123", model.RolePracticeAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/users/"+target.String()+"/totp/reset", nil,
		map[string]string{"Authorization": "Bearer " + token(t, staff, model.RolePracticeAdmin)})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTotpResetUnknownTargetIsNotFound(t *testing.T) {
	r, store, _, _ := newFixture(t)
	admin := seedPlatformProvider(t, store, "super5@omnisurg.test", model.RoleProviderSuperAdmin)
	w := do(r, "POST", "/api/v1/identity/provider/users/"+uuid.New().String()+"/totp/reset", nil,
		map[string]string{"Authorization": "Bearer " + providerToken(t, admin, model.RoleProviderSuperAdmin)})
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "USER_NOT_FOUND")
}

// TestTotpRequestBodiesCarryNoUserID is the binding security check: the enrol,
// confirm, and verify contracts must NOT accept a user id, so a provider can
// only ever act on its own token subject. The confirm and verify bodies are the
// shared TotpCodeRequest; enrol has no body at all. We assert the request type
// exposes no id-like field.
func TestTotpRequestBodiesCarryNoUserID(t *testing.T) {
	rt := reflect.TypeOf(api.TotpCodeRequest{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		assert.NotContains(t, name, "user", "the totp code body must not carry a user field")
		assert.NotContains(t, name, "id", "the totp code body must not carry an id field")
	}
}

func TestListUsersForbiddenForClinician(t *testing.T) {
	r, store, _, kr := newFixture(t)
	id := seedUser(t, store, kr, "doc@acme.test", "password123", model.RoleClinicianOphthalmologist)
	w := do(r, "GET", "/api/v1/identity/users", nil,
		map[string]string{"Authorization": "Bearer " + token(t, id, model.RoleClinicianOphthalmologist)})
	assert.Equal(t, http.StatusForbidden, w.Code)
}
