package handler_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/test/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPendingUser creates a pending_activation user directly on the store
// plus a bound activation token, and returns the raw token. Provisioning has
// no REST surface (it is gRPC only), so an HTTP layer test seeds the fixture
// the same way the real gRPC ProvisionUser adapter would leave it.
func seedPendingUser(t *testing.T, store *mocks.InMemoryUserStore, tenant uuid.UUID, email string) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	store.Users[id] = model.User{ID: id, TenantID: tenant, Email: email, DisplayName: "Pending", Role: model.RolePracticeAdmin, Status: "pending_activation"}
	raw, hash, err := security.GenerateActivationToken()
	require.NoError(t, err)
	store.Tokens = append(store.Tokens, mocks.PendingToken{
		Token: model.CredentialToken{ID: uuid.New(), TenantID: tenant, UserID: id, Purpose: model.CredentialTokenPurposeActivation, ExpiresAt: time.Now().Add(time.Hour)},
		Hash:  hash,
	})
	return id, raw
}

type activateResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
		User      struct {
			Status string `json:"status"`
			Email  string `json:"email"`
		} `json:"user"`
	} `json:"data"`
}

func TestActivateHappyPath(t *testing.T) {
	r, store, audit, _ := newFixture(t)
	_, raw := seedPendingUser(t, store, tenantA, "activate.http@acme.test")

	w := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": raw, "new_password": "BrandNewPassword1!"}, nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp activateResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Data.Token)
	assert.Equal(t, "active", resp.Data.User.Status)
	assert.Equal(t, "activate.http@acme.test", resp.Data.User.Email)

	require.Len(t, audit.Events, 1)
	assert.Equal(t, "identity.activate", audit.Events[0].Action)
}

func TestActivateUnknownTokenReturns401(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": "totally-unknown-token-value", "new_password": "GoodPassword1!"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "AUTH_ACTIVATION_INVALID")
}

func TestActivateMissingFieldsReturns422(t *testing.T) {
	r, _, _, _ := newFixture(t)
	w := do(r, "POST", "/api/v1/identity/activate", map[string]string{"token": "something"}, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

func TestActivateShortPasswordReturns422(t *testing.T) {
	r, store, _, _ := newFixture(t)
	_, raw := seedPendingUser(t, store, tenantA, "short.pw@acme.test")
	w := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": raw, "new_password": "short"}, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "VALIDATION_FAILED")
}

func TestActivateConsumedTokenCannotBeReplayed(t *testing.T) {
	r, store, _, _ := newFixture(t)
	_, raw := seedPendingUser(t, store, tenantA, "replay.me@acme.test")

	first := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": raw, "new_password": "FirstPassword1!"}, nil)
	require.Equal(t, http.StatusOK, first.Code)

	second := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": raw, "new_password": "SecondPassword1!"}, nil)
	assert.Equal(t, http.StatusUnauthorized, second.Code)
	assert.Contains(t, second.Body.String(), "AUTH_ACTIVATION_INVALID")
}

// TestActivateIsReachableWithNoAuthorizationHeader proves the endpoint is
// truly public: no Authorization header, no X-Tenant-ID header, exactly like
// login and provider login.
func TestActivateIsReachableWithNoAuthorizationHeader(t *testing.T) {
	r, store, _, _ := newFixture(t)
	_, raw := seedPendingUser(t, store, tenantA, "no.auth.header@acme.test")
	w := do(r, "POST", "/api/v1/identity/activate",
		map[string]string{"token": raw, "new_password": "NoAuthHeader1!"}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}
