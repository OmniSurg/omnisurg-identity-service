package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/OmniSurg/omnisurg-go-common/logger"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	"github.com/OmniSurg/omnisurg-go-common/tenant"
	api "github.com/OmniSurg/omnisurg-identity-service/internal/generated/api"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

// IdempotencyStore is the handler's view of the idempotency persistence.
type IdempotencyStore interface {
	Lookup(ctx context.Context, tenantID uuid.UUID, key, route string) (repository.StoredResponse, bool, error)
	Save(ctx context.Context, tenantID uuid.UUID, key, route string, status int, body []byte) error
}

// AuditQuerier reads audit rows for the non production debug endpoint.
type AuditQuerier interface {
	Query(ctx context.Context, tenantID uuid.UUID, action string, actorID *uuid.UUID) ([]model.AuditRow, error)
}

// Handler implements api.ServerInterface.
type Handler struct {
	auth  *service.AuthService
	users *service.UserService
	totp  *service.TotpService
	idem  IdempotencyStore
	audit AuditQuerier
	ping  func(context.Context) error
}

// compile time assertion that Handler satisfies the generated contract.
var _ api.ServerInterface = (*Handler)(nil)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type createUserRequest struct {
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName string  `json:"display_name"`
	Role        string  `json:"role"`
	BranchID    *string `json:"branch_id"`
}

type updateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Status      *string `json:"status"`
}

// GetHealth pings the database and returns the service status.
func (h *Handler) GetHealth(c *gin.Context) {
	if h.ping != nil {
		if err := h.ping(c.Request.Context()); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"success": false,
				"error": gin.H{"code": "DEPENDENCY_DOWN", "message": "database is not reachable"}})
			return
		}
	}
	respondSuccess(c, http.StatusOK, gin.H{"status": "ok", "service": "identity-service"})
}

// bindLoginRequest decodes and validates the shared email/password login body.
// It returns false and writes the VALIDATION_FAILED envelope when the body is
// malformed or missing a field, so the caller can return early.
func bindLoginRequest(c *gin.Context) (loginRequest, bool) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Email == "" || req.Password == "" {
		respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "body", "issue": "email and password are required"}}))
		return loginRequest{}, false
	}
	return req, true
}

// Login authenticates a tenant user. Tenant scope comes from X-Tenant-ID.
func (h *Handler) Login(c *gin.Context, params api.LoginParams) {
	if params.XTenantID == nil {
		respondError(c, model.ErrTenantMissing)
		return
	}
	req, ok := bindLoginRequest(c)
	if !ok {
		return
	}
	tenantID := uuid.UUID(*params.XTenantID)
	res, err := h.auth.Login(c.Request.Context(), tenantID, req.Email, req.Password, c.GetString(mw.RequestIDKey))
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{
		"token":      res.Token,
		"expires_at": res.ExpiresAt,
		"user":       presentUser(res.User),
	})
}

// ProviderLogin authenticates a provider (platform) user. It takes no tenant
// header; the issued token carries a provider role and an empty tenant scope.
func (h *Handler) ProviderLogin(c *gin.Context) {
	req, ok := bindLoginRequest(c)
	if !ok {
		return
	}
	res, err := h.auth.ProviderLogin(c.Request.Context(), req.Email, req.Password, c.GetString(mw.RequestIDKey))
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{
		"token":      res.Token,
		"expires_at": res.ExpiresAt,
		"mfa_status": res.MfaStatus,
	})
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// ProviderTotpEnroll starts two factor enrolment for the signed in provider. The
// account acted on is the token subject; no user id is taken from the body.
func (h *Handler) ProviderTotpEnroll(c *gin.Context) {
	caller, ok := providerCallerFrom(c)
	if !ok {
		respondError(c, model.ErrForbidden)
		return
	}
	res, err := h.totp.Enroll(c.Request.Context(), caller)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{
		"secret":      res.Secret,
		"otpauth_uri": res.OtpauthURI,
	})
}

// ProviderTotpConfirm confirms enrolment with a code and returns a full session
// token. The account acted on is the token subject; no user id is taken from the
// body.
func (h *Handler) ProviderTotpConfirm(c *gin.Context) {
	caller, ok := providerCallerFrom(c)
	if !ok {
		respondError(c, model.ErrForbidden)
		return
	}
	var req totpCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Code == "" {
		respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "code", "issue": "a code is required"}}))
		return
	}
	res, err := h.totp.Confirm(c.Request.Context(), caller, req.Code)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{
		"token":      res.Token,
		"expires_at": res.ExpiresAt,
	})
}

// ProviderTotpVerify completes sign in with a code and returns a full session
// token. The account acted on is the token subject; no user id is taken from the
// body.
func (h *Handler) ProviderTotpVerify(c *gin.Context) {
	caller, ok := providerCallerFrom(c)
	if !ok {
		respondError(c, model.ErrForbidden)
		return
	}
	var req totpCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Code == "" {
		respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "code", "issue": "a code is required"}}))
		return
	}
	res, err := h.totp.Verify(c.Request.Context(), caller, req.Code)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{
		"token":      res.Token,
		"expires_at": res.ExpiresAt,
	})
}

// ProviderTotpReset lets a super admin clear another provider's second factor.
// The route RBAC restricts this to provider_super_admin; the handler builds the
// provider caller (the acting super admin) and passes the target id from the
// path. The audit row written by the service records both parties.
func (h *Handler) ProviderTotpReset(c *gin.Context, id openapi_types.UUID) {
	caller, ok := providerCallerFrom(c)
	if !ok {
		respondError(c, model.ErrForbidden)
		return
	}
	target := uuid.UUID(id)
	if err := h.totp.Reset(c.Request.Context(), caller, target); err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{"id": target.String(), "status": "reset"})
}

// GetMe returns the authenticated caller.
func (h *Handler) GetMe(c *gin.Context) {
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	u, err := h.users.Get(c.Request.Context(), caller, caller.UserID)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, presentUser(u))
}

// CreateUser creates a user with optional idempotency replay.
func (h *Handler) CreateUser(c *gin.Context, params api.CreateUserParams) {
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	const route = "POST /api/v1/identity/users"
	idemKey := ""
	if params.XIdempotencyKey != nil {
		idemKey = *params.XIdempotencyKey
	}
	if idemKey != "" {
		stored, found, lerr := h.idem.Lookup(c.Request.Context(), caller.TenantID, idemKey, route)
		if lerr != nil {
			lg := logger.FromContext(c.Request.Context())
			lg.Warn().Err(lerr).Msg("idempotency lookup failed, proceeding without replay")
		} else if found {
			c.Data(stored.StatusCode, "application/json; charset=utf-8", stored.Body)
			return
		}
	}

	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "body", "issue": "malformed json"}}))
		return
	}
	user, err := h.users.Create(c.Request.Context(), caller, model.NewUser{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		Role:        req.Role,
		BranchID:    parseOptUUID(req.BranchID),
	})
	if err != nil {
		respondError(c, err)
		return
	}
	body, mErr := json.Marshal(gin.H{"success": true, "data": presentUser(user)})
	if mErr != nil {
		respondError(c, mErr)
		return
	}
	if idemKey != "" {
		_ = h.idem.Save(c.Request.Context(), caller.TenantID, idemKey, route, http.StatusCreated, body)
	}
	c.Data(http.StatusCreated, "application/json; charset=utf-8", body)
}

// ListUsers lists the tenant's users.
func (h *Handler) ListUsers(c *gin.Context, params api.ListUsersParams) {
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	var limit, offset int32 = 50, 0
	if params.Limit != nil {
		limit = int32(*params.Limit)
	}
	if params.Offset != nil {
		offset = int32(*params.Offset)
	}
	users, total, err := h.users.List(c.Request.Context(), caller, limit, offset)
	if err != nil {
		respondError(c, err)
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, presentUser(u))
	}
	respondSuccess(c, http.StatusOK, gin.H{"users": out, "total_count": total})
}

// GetUser fetches a user by id.
func (h *Handler) GetUser(c *gin.Context, id openapi_types.UUID) {
	uid := uuid.UUID(id)
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	u, err := h.users.Get(c.Request.Context(), caller, uid)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, presentUser(u))
}

// UpdateUser mutates display name or status.
func (h *Handler) UpdateUser(c *gin.Context, id openapi_types.UUID) {
	uid := uuid.UUID(id)
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "body", "issue": "malformed json"}}))
		return
	}
	u, err := h.users.Update(c.Request.Context(), caller, uid, model.UserUpdate{DisplayName: req.DisplayName, Status: req.Status})
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, presentUser(u))
}

// DeleteUser soft deletes a user.
func (h *Handler) DeleteUser(c *gin.Context, id openapi_types.UUID) {
	uid := uuid.UUID(id)
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	if err := h.users.Delete(c.Request.Context(), caller, uid); err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{"id": uid.String(), "status": "deleted"})
}

func callerFrom(c *gin.Context) (service.Caller, bool) {
	id, ok := tenant.Get(c)
	if !ok {
		return service.Caller{}, false
	}
	tid, err := uuid.Parse(id.TenantID)
	if err != nil {
		return service.Caller{}, false
	}
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return service.Caller{}, false
	}
	return service.Caller{
		UserID:    uid,
		TenantID:  tid,
		Role:      id.Role,
		RequestID: c.GetString(mw.RequestIDKey),
	}, true
}

// providerCallerFrom builds a service.Caller for a provider (platform) request.
// It requires the verified identity to carry a provider_role and resolves the
// user id from the token subject. Provider users live under the reserved
// platform tenant, so TenantID is set to it regardless of the (empty) tenant
// claim. It returns false when the caller is not a provider or the subject is
// unusable, so the handler can return 403.
func providerCallerFrom(c *gin.Context) (service.Caller, bool) {
	id, ok := tenant.Get(c)
	if !ok || id.ProviderRole == "" {
		return service.Caller{}, false
	}
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return service.Caller{}, false
	}
	return service.Caller{
		UserID:       uid,
		TenantID:     model.PlatformTenantID,
		ProviderRole: id.ProviderRole,
		RequestID:    c.GetString(mw.RequestIDKey),
	}, true
}

func parseOptUUID(s *string) *uuid.UUID {
	if s == nil || *s == "" {
		return nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil
	}
	return &id
}
