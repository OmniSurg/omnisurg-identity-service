package handler

import (
	"context"
	"net/http"
	"strings"

	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	api "github.com/OmniSurg/omnisurg-identity-service/internal/generated/api"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// RouterConfig is the dependency set for NewRouter.
type RouterConfig struct {
	Auth        *service.AuthService
	Users       *service.UserService
	Totp        *service.TotpService
	Idem        IdempotencyStore
	Audit       AuditQuerier
	JWTSecret   string
	Env         string
	BaseLogger  zerolog.Logger
	CORSOrigins []string
	Ping        func(context.Context) error
}

// NewRouter builds the full gin engine: middleware chain, public routes,
// JWT protected routes, and RBAC gated user routes. The handler implements the
// generated ServerInterface; routes mount via the generated wrapper so request
// parsing stays contract driven while middleware is applied per route group.
func NewRouter(cfg RouterConfig) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.RequestID())
	r.Use(mw.Logger(cfg.BaseLogger))
	r.Use(mw.Recovery())
	r.Use(corsMiddleware(cfg.CORSOrigins))

	h := &Handler{auth: cfg.Auth, users: cfg.Users, totp: cfg.Totp, idem: cfg.Idem, audit: cfg.Audit, ping: cfg.Ping}
	// ErrorHandler keeps generated parameter binding failures (a malformed
	// X-Tenant-ID uuid, a non integer limit, etc) inside the platform error
	// envelope instead of the wrapper's default plain gin 400.
	wrapper := api.ServerInterfaceWrapper{
		Handler: h,
		ErrorHandler: func(c *gin.Context, err error, statusCode int) {
			respondError(c, model.ErrValidation.WithDetails([]map[string]string{{"field": "request", "issue": err.Error()}}))
		},
	}

	grp := r.Group("/api/v1/identity")
	grp.GET("/health", wrapper.GetHealth)
	grp.POST("/login", wrapper.Login)
	// Provider (platform) login is public and takes no tenant header. It mints a
	// tenant less JWT carrying a provider role.
	grp.POST("/provider/login", wrapper.ProviderLogin)

	authed := grp.Group("", mw.JWTAuth(cfg.JWTSecret))
	authed.GET("/me", wrapper.GetMe)

	// Provider two factor: enrol and confirm require any verified provider token
	// (any mfa state); the handler asserts the provider_role and acts only on the
	// token subject, so a tenant role is not needed and no user id is accepted.
	authed.POST("/provider/totp/enroll", wrapper.ProviderTotpEnroll)
	authed.POST("/provider/totp/confirm", wrapper.ProviderTotpConfirm)
	// Verify is the login second factor: it requires a partial provider token of
	// an enrolled user and mints a full token.
	authed.POST("/provider/totp/verify", wrapper.ProviderTotpVerify)

	// Super admin reset: gated to the EXACT provider_super_admin role, so
	// provider_support, provider_billing, and tenant users are all 403.
	authed.POST("/provider/users/:id/totp/reset", mw.RequireRole(model.RoleProviderSuperAdmin), wrapper.ProviderTotpReset)

	authed.GET("/users", mw.RequireRole(model.RolePracticeAdmin, model.RoleReception), wrapper.ListUsers)
	authed.GET("/users/:id", mw.RequireRole(model.RolePracticeAdmin, model.RoleReception), wrapper.GetUser)
	authed.POST("/users", mw.RequireRole(model.RolePracticeAdmin), wrapper.CreateUser)
	authed.PATCH("/users/:id", mw.RequireRole(model.RolePracticeAdmin), wrapper.UpdateUser)
	authed.DELETE("/users/:id", mw.RequireRole(model.RolePracticeAdmin), wrapper.DeleteUser)

	// Non production debug audit read used only by the Contract Smoke Test.
	if cfg.Env != "production" {
		authed.GET("/_debug/audit", mw.RequireRole(model.RolePracticeAdmin), h.debugAudit)
	}

	return r
}

func (h *Handler) debugAudit(c *gin.Context) {
	caller, ok := callerFrom(c)
	if !ok {
		respondError(c, model.ErrTenantMissing)
		return
	}
	action := c.Query("action")
	var actor *uuid.UUID
	if a := c.Query("actor"); a != "" {
		if id, err := uuid.Parse(a); err == nil {
			actor = &id
		}
	}
	rows, err := h.audit.Query(c.Request.Context(), caller.TenantID, action, actor)
	if err != nil {
		respondError(c, err)
		return
	}
	respondSuccess(c, http.StatusOK, gin.H{"count": len(rows)})
}

func corsMiddleware(origins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[strings.TrimSpace(o)] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, ok := allowed[origin]; ok {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type,X-Tenant-ID,X-Idempotency-Key,X-Request-ID")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
