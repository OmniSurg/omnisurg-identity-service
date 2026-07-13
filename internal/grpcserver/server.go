// Package grpcserver adapts the gRPC IdentityService contract onto the existing
// internal/service layer. It holds NO business logic: every RPC builds a
// service.Caller from the gRPC identity (set by the shared go-common
// interceptor), maps the request to the service input, calls the SAME method
// the REST handler calls, and maps the domain result or error back. This is the
// gRPC analogue of internal/handler. Tenant isolation (RLS via
// postgres.WithTenant), validation, audit emission, and PII envelope encryption
// plus blind index all live in internal/service and the repository, reached
// identically from both transports. Login stays REST only: it mints the JWT and
// is the pre auth entry point, so it is intentionally absent from this contract.
package grpcserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	cerr "github.com/OmniSurg/omnisurg-go-common/errors"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	identityv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/identity/v1"
	"github.com/google/uuid"
)

// Server implements identityv1.IdentityServiceServer as a thin adapter over the
// existing UserService. It holds no business logic.
type Server struct {
	identityv1.UnimplementedIdentityServiceServer
	users *service.UserService
}

// New builds the adapter over the existing service layer.
func New(users *service.UserService) *Server {
	return &Server{users: users}
}

// grpcCaller is the interceptor populated identity plus a derived role view. It
// keeps the provider and admin detection (which the identity service.Caller does
// not model) alongside the service.Caller the service methods consume.
type grpcCaller struct {
	caller       service.Caller
	role         string
	providerRole string
}

func (g grpcCaller) isProvider() bool {
	switch g.providerRole {
	case model.RoleProviderSuperAdmin, model.RoleProviderSupport, model.RoleProviderBilling:
		return true
	}
	switch g.role {
	case model.RoleProviderSuperAdmin, model.RoleProviderSupport, model.RoleProviderBilling:
		return true
	}
	return false
}

func (g grpcCaller) isPracticeAdmin() bool {
	return g.role == model.RolePracticeAdmin
}

// caller builds the grpcCaller from the interceptor populated identity, the
// exact gRPC mirror of handler.callerFrom. Returns an Unauthenticated status
// when the identity or its ids are unusable. The user op RPCs are tenant scoped,
// so a usable tenant id is required here; the provider cross tenant create path
// carries the target tenant in the verified JWT, so it still satisfies this
// guard. This is the per RPC tenant guard the plan mandates while the
// interceptor runs with RequireTenant false (identity is the user registry).
func (s *Server) caller(ctx context.Context) (grpcCaller, error) {
	id, ok := mw.IdentityFromContext(ctx)
	if !ok {
		return grpcCaller{}, cerr.ToStatus(model.ErrTenantMissing)
	}
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return grpcCaller{}, cerr.ToStatus(model.ErrTenantMissing)
	}
	tid, err := uuid.Parse(id.TenantID)
	if err != nil {
		return grpcCaller{}, cerr.ToStatus(model.ErrTenantMissing)
	}
	return grpcCaller{
		caller: service.Caller{
			UserID:    uid,
			TenantID:  tid,
			Role:      id.Role,
			RequestID: id.RequestID,
		},
		role:         id.Role,
		providerRole: id.ProviderRole,
	}, nil
}

// requireUserAdmin mirrors the REST router's RequireRole gate for user mutations:
// a tenant practice_admin manages users within the tenant, and a platform
// provider manages users cross tenant (eg provisioning the first practice_admin
// for a new tenant). Anyone else is denied.
func requireUserAdmin(g grpcCaller) error {
	if g.isPracticeAdmin() || g.isProvider() {
		return nil
	}
	return cerr.ToStatus(model.ErrForbidden)
}

func parseUUID(v string) (uuid.UUID, error) {
	id, err := uuid.Parse(v)
	if err != nil {
		return uuid.Nil, cerr.ToStatus(model.ErrValidation.WithDetails([]map[string]string{{"field": "id", "issue": "must be a valid uuid"}}))
	}
	return id, nil
}

// GetUser returns a user within the caller's tenant. The service scopes by
// caller.TenantID under RLS, so an out of tenant id is NotFound.
func (s *Server) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.User, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, perr := parseUUID(req.GetId().GetValue())
	if perr != nil {
		return nil, perr
	}
	u, gerr := s.users.Get(ctx, g.caller, id)
	if gerr != nil {
		return nil, cerr.ToStatus(gerr)
	}
	return toProtoUser(u), nil
}

// CheckRole reports whether the named user holds the given role. It composes the
// existing UserService.Get (tenant scoped under RLS) and compares the role; no
// new business logic is introduced. An out of tenant or missing user is
// NotFound, exactly as GetUser.
func (s *Server) CheckRole(ctx context.Context, req *identityv1.CheckRoleRequest) (*identityv1.CheckRoleResponse, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	id, perr := parseUUID(req.GetUserId().GetValue())
	if perr != nil {
		return nil, perr
	}
	u, gerr := s.users.Get(ctx, g.caller, id)
	if gerr != nil {
		return nil, cerr.ToStatus(gerr)
	}
	allowed := u.Role == roleProtoToString(req.GetRole())
	return &identityv1.CheckRoleResponse{Allowed: allowed}, nil
}

// ListUsersByRole returns the caller tenant's users holding the named role,
// paginated. It composes UserService.List (tenant scoped) and filters by role.
// The filter is a pure projection over the tenant scoped result, not a business
// rule. Pagination is applied by the service before the role filter, matching
// the wire contract's offset semantics.
func (s *Server) ListUsersByRole(ctx context.Context, req *identityv1.ListUsersByRoleRequest) (*identityv1.ListUsersByRoleResponse, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	want := roleProtoToString(req.GetRole())
	limit, offset := pageToLimitOffset(req.GetPage())
	users, _, lerr := s.users.List(ctx, g.caller, limit, offset)
	if lerr != nil {
		return nil, cerr.ToStatus(lerr)
	}
	out := make([]*identityv1.User, 0, len(users))
	for _, u := range users {
		if u.Role == want {
			out = append(out, toProtoUser(u))
		}
	}
	return &identityv1.ListUsersByRoleResponse{
		Users:    out,
		PageInfo: pageInfo(int64(len(out))),
	}, nil
}

// ListUsers returns the caller tenant's users, paginated and tenant scoped.
func (s *Server) ListUsers(ctx context.Context, req *identityv1.ListUsersRequest) (*identityv1.ListUsersResponse, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	limit, offset := pageToLimitOffset(req.GetPage())
	users, total, lerr := s.users.List(ctx, g.caller, limit, offset)
	if lerr != nil {
		return nil, cerr.ToStatus(lerr)
	}
	out := make([]*identityv1.User, 0, len(users))
	for _, u := range users {
		out = append(out, toProtoUser(u))
	}
	return &identityv1.ListUsersResponse{
		Users:    out,
		PageInfo: pageInfo(total),
	}, nil
}

// CreateUser provisions a user in the caller's tenant. Practice admin gated for
// tenant callers; providers may provision cross tenant (the first practice_admin
// for a new tenant, the target tenant carried in the verified JWT). The contract
// carries no password by design: provisioning never transports a secret. The
// adapter sets a cryptographically random temporary password so the row is valid
// and login stays blocked until the user resets it through the invite flow. PII
// encryption and the blind index happen in the service and repository, unchanged.
func (s *Server) CreateUser(ctx context.Context, req *identityv1.CreateUserRequest) (*identityv1.User, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if perr := requireUserAdmin(g); perr != nil {
		return nil, perr
	}
	role := firstRole(req.GetRoles())
	branchID, bok := firstBranchID(req.GetBranchIds())
	if !bok {
		return nil, cerr.ToStatus(model.ErrValidation.WithDetails([]map[string]string{{"field": "branch_ids", "issue": "must be valid uuids"}}))
	}
	tempPassword, terr := randomTempPassword()
	if terr != nil {
		return nil, cerr.ToStatus(terr)
	}
	u, cuerr := s.users.Create(ctx, g.caller, model.NewUser{
		Email:       req.GetEmail(),
		Password:    tempPassword,
		DisplayName: req.GetDisplayName(),
		Role:        role,
		BranchID:    branchID,
	})
	if cuerr != nil {
		return nil, cerr.ToStatus(cuerr)
	}
	return toProtoUser(u), nil
}

// UpdateUser mutates display name and status within the caller's tenant. The
// contract also carries role and branch replacement, but the P1 service layer
// supports display name and status mutation only; role and branch replacement
// are not wired in P1, so set_roles and set_branches are accepted on the wire
// and surfaced as unimplemented to avoid a silent partial write. Practice admin
// or provider gated.
func (s *Server) UpdateUser(ctx context.Context, req *identityv1.UpdateUserRequest) (*identityv1.User, error) {
	g, err := s.caller(ctx)
	if err != nil {
		return nil, err
	}
	if perr := requireUserAdmin(g); perr != nil {
		return nil, perr
	}
	id, perr := parseUUID(req.GetId().GetValue())
	if perr != nil {
		return nil, perr
	}
	if req.GetSetRoles() || req.GetSetBranches() {
		return nil, cerr.ToStatus(cerr.New("USER_UPDATE_UNSUPPORTED", "role and branch replacement is not supported in this phase", 422))
	}
	upd := model.UserUpdate{}
	if req.DisplayName != nil {
		v := req.GetDisplayName()
		upd.DisplayName = &v
	}
	if req.Status != nil {
		v := userStatusString(req.GetStatus())
		upd.Status = &v
	}
	u, uerr := s.users.Update(ctx, g.caller, id, upd)
	if uerr != nil {
		return nil, cerr.ToStatus(uerr)
	}
	return toProtoUser(u), nil
}

// firstRole returns the canonical role string for the first role in the repeated
// proto field, or empty when none is set. The P1 user model carries a single
// role; an empty string is rejected by the service validation as an invalid role.
func firstRole(roles []commonv1.Role) string {
	for _, r := range roles {
		if s := roleProtoToString(r); s != "" {
			return s
		}
	}
	return ""
}

// randomTempPassword returns a url safe random string used as the provisioning
// temporary password: 24 random bytes encoded to a 32 char url-safe string. It
// comfortably exceeds the service minimum length and is never returned to the
// caller; the user resets it via the invite flow.
func randomTempPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
