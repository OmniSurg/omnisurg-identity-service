package grpcserver_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/OmniSurg/omnisurg-go-common/crypto"
	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/grpcserver"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	"github.com/OmniSurg/omnisurg-identity-service/test/harness"
	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	identityv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/identity/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const grpcTestSecret = "grpc-leak-test-secret"

var (
	tenantA = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	tenantB = uuid.MustParse("00000000-0000-0000-0000-000000000002")
)

// testServer boots Postgres via the harness (non superuser, NOBYPASSRLS, so RLS
// is fully enforced), constructs the REAL repositories and service layer (no
// mocks), wires the grpcserver with the shared go-common interceptor, and serves
// it on an in process bufconn. It returns a connected client. RequireTenant is
// false at the interceptor because identity is the user registry: a provider
// caller provisions the first practice_admin for a NEW tenant cross tenant, with
// the target tenant carried in the verified JWT. Tenant presence for tenant
// scoped user ops is enforced per RPC by the adapter caller guard, the gRPC
// mirror of the REST router.
func testServer(t *testing.T) identityv1.IdentityServiceClient {
	t.Helper()
	dsn, stop := harness.StartPostgres(t)
	t.Cleanup(stop)

	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	kek, err := crypto.GenerateDEK()
	require.NoError(t, err)
	keyring, err := security.LoadKeyring(ctx, pool, kek)
	require.NoError(t, err)

	// Real repositories and real service layer. No mocks.
	userRepo := repository.NewUserRepository(pool, keyring)
	auditRepo := repository.NewAuditRepository(pool)
	userSvc := service.NewUserService(userRepo, auditRepo, keyring)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(mw.UnaryServerInterceptor(mw.InterceptorOptions{
			JWTSecret:     grpcTestSecret,
			RequireTenant: false,
		})),
	)
	identityv1.RegisterIdentityServiceServer(srv, grpcserver.New(userSvc))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewIdentityServiceClient(conn)
}

// ctxFor mints a JWT for a tenant caller and attaches it as the x-omnisurg-jwt
// metadata the interceptor verifies. This is exactly what the admin-bff does on
// the gRPC path.
func ctxFor(t *testing.T, tenantID uuid.UUID, role string) context.Context {
	t.Helper()
	claims := ojwt.Claims{Subject: uuid.NewString(), Role: role}
	if tenantID != uuid.Nil {
		claims.TenantID = tenantID.String()
	}
	tok, err := ojwt.Sign(claims, grpcTestSecret, time.Hour)
	require.NoError(t, err)
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs(mw.MetadataKeyJWT, tok))
}

// ctxForProvider mints a provider JWT carrying the TARGET tenant the BFF
// resolved, so a provider_super_admin can provision the first practice_admin in
// a brand new tenant cross tenant. The provider role rides in both role and
// provider_role; the target tenant rides in tenant_id.
func ctxForProvider(t *testing.T, targetTenant uuid.UUID, providerRole string) context.Context {
	t.Helper()
	claims := ojwt.Claims{
		Subject:      uuid.NewString(),
		Role:         providerRole,
		ProviderRole: providerRole,
		TenantID:     targetTenant.String(),
	}
	tok, err := ojwt.Sign(claims, grpcTestSecret, time.Hour)
	require.NoError(t, err)
	return metadata.NewOutgoingContext(context.Background(), metadata.Pairs(mw.MetadataKeyJWT, tok))
}

func uuidProto(id uuid.UUID) *commonv1.UUID { return &commonv1.UUID{Value: id.String()} }

func createUserA(t *testing.T, client identityv1.IdentityServiceClient, email string) *identityv1.User {
	t.Helper()
	u, err := client.CreateUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.CreateUserRequest{
		Email:       email,
		DisplayName: "Test Reception",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_RECEPTION},
	})
	require.NoError(t, err)
	require.NotEmpty(t, u.GetId().GetValue())
	return u
}

// TestGRPCUserTenantIsolationLeak is the mandatory gRPC path leak test. It
// proves that RLS isolation holding on the REST path holds identically over
// gRPC, because both converge on the same repository under postgres.WithTenant.
func TestGRPCUserTenantIsolationLeak(t *testing.T) {
	client := testServer(t)

	created := createUserA(t, client, "reception.a@example.com")
	userAID := uuid.MustParse(created.GetId().GetValue())

	// Tenant B cannot read tenant A's user: RLS makes it NotFound.
	_, err := client.GetUser(ctxFor(t, tenantB, model.RolePracticeAdmin), &identityv1.GetUserRequest{
		Id: uuidProto(userAID),
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// Tenant B's user list excludes tenant A's user.
	listB, err := client.ListUsers(ctxFor(t, tenantB, model.RolePracticeAdmin), &identityv1.ListUsersRequest{})
	require.NoError(t, err)
	assert.Empty(t, listB.GetUsers())

	// Positive control: tenant A reads its own user, with PII (email) intact.
	gotA, err := client.GetUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.GetUserRequest{
		Id: uuidProto(userAID),
	})
	require.NoError(t, err)
	assert.Equal(t, userAID.String(), gotA.GetId().GetValue())
	assert.Equal(t, "reception.a@example.com", gotA.GetEmail())

	listA, err := client.ListUsers(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ListUsersRequest{})
	require.NoError(t, err)
	assert.Len(t, listA.GetUsers(), 1)
}

// TestGRPCNoJWTIsUnauthenticated proves the interceptor gate: a tenant scoped
// RPC with no JWT and no tenant metadata is rejected.
func TestGRPCNoJWTIsUnauthenticated(t *testing.T) {
	client := testServer(t)
	_, err := client.GetUser(context.Background(), &identityv1.GetUserRequest{Id: uuidProto(uuid.New())})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestGRPCNonAdminCreateUserIsPermissionDenied proves per method RBAC: a non
// admin, non provider caller hitting CreateUser is denied. The adapter mirrors
// the REST router's RequireRole gate.
func TestGRPCNonAdminCreateUserIsPermissionDenied(t *testing.T) {
	client := testServer(t)
	_, err := client.CreateUser(ctxFor(t, tenantA, model.RoleReception), &identityv1.CreateUserRequest{
		Email:       "sneaky@example.com",
		DisplayName: "Sneaky",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_RECEPTION},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestGRPCProviderCreateUserCrossTenantSucceeds proves the registry path: a
// provider_super_admin provisions the first practice_admin in a brand new tenant
// the provider carries as the target tenant in the verified JWT.
func TestGRPCProviderCreateUserCrossTenantSucceeds(t *testing.T) {
	client := testServer(t)
	newTenant := uuid.MustParse("00000000-0000-0000-0000-0000000000ff")
	u, err := client.CreateUser(ctxForProvider(t, newTenant, model.RoleProviderSuperAdmin), &identityv1.CreateUserRequest{
		Email:       "first.admin@newpractice.example.com",
		DisplayName: "First Admin",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
	})
	require.NoError(t, err)
	assert.Equal(t, newTenant.String(), u.GetTenantId().GetValue())
	assert.Contains(t, u.GetRoles(), commonv1.Role_ROLE_PRACTICE_ADMIN)
}

// TestGRPCGetUserServiceToService confirms GetUser works on the gRPC path for
// the service to service callers (the admin-bff and other services).
func TestGRPCGetUserServiceToService(t *testing.T) {
	client := testServer(t)
	created := createUserA(t, client, "lookup.a@example.com")
	got, err := client.GetUser(ctxFor(t, tenantA, model.RoleReception), &identityv1.GetUserRequest{
		Id: created.GetId(),
	})
	require.NoError(t, err)
	assert.Equal(t, created.GetId().GetValue(), got.GetId().GetValue())
	assert.Equal(t, "lookup.a@example.com", got.GetEmail())
}

// TestGRPCCheckRole confirms CheckRole works on the gRPC path for the service to
// service callers: it returns true for a user's actual role and false otherwise.
func TestGRPCCheckRole(t *testing.T) {
	client := testServer(t)
	created := createUserA(t, client, "checkrole.a@example.com")

	yes, err := client.CheckRole(ctxFor(t, tenantA, model.RoleReception), &identityv1.CheckRoleRequest{
		UserId: created.GetId(),
		Role:   commonv1.Role_ROLE_RECEPTION,
	})
	require.NoError(t, err)
	assert.True(t, yes.GetAllowed())

	no, err := client.CheckRole(ctxFor(t, tenantA, model.RoleReception), &identityv1.CheckRoleRequest{
		UserId: created.GetId(),
		Role:   commonv1.Role_ROLE_PRACTICE_ADMIN,
	})
	require.NoError(t, err)
	assert.False(t, no.GetAllowed())

	// A user that does not exist in the caller tenant is NotFound.
	_, err = client.CheckRole(ctxFor(t, tenantB, model.RoleReception), &identityv1.CheckRoleRequest{
		UserId: created.GetId(),
		Role:   commonv1.Role_ROLE_RECEPTION,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestGRPCUpdateUser confirms the update path maps display name and status and
// stays tenant scoped.
func TestGRPCUpdateUser(t *testing.T) {
	client := testServer(t)
	created := createUserA(t, client, "update.a@example.com")

	newName := "Renamed Reception"
	updated, err := client.UpdateUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.UpdateUserRequest{
		Id:          created.GetId(),
		DisplayName: &newName,
	})
	require.NoError(t, err)
	assert.Equal(t, newName, updated.GetDisplayName())

	// Tenant B cannot update tenant A's user.
	_, err = client.UpdateUser(ctxFor(t, tenantB, model.RolePracticeAdmin), &identityv1.UpdateUserRequest{
		Id:          created.GetId(),
		DisplayName: &newName,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
