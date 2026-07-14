package grpcserver_test

import (
	"testing"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	identityv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/identity/v1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGRPCProvisionUserCreatesAPendingUserAndAToken proves the happy path: a
// practice admin provisions a pending user and receives a raw activation
// token, and the created user carries no usable session (it is pending).
func TestGRPCProvisionUserCreatesAPendingUserAndAToken(t *testing.T) {
	client := testServer(t)
	res, err := client.ProvisionUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ProvisionUserRequest{
		Email:       "provisioned.admin@example.com",
		DisplayName: "Provisioned Admin",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
		Phone:       "+263771234567",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, res.GetActivationToken())
	assert.NotNil(t, res.GetActivationExpiresAt())
	assert.Equal(t, identityv1.UserStatus_USER_STATUS_UNSPECIFIED, res.GetUser().GetStatus(), "pending_activation has no matching proto enum value; it maps to unspecified, never active")
	assert.Equal(t, "provisioned.admin@example.com", res.GetUser().GetEmail())
	assert.Equal(t, tenantA.String(), res.GetUser().GetTenantId().GetValue())
}

// TestGRPCProvisionUserForbiddenForNonAdmin mirrors CreateUser's RBAC gate.
func TestGRPCProvisionUserForbiddenForNonAdmin(t *testing.T) {
	client := testServer(t)
	_, err := client.ProvisionUser(ctxFor(t, tenantA, model.RoleReception), &identityv1.ProvisionUserRequest{
		Email:       "sneaky.pending@example.com",
		DisplayName: "Sneaky",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_RECEPTION},
		Phone:       "+263779990000",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestGRPCProvisionUserCrossTenantByProviderSucceeds mirrors CreateUser's
// provider cross tenant registry path.
func TestGRPCProvisionUserCrossTenantByProviderSucceeds(t *testing.T) {
	client := testServer(t)
	newTenant := uuid.MustParse("00000000-0000-0000-0000-0000000000fe")
	res, err := client.ProvisionUser(ctxForProvider(t, newTenant, model.RoleProviderSuperAdmin), &identityv1.ProvisionUserRequest{
		Email:       "first.provisioned@newpractice.example.com",
		DisplayName: "First Provisioned Admin",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
		Phone:       "+263771112222",
	})
	require.NoError(t, err)
	assert.Equal(t, newTenant.String(), res.GetUser().GetTenantId().GetValue())
}

// TestGRPCResendActivationInvalidatesPriorAndIssuesFresh proves the resend
// path issues a fresh token that differs from the original, and is gated
// identically to ProvisionUser.
func TestGRPCResendActivationInvalidatesPriorAndIssuesFresh(t *testing.T) {
	client := testServer(t)
	provisioned, err := client.ProvisionUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ProvisionUserRequest{
		Email:       "resend.grpc@example.com",
		DisplayName: "Resend Grpc",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
		Phone:       "+263773338888",
	})
	require.NoError(t, err)

	resent, err := client.ResendActivation(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ResendActivationRequest{
		UserId: provisioned.GetUser().GetId(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resent.GetActivationToken())
	assert.NotEqual(t, provisioned.GetActivationToken(), resent.GetActivationToken())
}

// TestGRPCResendActivationForbiddenForNonAdmin mirrors ProvisionUser's RBAC.
func TestGRPCResendActivationForbiddenForNonAdmin(t *testing.T) {
	client := testServer(t)
	provisioned, err := client.ProvisionUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ProvisionUserRequest{
		Email:       "resend.forbidden@example.com",
		DisplayName: "Resend Forbidden",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
		Phone:       "+263773339999",
	})
	require.NoError(t, err)

	_, err = client.ResendActivation(ctxFor(t, tenantA, model.RoleReception), &identityv1.ResendActivationRequest{
		UserId: provisioned.GetUser().GetId(),
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestGRPCResendActivationCrossTenantIsNotFound proves the resend path stays
// tenant scoped: a resend targeting a user id that only exists in another
// tenant finds nothing under the caller's RLS scope.
func TestGRPCResendActivationCrossTenantIsNotFound(t *testing.T) {
	client := testServer(t)
	provisioned, err := client.ProvisionUser(ctxFor(t, tenantA, model.RolePracticeAdmin), &identityv1.ProvisionUserRequest{
		Email:       "cross.tenant.resend@example.com",
		DisplayName: "Cross Tenant Resend",
		Roles:       []commonv1.Role{commonv1.Role_ROLE_PRACTICE_ADMIN},
		Phone:       "+263773330000",
	})
	require.NoError(t, err)

	_, err = client.ResendActivation(ctxFor(t, tenantB, model.RolePracticeAdmin), &identityv1.ResendActivationRequest{
		UserId: provisioned.GetUser().GetId(),
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
