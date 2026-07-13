package grpcserver

import (
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
	identityv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/identity/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This file holds the pure model to proto mappers and the role enum projection.
// They mirror the REST presenter's model to DTO logic but target the proto
// types. There is no business logic here; only field projection. The single
// source of truth for the canonical role strings is the common.v1 Role enum;
// the model strings mirror it.

func uuidProto(id uuid.UUID) *commonv1.UUID {
	return &commonv1.UUID{Value: id.String()}
}

// roleStringToProto maps a canonical role string (as stored on the user row and
// carried in the JWT) to the common.v1 Role enum. An unknown string maps to
// ROLE_UNSPECIFIED so a contract drift surfaces as an explicit zero rather than
// a silent mismatch.
func roleStringToProto(s string) commonv1.Role {
	switch s {
	case model.RolePracticeAdmin:
		return commonv1.Role_ROLE_PRACTICE_ADMIN
	case model.RoleClinicianOphthalmologist:
		return commonv1.Role_ROLE_CLINICIAN_OPHTHALMOLOGIST
	case model.RoleClinicianLocum:
		return commonv1.Role_ROLE_CLINICIAN_LOCUM
	case model.RoleOphthalmicAssistant:
		return commonv1.Role_ROLE_OPHTHALMIC_ASSISTANT
	case model.RoleReception:
		return commonv1.Role_ROLE_RECEPTION
	case model.RoleProviderSuperAdmin:
		return commonv1.Role_ROLE_PROVIDER_SUPER_ADMIN
	case model.RoleProviderSupport:
		return commonv1.Role_ROLE_PROVIDER_SUPPORT
	case model.RoleProviderBilling:
		return commonv1.Role_ROLE_PROVIDER_BILLING
	default:
		return commonv1.Role_ROLE_UNSPECIFIED
	}
}

// roleProtoToString maps the common.v1 Role enum back to the canonical role
// string the service layer and the user row use. An unspecified or unknown enum
// maps to the empty string, which the service layer rejects as an invalid role.
func roleProtoToString(r commonv1.Role) string {
	switch r {
	case commonv1.Role_ROLE_PRACTICE_ADMIN:
		return model.RolePracticeAdmin
	case commonv1.Role_ROLE_CLINICIAN_OPHTHALMOLOGIST:
		return model.RoleClinicianOphthalmologist
	case commonv1.Role_ROLE_CLINICIAN_LOCUM:
		return model.RoleClinicianLocum
	case commonv1.Role_ROLE_OPHTHALMIC_ASSISTANT:
		return model.RoleOphthalmicAssistant
	case commonv1.Role_ROLE_RECEPTION:
		return model.RoleReception
	case commonv1.Role_ROLE_PROVIDER_SUPER_ADMIN:
		return model.RoleProviderSuperAdmin
	case commonv1.Role_ROLE_PROVIDER_SUPPORT:
		return model.RoleProviderSupport
	case commonv1.Role_ROLE_PROVIDER_BILLING:
		return model.RoleProviderBilling
	default:
		return ""
	}
}

func userStatusProto(s string) identityv1.UserStatus {
	switch s {
	case "active":
		return identityv1.UserStatus_USER_STATUS_ACTIVE
	case "suspended":
		return identityv1.UserStatus_USER_STATUS_SUSPENDED
	case "deleted":
		return identityv1.UserStatus_USER_STATUS_DELETED
	default:
		return identityv1.UserStatus_USER_STATUS_UNSPECIFIED
	}
}

func userStatusString(s identityv1.UserStatus) string {
	switch s {
	case identityv1.UserStatus_USER_STATUS_ACTIVE:
		return "active"
	case identityv1.UserStatus_USER_STATUS_SUSPENDED:
		return "suspended"
	case identityv1.UserStatus_USER_STATUS_DELETED:
		return "deleted"
	default:
		return ""
	}
}

// toProtoUser projects the decrypted domain user onto the proto User. The model
// carries a single role and a single optional branch; the contract carries the
// repeated forms, so the projection wraps the single values into one element
// lists. The email is the decrypted plaintext the repository produced under the
// keyring, identical to the REST presenter.
func toProtoUser(u model.User) *identityv1.User {
	roles := make([]commonv1.Role, 0, 1)
	if u.Role != "" {
		roles = append(roles, roleStringToProto(u.Role))
	}
	branchIDs := make([]*commonv1.UUID, 0, 1)
	if u.BranchID != nil {
		branchIDs = append(branchIDs, uuidProto(*u.BranchID))
	}
	return &identityv1.User{
		Id:          uuidProto(u.ID),
		TenantId:    uuidProto(u.TenantID),
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Status:      userStatusProto(u.Status),
		Roles:       roles,
		BranchIds:   branchIDs,
		MfaEnrolled: u.MFAEnrolled,
		CreatedAt:   timestamppb.New(u.CreatedAt),
		UpdatedAt:   timestamppb.New(u.UpdatedAt),
	}
}

// firstBranchID returns the first branch id from the repeated proto field, or
// nil when none is set. The model carries a single optional branch in P1.
func firstBranchID(ids []*commonv1.UUID) (*uuid.UUID, bool) {
	for _, b := range ids {
		if v := b.GetValue(); v != "" {
			parsed, err := uuid.Parse(v)
			if err != nil {
				return nil, false
			}
			return &parsed, true
		}
	}
	return nil, true
}
