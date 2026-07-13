package handler

import (
	"time"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
)

type userJSON struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	BranchID     *string   `json:"branch_id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"display_name"`
	Role         string    `json:"role"`
	ProviderRole string    `json:"provider_role"`
	Status       string    `json:"status"`
	MFAEnrolled  bool      `json:"mfa_enrolled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func presentUser(u model.User) userJSON {
	var branch *string
	if u.BranchID != nil {
		s := u.BranchID.String()
		branch = &s
	}
	return userJSON{
		ID:           u.ID.String(),
		TenantID:     u.TenantID.String(),
		BranchID:     branch,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		Role:         u.Role,
		ProviderRole: u.ProviderRole,
		Status:       u.Status,
		MFAEnrolled:  u.MFAEnrolled,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}
