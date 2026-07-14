// Package model holds the identity service domain types and error sentinels.
package model

import (
	"net/http"

	apperr "github.com/OmniSurg/omnisurg-go-common/errors"
)

// Predefined errors. Codes are service prefixed per the Go service standard.
var (
	ErrBadCredentials = apperr.New("AUTH_BAD_CREDENTIALS", "email or password is incorrect", http.StatusUnauthorized)
	ErrTenantMissing  = apperr.New("AUTH_TENANT_MISSING", "tenant context is required", http.StatusUnauthorized)
	ErrForbidden      = apperr.New("AUTH_FORBIDDEN", "the caller is not permitted to perform this action", http.StatusForbidden)
	ErrUserNotFound   = apperr.New("USER_NOT_FOUND", "user does not exist in this tenant", http.StatusNotFound)
	ErrEmailTaken     = apperr.New("USER_EMAIL_TAKEN", "a user with this email already exists in this tenant", http.StatusConflict)
	ErrValidation     = apperr.New("VALIDATION_FAILED", "the request body is invalid", http.StatusUnprocessableEntity)
	ErrUserDeleted    = apperr.New("USER_ALREADY_DELETED", "user is already deleted", http.StatusConflict)

	// TOTP (two factor) sentinels.
	ErrMfaAlreadyEnrolled = apperr.New("MFA_ALREADY_ENROLLED", "two factor sign in is already set up; reset it before enrolling again", http.StatusConflict)
	ErrMfaNotEnrolled     = apperr.New("MFA_NOT_ENROLLED", "two factor sign in is not set up yet; set it up first", http.StatusConflict)
	ErrInvalidTotpCode    = apperr.New("MFA_INVALID_CODE", "that code is not correct or has expired", http.StatusUnauthorized)

	// Account activation sentinels. ErrActivationInvalid is deliberately generic
	// and returned for every negative case (unknown token, wrong purpose,
	// expired, already consumed, or a lost consume race) so a failed activate
	// attempt never reveals which condition failed, mirroring the login
	// enumeration protection (HG-B3).
	ErrActivationInvalid    = apperr.New("AUTH_ACTIVATION_INVALID", "this activation link is not valid or has expired", http.StatusUnauthorized)
	ErrNotPendingActivation = apperr.New("USER_NOT_PENDING_ACTIVATION", "this user is not waiting to be activated", http.StatusConflict)
)
