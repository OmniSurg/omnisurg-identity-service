// Package bootstrap creates the first provider super-admin (the platform
// operator) on a fresh, non-seeded environment (staging or production). The
// demo seed is env-guarded to local and pre-enrols a fixed dev TOTP secret, so
// it cannot stand up an operator off local. This package fills that gap: it
// creates exactly one provider super-admin from operator-supplied credentials
// with a freshly generated random TOTP secret, reusing the service's own
// PII-encryption and enrolment path. It reads no environment and holds no
// config, so it is unit and integration testable directly; the thin
// cmd/bootstrap-operator wrapper handles env reading, config, wiring, and
// printing.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
)

// DefaultDisplayName is used when the operator supplies no name.
const DefaultDisplayName = "Platform Operator"

// minPasswordLength is a weak-credential guard, not a strength meter. It only
// blocks an obviously trivial operator password on a production environment.
const minPasswordLength = 12

// Params carries the operator-supplied inputs for creating the platform
// operator. Email and DisplayName are already trimmed and validated by the
// caller (via ValidateEmail and DisplayNameOrDefault); Password is validated by
// ValidatePassword and passed through unchanged.
type Params struct {
	Email       string
	Password    string
	DisplayName string
}

// Result reports the outcome of a bootstrap run. Created is true when a new
// operator was created and false when one already existed (the idempotent
// no-op). Secret and OtpauthURI are populated only on creation so the caller
// can print them once for enrolment; they are never set on the no-op path.
type Result struct {
	Created    bool
	Email      string
	Secret     string
	OtpauthURI string
}

// Run creates the platform operator if none exists yet, otherwise no-ops. It
// first counts live provider super-admins under the platform tenant; if one is
// already present it returns Result{Created: false} so the command is safe to
// re-run in a deploy pipeline and never re-mints a secret for an already
// enrolled operator. Otherwise it generates a fresh random TOTP secret,
// encrypts the email, hashes the password, and hands all three to a SINGLE
// atomic repository write that creates the user as a provider super-admin under
// the platform tenant, stores the secret, and marks the user enrolled so
// provider login lands in the TOTP_REQUIRED state (matching the demo seed).
// Doing the create-plus-enrol as one transaction keeps the count guard
// truthful: there is no window in which a row exists but is not fully
// provisioned, so a failed run never leaves an operator that a later run would
// mistake for complete.
//
// This command is a serial one-shot; the count guard is not a substitute for a
// lock under concurrent invocation, which is not a supported mode. Note also
// that if the sole operator was previously soft-deleted, the count returns 0 but
// re-creating with the SAME email surfaces model.ErrEmailTaken, because the
// per-tenant email_hash unique index retains soft-deleted rows; recover by using
// a different email.
func Run(ctx context.Context, repo *repository.UserRepository, keyring *security.Keyring, p Params) (Result, error) {
	existing, err := repo.CountProviderSuperAdmins(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("check for an existing operator: %w", err)
	}
	if existing > 0 {
		return Result{Created: false}, nil
	}

	secret, otpauthURI, err := security.GenerateSecret(p.Email)
	if err != nil {
		return Result{}, fmt.Errorf("generate operator two-factor secret: %w", err)
	}
	enc, err := keyring.Cipher().Encrypt([]byte(p.Email))
	if err != nil {
		return Result{}, fmt.Errorf("encrypt operator email: %w", err)
	}
	hash, err := security.HashPassword(p.Password)
	if err != nil {
		return Result{}, fmt.Errorf("hash operator password: %w", err)
	}

	if _, err := repo.CreateEnrolledProviderOperator(ctx, model.PlatformTenantID, model.NewUser{
		TenantID:     model.PlatformTenantID,
		Email:        p.Email,
		DisplayName:  p.DisplayName,
		ProviderRole: model.RoleProviderSuperAdmin,
	}, string(enc), hash, secret); err != nil {
		return Result{}, fmt.Errorf("create operator: %w", err)
	}

	return Result{
		Created:    true,
		Email:      p.Email,
		Secret:     secret,
		OtpauthURI: otpauthURI,
	}, nil
}

// ValidateEmail trims the operator email and applies a light sanity check: it
// must be non-blank, contain a name and a domain separated by a single "@", and
// the domain must contain a dot. It returns the trimmed value. This is a guard
// against an obvious typo, not full RFC 5321 validation.
func ValidateEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" {
		return "", errors.New("operator email is required")
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", errors.New("operator email must have a name and a domain separated by @")
	}
	if !strings.Contains(email[at+1:], ".") {
		return "", errors.New("operator email domain must contain a dot")
	}
	return email, nil
}

// ValidatePassword rejects a blank or whitespace-only operator password and
// enforces a minimum length as a weak-credential guard. It returns the password
// unchanged (never trimmed, since surrounding characters can be intentional).
func ValidatePassword(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("operator password is required")
	}
	if len(raw) < minPasswordLength {
		return "", fmt.Errorf("operator password must be at least %d characters", minPasswordLength)
	}
	return raw, nil
}

// DisplayNameOrDefault trims the operator name and falls back to the default
// when it is blank.
func DisplayNameOrDefault(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return DefaultDisplayName
	}
	return name
}
