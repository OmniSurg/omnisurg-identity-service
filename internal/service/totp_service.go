package service

import (
	"context"
	"time"

	ojwt "github.com/OmniSurg/omnisurg-go-common/jwt"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// TotpService runs the provider two factor lifecycle: enrol a secret, confirm
// it to complete enrolment, verify a code as the login second factor, and a
// super-admin reset. Every operation acts on the caller's own subject; the only
// exception is reset, which names a target and is gated to super admins. Secrets
// are stored encrypted by the store (the repository encrypts under the keyring),
// so this layer never sees ciphertext.
type TotpService struct {
	store  UserStore
	audit  AuditEmitter
	secret string
	ttl    time.Duration
}

// NewTotpService builds a TotpService. secret and ttl sign the full provider
// token issued on a successful confirm or verify.
func NewTotpService(store UserStore, audit AuditEmitter, secret string, ttl time.Duration) *TotpService {
	return &TotpService{store: store, audit: audit, secret: secret, ttl: ttl}
}

// EnrollResult carries the new secret and the otpauth provisioning uri the
// client renders as a QR code. The secret is shown once so the provider can key
// it in manually if scanning fails.
type EnrollResult struct {
	Secret     string
	OtpauthURI string
}

// TokenResult is a freshly minted full provider token (mfa_verified true) plus
// its expiry.
type TokenResult struct {
	Token     string
	ExpiresAt time.Time
}

// Enroll generates a fresh TOTP secret for the caller and stores it
// unconfirmed. A second enrol before confirming overwrites the unconfirmed
// secret. An enrol by an already enrolled provider is refused with a conflict;
// they must reset first. The user id is the caller's own subject, never a body
// field, so a provider cannot enrol on another account.
func (s *TotpService) Enroll(ctx context.Context, caller Caller) (EnrollResult, error) {
	user, err := s.store.Get(ctx, caller.TenantID, caller.UserID)
	if err != nil {
		return EnrollResult{}, err
	}
	_, enrolled, err := s.store.GetTotpSecret(ctx, caller.TenantID, caller.UserID)
	if err != nil {
		return EnrollResult{}, err
	}
	if enrolled {
		return EnrollResult{}, model.ErrMfaAlreadyEnrolled
	}

	secret, uri, err := security.GenerateSecret(user.Email)
	if err != nil {
		return EnrollResult{}, err
	}
	if err := s.store.SetTotpSecret(ctx, caller.TenantID, caller.UserID, secret); err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{Secret: secret, OtpauthURI: uri}, nil
}

// Confirm completes enrolment: it verifies the supplied code against the stored
// secret, marks the user enrolled, and mints a full token. It refuses if no
// secret has been enrolled. The user id is the caller's own subject.
func (s *TotpService) Confirm(ctx context.Context, caller Caller, code string) (TokenResult, error) {
	secret, _, err := s.store.GetTotpSecret(ctx, caller.TenantID, caller.UserID)
	if err != nil {
		return TokenResult{}, err
	}
	if secret == "" {
		return TokenResult{}, model.ErrMfaNotEnrolled
	}
	step, ok := security.VerifyCodeStep(secret, code, time.Now().UTC())
	if !ok {
		return TokenResult{}, model.ErrInvalidTotpCode
	}
	// Record the accepted step before completing enrolment so this code cannot be
	// replayed within the skew window. Confirm stores step N and issues a full
	// token; an immediate Verify with the same code is then correctly rejected as
	// a replay, which is benign because Confirm already completed MFA.
	if err := s.acceptStep(ctx, caller, step); err != nil {
		return TokenResult{}, err
	}
	if err := s.store.SetMfaEnrolled(ctx, caller.TenantID, caller.UserID, true); err != nil {
		return TokenResult{}, err
	}
	s.emit(ctx, caller, "identity.provider_totp.confirm", caller.UserID)
	return s.issueFullToken(caller)
}

// Verify is the login second factor: it requires the caller to be enrolled,
// verifies the code, and mints a full token. The user id is the caller's own
// subject.
func (s *TotpService) Verify(ctx context.Context, caller Caller, code string) (TokenResult, error) {
	secret, enrolled, err := s.store.GetTotpSecret(ctx, caller.TenantID, caller.UserID)
	if err != nil {
		return TokenResult{}, err
	}
	if !enrolled || secret == "" {
		return TokenResult{}, model.ErrMfaNotEnrolled
	}
	step, ok := security.VerifyCodeStep(secret, code, time.Now().UTC())
	if !ok {
		return TokenResult{}, model.ErrInvalidTotpCode
	}
	if err := s.acceptStep(ctx, caller, step); err != nil {
		return TokenResult{}, err
	}
	s.emit(ctx, caller, "identity.provider_totp.verify", caller.UserID)
	return s.issueFullToken(caller)
}

// Reset clears a target provider's secret and enrolment so their next login is
// enrol-required. It is gated to super admins by the handler RBAC; the audit row
// records both the acting super admin and the target.
func (s *TotpService) Reset(ctx context.Context, caller Caller, targetID uuid.UUID) error {
	// Confirm the target exists in the platform tenant before clearing, so a
	// reset of an unknown id reports not found rather than silently succeeding.
	if _, err := s.store.Get(ctx, caller.TenantID, targetID); err != nil {
		return err
	}
	if err := s.store.ClearTotp(ctx, caller.TenantID, targetID); err != nil {
		return err
	}
	s.emit(ctx, caller, "identity.provider_totp.reset", targetID)
	return nil
}

// acceptStep records the matched TOTP step and reports replay. It returns
// ErrInvalidTotpCode (the same error the wrong-code path returns, no
// distinguishable message, no token) when the step was already accepted or is
// older, atomically (RFC 6238 section 5.2). Shared by Confirm and Verify so both
// second-factor paths guard replay identically.
func (s *TotpService) acceptStep(ctx context.Context, caller Caller, step int64) error {
	ok, err := s.store.AcceptTotpStep(ctx, caller.TenantID, caller.UserID, step)
	if err != nil {
		return err
	}
	if !ok {
		return model.ErrInvalidTotpCode
	}
	return nil
}

// issueFullToken mints a provider token with mfa_verified true. It re-reads the
// caller's provider role from the verified caller identity, never from a body.
func (s *TotpService) issueFullToken(caller Caller) (TokenResult, error) {
	now := time.Now().UTC()
	token, err := ojwt.Sign(ojwt.Claims{
		Subject:      caller.UserID.String(),
		TenantID:     "",
		BranchID:     "",
		Role:         "",
		ProviderRole: caller.ProviderRole,
		MFAVerified:  true,
	}, s.secret, s.ttl)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{Token: token, ExpiresAt: now.Add(s.ttl)}, nil
}

// emit writes an audit row under the platform tenant recording the actor and
// target. An audit write failure is alertable but never blocks the operation.
func (s *TotpService) emit(ctx context.Context, caller Caller, action string, targetID uuid.UUID) {
	actor := caller.UserID
	tid := targetID
	if err := s.audit.Emit(ctx, model.AuditEvent{
		TenantID:   caller.TenantID,
		ActorID:    &actor,
		Action:     action,
		TargetType: "user",
		TargetID:   &tid,
		RequestID:  caller.RequestID,
	}); err != nil {
		log.Error().Err(err).Str("action", action).Msg("audit emit failed")
	}
}
