package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserRepository wraps the sqlc generated queries with tenant context (via
// postgres.WithTenant), error mapping, and domain conversion. It decrypts email
// for the domain view using the keyring. tokens composes the standalone
// credential token operations (insert, invalidate, the service-global hash
// lookup) over the SAME pool; the two atomic operations that must run as ONE
// transaction spanning both the users and credential_tokens tables
// (ProvisionPendingAdmin, ActivateWithToken) are implemented directly on
// UserRepository below instead, since tokens' own methods each open their own
// WithTenant scope and cannot be composed into a single transaction.
type UserRepository struct {
	pool    *pgxpool.Pool
	keyring *security.Keyring
	tokens  *CredentialTokenRepo
}

// NewUserRepository builds a UserRepository.
func NewUserRepository(pool *pgxpool.Pool, keyring *security.Keyring) *UserRepository {
	return &UserRepository{pool: pool, keyring: keyring, tokens: NewCredentialTokenRepo(pool)}
}

// Create inserts a user. emailEncrypted is the AES-256-GCM ciphertext as a
// string (raw bytes). The blind index is computed here from the plaintext email
// in the input.
func (r *UserRepository) Create(ctx context.Context, tenantID uuid.UUID, in model.NewUser, emailEncrypted string, passwordHash string) (model.User, error) {
	if err := model.ValidateRoleExclusivity(in); err != nil {
		return model.User{}, err
	}
	var out model.User
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		q := db.New(conn)
		row, qerr := q.CreateUser(ctx, db.CreateUserParams{
			TenantID:       pgUUID(tenantID),
			BranchID:       pgUUIDPtr(in.BranchID),
			EmailEncrypted: []byte(emailEncrypted),
			EmailHash:      r.keyring.EmailBlindIndex(in.Email),
			PasswordHash:   passwordHash,
			DisplayName:    in.DisplayName,
			Role:           in.Role,
			ProviderRole:   in.ProviderRole,
		})
		if qerr != nil {
			if isUniqueViolation(qerr) {
				return model.ErrEmailTaken
			}
			return fmt.Errorf("create user: %w", qerr)
		}
		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// Get returns a user by id within the tenant.
func (r *UserRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (model.User, error) {
	var out model.User
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).GetUser(ctx, pgUUID(id))
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("get user: %w", qerr)
		}
		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// List returns the tenant's users and a total count.
func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]model.User, int64, error) {
	var users []model.User
	var total int64
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		q := db.New(conn)
		rows, qerr := q.ListUsers(ctx, db.ListUsersParams{Limit: limit, Offset: offset})
		if qerr != nil {
			return fmt.Errorf("list users: %w", qerr)
		}
		for _, row := range rows {
			u, derr := r.toDomain(userRow{
				ID:             row.ID,
				TenantID:       row.TenantID,
				BranchID:       row.BranchID,
				EmailEncrypted: row.EmailEncrypted,
				DisplayName:    row.DisplayName,
				Role:           row.Role,
				ProviderRole:   row.ProviderRole,
				Status:         row.Status,
				MfaEnrolled:    row.MfaEnrolled,
				CreatedAt:      row.CreatedAt,
				UpdatedAt:      row.UpdatedAt,
			})
			if derr != nil {
				return derr
			}
			users = append(users, u)
		}
		count, cerr := q.CountUsers(ctx)
		if cerr != nil {
			return fmt.Errorf("count users: %w", cerr)
		}
		total = count
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// CreateEnrolledProviderOperator inserts a provider operator and enrols it for
// two factor in ONE transaction: the user insert, the TOTP secret write, and the
// mfa_enrolled flip are all-or-nothing. This keeps the operator-bootstrap count
// guard truthful: a half-provisioned operator (a row with no secret, or not
// enrolled) can never be persisted, so a later run never mistakes an incomplete
// insert for a done one. It encrypts plainTotpSecret with the keyring exactly
// like SetTotpSecret does, and enforces role exclusivity up front like Create.
// The standalone SetTotpSecret and SetMfaEnrolled remain for the enrolment-
// confirm path, which mutates an already existing user.
func (r *UserRepository) CreateEnrolledProviderOperator(ctx context.Context, tenantID uuid.UUID, in model.NewUser, emailEncrypted, passwordHash, plainTotpSecret string) (model.User, error) {
	if err := model.ValidateRoleExclusivity(in); err != nil {
		return model.User{}, err
	}
	if plainTotpSecret == "" {
		return model.User{}, fmt.Errorf("create enrolled provider operator: empty totp secret")
	}
	encSecret, err := r.keyring.Cipher().Encrypt([]byte(plainTotpSecret))
	if err != nil {
		return model.User{}, fmt.Errorf("encrypt totp secret: %w", err)
	}

	var out model.User
	err = pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		tx, berr := conn.Begin(ctx)
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		q := db.New(tx)

		row, qerr := q.CreateUser(ctx, db.CreateUserParams{
			TenantID:       pgUUID(tenantID),
			BranchID:       pgUUIDPtr(in.BranchID),
			EmailEncrypted: []byte(emailEncrypted),
			EmailHash:      r.keyring.EmailBlindIndex(in.Email),
			PasswordHash:   passwordHash,
			DisplayName:    in.DisplayName,
			Role:           in.Role,
			ProviderRole:   in.ProviderRole,
		})
		if qerr != nil {
			if isUniqueViolation(qerr) {
				return model.ErrEmailTaken
			}
			return fmt.Errorf("create user: %w", qerr)
		}
		if serr := q.SetTotpSecret(ctx, db.SetTotpSecretParams{ID: row.ID, TotpSecret: encSecret}); serr != nil {
			return fmt.Errorf("set totp secret: %w", serr)
		}
		if merr := q.SetMfaEnrolled(ctx, db.SetMfaEnrolledParams{ID: row.ID, MfaEnrolled: true}); merr != nil {
			return fmt.Errorf("set mfa enrolled: %w", merr)
		}

		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		// CreateUser returns the pre-flip row (mfa_enrolled false), so reflect the
		// enrolled state this transaction just set for an accurate domain view.
		u.MFAEnrolled = true

		if cerr := tx.Commit(ctx); cerr != nil {
			return fmt.Errorf("commit tx: %w", cerr)
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// CountProviderSuperAdmins returns the number of live provider super-admins
// under the platform tenant. The operator bootstrap uses it to stay a safe
// one-shot: it refuses to create a second operator once one exists. It runs
// under the platform tenant scope via WithTenant, so RLS confines the count to
// the platform registry exactly like the sibling reads.
func (r *UserRepository) CountProviderSuperAdmins(ctx context.Context) (int64, error) {
	var count int64
	err := pg.WithTenant(ctx, r.pool, model.PlatformTenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		c, qerr := db.New(conn).CountProviderSuperAdmins(ctx, model.RoleProviderSuperAdmin)
		if qerr != nil {
			return fmt.Errorf("count provider super admins: %w", qerr)
		}
		count = c
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Update mutates display name or status.
func (r *UserRepository) Update(ctx context.Context, tenantID, id uuid.UUID, upd model.UserUpdate) (model.User, error) {
	var out model.User
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).UpdateUser(ctx, db.UpdateUserParams{
			ID:          pgUUID(id),
			DisplayName: upd.DisplayName,
			Status:      upd.Status,
		})
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("update user: %w", qerr)
		}
		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// SoftDelete sets status to deleted and, in the SAME transaction, invalidates
// every outstanding activation token for the user (reusing
// InvalidateActivationTokensForUser, the same query the resend flow uses).
// This closes the resurrection gap where a still-live activation link could
// otherwise reach a deleted pending user: the token is revoked at the moment
// of deletion, not left to be caught only by the status guard in
// SetPasswordAndActivate. Both writes commit together or neither does.
func (r *UserRepository) SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		tx, berr := conn.Begin(ctx)
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		q := db.New(tx)

		_, qerr := q.SoftDeleteUser(ctx, pgUUID(id))
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("soft delete user: %w", qerr)
		}

		if terr := q.InvalidateActivationTokensForUser(ctx, pgUUID(id)); terr != nil {
			return fmt.Errorf("invalidate activation tokens on delete: %w", terr)
		}

		if cerr := tx.Commit(ctx); cerr != nil {
			return fmt.Errorf("commit: %w", cerr)
		}
		return nil
	})
}

// AuthByEmailHash returns the minimal auth projection for a blind index match,
// scoped to the tenant by RLS.
func (r *UserRepository) AuthByEmailHash(ctx context.Context, tenantID uuid.UUID, emailHash string) (model.AuthRecord, error) {
	var rec model.AuthRecord
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).AuthByEmailHash(ctx, emailHash)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("auth by email hash: %w", qerr)
		}
		rec = model.AuthRecord{
			ID:           fromPgUUID(row.ID),
			TenantID:     fromPgUUID(row.TenantID),
			BranchID:     fromPgUUIDPtr(row.BranchID),
			PasswordHash: row.PasswordHash,
			Role:         row.Role,
			ProviderRole: row.ProviderRole,
			Status:       row.Status,
			MfaEnrolled:  row.MfaEnrolled,
		}
		return nil
	})
	if err != nil {
		return model.AuthRecord{}, err
	}
	return rec, nil
}

// SetTotpSecret encrypts the base32 TOTP secret under the keyring (the same DEK
// that protects email) and stores the ciphertext. It does not mark the user
// enrolled: enrolment completes only when the user confirms a code. A blank
// secret would be a programming error, so it is rejected.
func (r *UserRepository) SetTotpSecret(ctx context.Context, tenantID, id uuid.UUID, plainSecret string) error {
	if plainSecret == "" {
		return fmt.Errorf("set totp secret: empty secret")
	}
	enc, err := r.keyring.Cipher().Encrypt([]byte(plainSecret))
	if err != nil {
		return fmt.Errorf("encrypt totp secret: %w", err)
	}
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		qerr := db.New(conn).SetTotpSecret(ctx, db.SetTotpSecretParams{ID: pgUUID(id), TotpSecret: enc})
		if qerr != nil {
			return fmt.Errorf("set totp secret: %w", qerr)
		}
		return nil
	})
}

// GetTotpSecret decrypts and returns the stored TOTP secret plus the enrolled
// flag. A user with no stored secret returns an empty string and no error so
// callers can distinguish not-yet-enrolled from a hard read failure. An unknown
// user maps to ErrUserNotFound.
func (r *UserRepository) GetTotpSecret(ctx context.Context, tenantID, id uuid.UUID) (string, bool, error) {
	var secret string
	var enrolled bool
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		row, qerr := db.New(conn).GetTotpSecret(ctx, pgUUID(id))
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("get totp secret: %w", qerr)
		}
		enrolled = row.MfaEnrolled
		if len(row.TotpSecret) == 0 {
			return nil
		}
		plain, derr := r.keyring.Cipher().Decrypt(row.TotpSecret)
		if derr != nil {
			return fmt.Errorf("decrypt totp secret: %w", derr)
		}
		secret = string(plain)
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return secret, enrolled, nil
}

// SetMfaEnrolled flips the mfa_enrolled flag for a user within the tenant.
func (r *UserRepository) SetMfaEnrolled(ctx context.Context, tenantID, id uuid.UUID, enrolled bool) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		qerr := db.New(conn).SetMfaEnrolled(ctx, db.SetMfaEnrolledParams{ID: pgUUID(id), MfaEnrolled: enrolled})
		if qerr != nil {
			return fmt.Errorf("set mfa enrolled: %w", qerr)
		}
		return nil
	})
}

// ClearTotp wipes the secret and unsets mfa_enrolled, returning the user to the
// enrol-required state. Used by the super-admin reset.
func (r *UserRepository) ClearTotp(ctx context.Context, tenantID, id uuid.UUID) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		qerr := db.New(conn).ClearTotp(ctx, pgUUID(id))
		if qerr != nil {
			return fmt.Errorf("clear totp: %w", qerr)
		}
		return nil
	})
}

// AcceptTotpStep atomically records step as the user's last accepted TOTP
// time-step, but only if it is strictly greater than the stored one (or none is
// stored yet). It returns true when the step was accepted and false when the row
// did not advance, which means the code was a replay of the same or an older
// step (RFC 6238 section 5.2). It runs inside WithTenant like every other user
// write, so the conditional update is scoped to the caller tenant by RLS; a row
// invisible under the tenant scope simply matches nothing and returns false.
func (r *UserRepository) AcceptTotpStep(ctx context.Context, tenantID, id uuid.UUID, step int64) (bool, error) {
	var accepted bool
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		_, qerr := db.New(conn).AcceptTotpStep(ctx, db.AcceptTotpStepParams{ID: pgUUID(id), Step: step})
		if errors.Is(qerr, pgx.ErrNoRows) {
			accepted = false
			return nil
		}
		if qerr != nil {
			return fmt.Errorf("accept totp step: %w", qerr)
		}
		accepted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return accepted, nil
}

// ProvisionPendingAdmin inserts a user in the pending_activation state plus a
// bound activation credential token, in ONE transaction (mirroring
// payment-service's atomic RecordPayment): a crash or error between the two
// writes leaves neither behind, so a pending user is never created without an
// activation path, and a token is never created without an owning user.
// passwordHash is an already-hashed random, unusable value (the caller never
// accepts an operator-supplied password here); tokenHash is the sha256 of the
// activation token the caller generated and will return to the operator
// exactly once.
func (r *UserRepository) ProvisionPendingAdmin(ctx context.Context, tenantID uuid.UUID, in model.NewPendingUser, emailEncrypted string, phoneEncrypted []byte, passwordHash string, tokenHash []byte, expiresAt time.Time) (model.User, error) {
	var out model.User
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		tx, berr := conn.Begin(ctx)
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		q := db.New(tx)

		row, qerr := q.InsertPendingUser(ctx, db.InsertPendingUserParams{
			TenantID:       pgUUID(tenantID),
			BranchID:       pgUUIDPtr(in.BranchID),
			EmailEncrypted: []byte(emailEncrypted),
			EmailHash:      r.keyring.EmailBlindIndex(in.Email),
			PasswordHash:   passwordHash,
			PhoneEncrypted: phoneEncrypted,
			DisplayName:    in.DisplayName,
			Role:           in.Role,
			ProviderRole:   "",
		})
		if qerr != nil {
			if isUniqueViolation(qerr) {
				return model.ErrEmailTaken
			}
			return fmt.Errorf("insert pending user: %w", qerr)
		}

		if _, terr := q.InsertCredentialToken(ctx, db.InsertCredentialTokenParams{
			TenantID:  pgUUID(tenantID),
			UserID:    row.ID,
			Purpose:   model.CredentialTokenPurposeActivation,
			TokenHash: tokenHash,
			ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		}); terr != nil {
			return fmt.Errorf("insert credential token: %w", terr)
		}

		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return fmt.Errorf("commit: %w", cerr)
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// ActivateWithToken atomically consumes the named credential token (claim
// first, execute second, mirroring payment-service's RecordPayment) and, only
// if the claim succeeded, sets the user's password and activates it, in ONE
// transaction under WithTenant(tenantID). A lost race (the token was already
// consumed by a concurrent call) fails the whole transaction closed with
// model.ErrActivationInvalid: neither the token nor the user is left
// partially mutated.
func (r *UserRepository) ActivateWithToken(ctx context.Context, tenantID, tokenID, userID uuid.UUID, passwordHash string) (model.User, error) {
	var out model.User
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		tx, berr := conn.Begin(ctx)
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		q := db.New(tx)

		if _, cerr := q.ConsumeCredentialToken(ctx, pgUUID(tokenID)); cerr != nil {
			if errors.Is(cerr, pgx.ErrNoRows) {
				return model.ErrActivationInvalid
			}
			return fmt.Errorf("consume credential token: %w", cerr)
		}

		row, uerr := q.SetPasswordAndActivate(ctx, db.SetPasswordAndActivateParams{
			ID:           pgUUID(userID),
			PasswordHash: passwordHash,
		})
		if errors.Is(uerr, pgx.ErrNoRows) {
			return model.ErrActivationInvalid
		}
		if uerr != nil {
			return fmt.Errorf("set password and activate: %w", uerr)
		}

		u, derr := r.toDomain(userRow{
			ID:             row.ID,
			TenantID:       row.TenantID,
			BranchID:       row.BranchID,
			EmailEncrypted: row.EmailEncrypted,
			DisplayName:    row.DisplayName,
			Role:           row.Role,
			ProviderRole:   row.ProviderRole,
			Status:         row.Status,
			MfaEnrolled:    row.MfaEnrolled,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
		if derr != nil {
			return derr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return fmt.Errorf("commit: %w", cerr)
		}
		out = u
		return nil
	})
	if err != nil {
		return model.User{}, err
	}
	return out, nil
}

// GetCredentialTokenByHash delegates to the composed CredentialTokenRepo: a
// service-global, pre-auth lookup on the bare pool with no tenant context.
func (r *UserRepository) GetCredentialTokenByHash(ctx context.Context, hash []byte) (model.CredentialToken, error) {
	return r.tokens.GetByHash(ctx, hash)
}

// InvalidateActivationTokens marks every outstanding activation token for the
// user consumed, used before ResendActivation issues a fresh one.
func (r *UserRepository) InvalidateActivationTokens(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.tokens.InvalidateForUser(ctx, tenantID, userID)
}

// InsertActivationToken stores a fresh activation token for an already
// existing pending user, used by ResendActivation (which does not create a
// user, so it does not need ProvisionPendingAdmin's combined transaction).
func (r *UserRepository) InsertActivationToken(ctx context.Context, tenantID, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) (model.CredentialToken, error) {
	return r.tokens.Insert(ctx, tenantID, userID, tokenHash, model.CredentialTokenPurposeActivation, expiresAt)
}

// userRow is the common projection the user read queries return. The sqlc
// generated CreateUserRow, GetUserRow, ListUsersRow, and UpdateUserRow are
// structurally identical but distinct named types, so each maps into this
// shape before domain conversion.
type userRow struct {
	ID             pgtype.UUID
	TenantID       pgtype.UUID
	BranchID       pgtype.UUID
	EmailEncrypted []byte
	DisplayName    string
	Role           string
	ProviderRole   string
	Status         string
	MfaEnrolled    bool
	CreatedAt      pgtype.Timestamptz
	UpdatedAt      pgtype.Timestamptz
}

// toDomain decrypts the email and converts a db row to the domain User.
func (r *UserRepository) toDomain(row userRow) (model.User, error) {
	plain, err := r.keyring.Cipher().Decrypt(row.EmailEncrypted)
	if err != nil {
		return model.User{}, fmt.Errorf("decrypt email: %w", err)
	}
	return model.User{
		ID:           fromPgUUID(row.ID),
		TenantID:     fromPgUUID(row.TenantID),
		BranchID:     fromPgUUIDPtr(row.BranchID),
		Email:        string(plain),
		DisplayName:  row.DisplayName,
		Role:         row.Role,
		ProviderRole: row.ProviderRole,
		Status:       row.Status,
		MFAEnrolled:  row.MfaEnrolled,
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
	}, nil
}
