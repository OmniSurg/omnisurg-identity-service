package repository

import (
	"context"
	"errors"
	"fmt"

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
// for the domain view using the keyring.
type UserRepository struct {
	pool    *pgxpool.Pool
	keyring *security.Keyring
}

// NewUserRepository builds a UserRepository.
func NewUserRepository(pool *pgxpool.Pool, keyring *security.Keyring) *UserRepository {
	return &UserRepository{pool: pool, keyring: keyring}
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

// SoftDelete sets status to deleted.
func (r *UserRepository) SoftDelete(ctx context.Context, tenantID, id uuid.UUID) error {
	return pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		_, qerr := db.New(conn).SoftDeleteUser(ctx, pgUUID(id))
		if errors.Is(qerr, pgx.ErrNoRows) {
			return model.ErrUserNotFound
		}
		if qerr != nil {
			return fmt.Errorf("soft delete user: %w", qerr)
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
