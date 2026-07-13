// Command seed creates the Contract Smoke Test users for local development. It
// is idempotent and safe to run repeatedly. It encrypts email through the same
// keyring the service uses, so login by blind index works against seeded rows.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/config"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/google/uuid"
)

const seedPassword = "LocalDevPass1!"

// providerTotpTestSecret is the FIXED base32 TOTP secret the seeded provider
// super admin is pre-enrolled with, so the Contract Smoke Test and local sign in
// can compute a valid code deterministically. It is DEV ONLY and distinct from
// the public RFC 6238 test vector. Never use this value in production.
const providerTotpTestSecret = "ABCDEFGHIJKLMNOP"

// providerAdminEmail is the seeded provider super admin pre-enrolled for TOTP.
const providerAdminEmail = "provider.admin@omnisurg.test"

var (
	tenantAcme  = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	tenantOther = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	// branchCentral is the Central CBD branch (matches the tenant-service
	// seed). The Acme staff are based here so their JWT carries a branch_id,
	// which the branch scoped screens (the eye visit encounter) read as the
	// default branch for a new record.
	branchCentral = uuid.MustParse("000000b1-0000-0000-0000-000000000001")
)

type seedUser struct {
	tenant       uuid.UUID
	branch       *uuid.UUID
	email        string
	name         string
	role         string
	providerRole string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "seed failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("seed complete")
}

func run() error {
	cfg, err := config.Load(".env")
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		return err
	}
	defer pool.Close()

	kek, err := cfg.DecodeKEK()
	if err != nil {
		return err
	}
	keyring, err := security.LoadKeyring(ctx, pool, kek)
	if err != nil {
		return err
	}
	repo := repository.NewUserRepository(pool, keyring)

	users := []seedUser{
		{tenantAcme, &branchCentral, "practice.admin@acme.test", "Practice Admin", model.RolePracticeAdmin, ""},
		{tenantAcme, &branchCentral, "reception@acme.test", "Reception Desk", model.RoleReception, ""},
		{tenantAcme, &branchCentral, "ophthal@acme.test", "Lead Ophthalmologist", model.RoleClinicianOphthalmologist, ""},
		{tenantAcme, &branchCentral, "clinician@acme.test", "Second Ophthalmologist", model.RoleClinicianOphthalmologist, ""},
		{tenantOther, nil, "practice.admin@othertenant.test", "Other Admin", model.RolePracticeAdmin, ""},
		// Provider (platform) super admin under the reserved platform tenant. It
		// carries no tenant role and no branch; provider login mints a tenant
		// less token from it.
		{model.PlatformTenantID, nil, "provider.admin@omnisurg.test", "Provider Super Admin", "", model.RoleProviderSuperAdmin},
	}

	for _, u := range users {
		enc, encErr := keyring.Cipher().Encrypt([]byte(u.email))
		if encErr != nil {
			return fmt.Errorf("encrypt %s: %w", u.email, encErr)
		}
		hash, hashErr := security.HashPassword(seedPassword)
		if hashErr != nil {
			return fmt.Errorf("hash %s: %w", u.email, hashErr)
		}
		_, createErr := repo.Create(ctx, u.tenant, model.NewUser{
			TenantID: u.tenant, BranchID: u.branch, Email: u.email, DisplayName: u.name, Role: u.role, ProviderRole: u.providerRole,
		}, string(enc), hash)
		// The provider user carries no tenant role, so report its provider role
		// instead of an empty parenthetical.
		scope := u.role
		if scope == "" {
			scope = u.providerRole
		}
		switch {
		case createErr == nil:
			fmt.Printf("created %s (%s) in %s\n", u.email, scope, u.tenant)
		case errors.Is(createErr, model.ErrEmailTaken):
			fmt.Printf("exists  %s (%s)\n", u.email, u.role)
		default:
			return fmt.Errorf("create %s: %w", u.email, createErr)
		}
	}

	if err := preEnrolProviderTotp(ctx, repo, keyring); err != nil {
		return err
	}
	return nil
}

// preEnrolProviderTotp pre-enrols the seeded provider super admin with the fixed
// DEV ONLY test secret and marks it enrolled, so a fresh sign in lands in the
// TOTP_REQUIRED state and the CST can compute a valid code. It is idempotent:
// it looks the provider up by its email blind index and overwrites the secret
// and flag on every run.
func preEnrolProviderTotp(ctx context.Context, repo *repository.UserRepository, keyring *security.Keyring) error {
	hash := keyring.EmailBlindIndex(providerAdminEmail)
	rec, err := repo.AuthByEmailHash(ctx, model.PlatformTenantID, hash)
	if err != nil {
		return fmt.Errorf("look up provider admin for totp pre-enrol: %w", err)
	}
	if err := repo.SetTotpSecret(ctx, model.PlatformTenantID, rec.ID, providerTotpTestSecret); err != nil {
		return fmt.Errorf("pre-enrol provider totp secret: %w", err)
	}
	if err := repo.SetMfaEnrolled(ctx, model.PlatformTenantID, rec.ID, true); err != nil {
		return fmt.Errorf("pre-enrol provider totp flag: %w", err)
	}
	fmt.Printf("pre-enrolled %s for two factor (dev test secret)\n", providerAdminEmail)
	return nil
}
