// Command bootstrap-operator creates the FIRST provider super-admin (the
// platform operator) on a fresh, non-seeded environment (staging or
// production). It is a one-shot: if a provider super-admin already exists it
// no-ops, so it is safe to re-run in a deploy pipeline. On creation it prints
// the operator email, the freshly generated base32 TOTP secret, and the otpauth
// provisioning URI ONCE so the operator can enrol an authenticator; the secret
// is never persisted in plaintext, never logged again, and never fixed.
//
// It refuses to run in the local env, where local development uses the demo
// seed (cmd/seed) with its dev-only fixed secret instead.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/bootstrap"
	"github.com/OmniSurg/omnisurg-identity-service/internal/config"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap-operator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// config.Load runs assertSecretsSafe internally, so an unsafe, placeholder,
	// or local-dev JWT/KEK on a non-local env fails closed here for free.
	cfg, err := config.Load(".env")
	if err != nil {
		return err
	}
	if cfg.IsLocal() {
		return errors.New("bootstrap-operator refuses to run in the local env; local development uses the demo seed")
	}

	params, err := readParams()
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

	result, err := bootstrap.Run(ctx, repo, keyring, params)
	if err != nil {
		return err
	}

	if !result.Created {
		fmt.Println("a provider super-admin already exists; nothing to do")
		return nil
	}

	printResult(result)
	return nil
}

// readParams reads and validates the operator inputs from the environment. It
// never echoes the password.
func readParams() (bootstrap.Params, error) {
	email, err := bootstrap.ValidateEmail(os.Getenv("OMNISURG_OPERATOR_EMAIL"))
	if err != nil {
		return bootstrap.Params{}, err
	}
	password, err := bootstrap.ValidatePassword(os.Getenv("OMNISURG_OPERATOR_PASSWORD"))
	if err != nil {
		return bootstrap.Params{}, err
	}
	name := bootstrap.DisplayNameOrDefault(os.Getenv("OMNISURG_OPERATOR_NAME"))
	return bootstrap.Params{Email: email, Password: password, DisplayName: name}, nil
}

// printResult prints the created operator and its two-factor enrolment details
// ONCE to stdout. The password is never printed.
func printResult(r bootstrap.Result) {
	fmt.Println("Created provider super-admin:")
	fmt.Printf("  email:       %s\n", r.Email)
	fmt.Printf("  totp secret: %s\n", r.Secret)
	fmt.Printf("  otpauth uri: %s\n", r.OtpauthURI)
	fmt.Println()
	fmt.Println("Enrol an authenticator app with this secret or otpauth uri now. It will not be shown again.")
	fmt.Println("Run this once, interactively. Do not capture this output in shared or CI logs. This secret is shown only now and cannot be retrieved later.")
}
