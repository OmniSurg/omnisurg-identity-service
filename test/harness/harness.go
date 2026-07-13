// Package harness provides shared integration test helpers: an ephemeral
// Postgres via testcontainers, migration application, and a non superuser
// application role. Used by repository, keyring, and service integration tests.
package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	tcpg "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// StartPostgres launches a throwaway Postgres 16 container, applies every
// migration as the bootstrap owner, then creates a NON superuser, NON owner
// application role and returns a DSN that connects as that role.
//
// This distinction is critical: PostgreSQL superusers and table owners BYPASS
// row level security, even with FORCE ROW LEVEL SECURITY. The bootstrap
// POSTGRES_USER the testcontainers module creates is a superuser, so running
// the application pool as it would silently disable RLS and turn every tenant
// isolation test into a false pass. The returned appDSN connects as a plain
// role (NOSUPERUSER, NOBYPASSRLS, not the table owner) so RLS is fully enforced
// and the leak tests are real.
func StartPostgres(t *testing.T) (appDSN string, stop func()) {
	t.Helper()
	ctx := context.Background()
	container, err := tcpg.Run(ctx,
		"postgres:16-alpine",
		tcpg.WithDatabase("omnisurg_identity"),
		tcpg.WithUsername("omnisurg_root"),
		tcpg.WithPassword("root"),
		tcpg.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	cleanup := func() { _ = container.Terminate(ctx) }

	adminDSN, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	applyMigrations(t, adminDSN)
	provisionAppRole(t, adminDSN)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	appDSN = fmt.Sprintf("postgres://omnisurg_app:app@%s:%s/omnisurg_identity?sslmode=disable", host, port.Port())
	return appDSN, cleanup
}

// applyMigrations runs every up migration in order, resolved relative to this
// source file so tests work from any package directory.
func applyMigrations(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)

	_, thisFile, _, _ := runtime.Caller(0)
	migDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations")
	entries, err := os.ReadDir(migDir)
	require.NoError(t, err)

	var ups []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			ups = append(ups, e.Name())
		}
	}
	sort.Strings(ups)
	for _, name := range ups {
		sqlBytes, err := os.ReadFile(filepath.Join(migDir, name))
		require.NoError(t, err)
		_, err = conn.Exec(ctx, string(sqlBytes))
		require.NoError(t, err, "applying migration %s", name)
	}
}

// provisionAppRole creates the non superuser application role and grants it the
// privileges the service needs. Tables stay owned by the bootstrap role, so the
// app role is fully subject to RLS.
func provisionAppRole(t *testing.T, adminDSN string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	require.NoError(t, err)
	defer conn.Close(ctx)
	stmts := []string{
		"CREATE ROLE omnisurg_app LOGIN PASSWORD 'app' NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA public TO omnisurg_app",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO omnisurg_app",
	}
	for _, s := range stmts {
		_, err := conn.Exec(ctx, s)
		require.NoError(t, err, "provision app role: %s", s)
	}
}
