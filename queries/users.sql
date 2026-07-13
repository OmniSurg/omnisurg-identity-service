-- queries/users.sql

-- name: AuthByEmailHash :one
-- Runs under RLS (app.tenant_id set by WithTenant), so only the caller tenant's
-- row is visible. email_hash is unique per tenant. LIMIT 1 is defensive: it
-- keeps the :one contract safe even if RLS were ever misconfigured. mfa_enrolled
-- is projected so login can decide whether to require a second factor.
SELECT id, tenant_id, branch_id, password_hash, role, provider_role, status,
    mfa_enrolled
FROM users
WHERE email_hash = $1
LIMIT 1;

-- name: GetTotpSecret :one
-- Reads the encrypted TOTP secret and mfa_enrolled for a user by id, under RLS.
-- A null totp_secret means the user has not enrolled a secret.
SELECT totp_secret, mfa_enrolled
FROM users
WHERE id = $1;

-- name: SetTotpSecret :exec
-- Stores the encrypted TOTP secret. It does NOT flip mfa_enrolled: enrolment
-- only completes once the user confirms a code, which calls SetMfaEnrolled.
UPDATE users
SET totp_secret = $2, updated_at = now()
WHERE id = $1;

-- name: SetMfaEnrolled :exec
-- Flips mfa_enrolled, called on a confirmed enrolment.
UPDATE users
SET mfa_enrolled = $2, updated_at = now()
WHERE id = $1;

-- name: ClearTotp :exec
-- Clears the secret, unsets mfa_enrolled, and resets the replay step, returning
-- the user to the enrol-required state. Used by the super-admin reset. The last
-- accepted step is nulled too so a fresh re-enrolment starts with clean replay
-- state (a reset resets all TOTP state, not just the secret).
UPDATE users
SET totp_secret = NULL, mfa_enrolled = false, totp_last_step = NULL,
    updated_at = now()
WHERE id = $1;

-- name: AcceptTotpStep :one
-- Records the highest accepted TOTP time-step for a user, atomically rejecting a
-- replayed or older code: the row updates only when the new step is strictly
-- greater than the stored one (or none is stored yet), so a code from the same
-- or an earlier window matches no row (RFC 6238 section 5.2). Runs under RLS via
-- WithTenant, so it is scoped to the caller tenant exactly like the sibling TOTP
-- writes. Returns the user id only when a step was accepted.
UPDATE users
SET totp_last_step = sqlc.arg('step')::bigint, updated_at = now()
WHERE id = sqlc.arg('id')
    AND (totp_last_step IS NULL OR totp_last_step < sqlc.arg('step')::bigint)
RETURNING id;

-- name: CreateUser :one
INSERT INTO users (
    tenant_id, branch_id, email_encrypted, email_hash, password_hash,
    display_name, role, provider_role
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, tenant_id, branch_id, email_encrypted, display_name, role,
    provider_role, status, mfa_enrolled, created_at, updated_at;

-- name: GetUser :one
SELECT id, tenant_id, branch_id, email_encrypted, display_name, role,
    provider_role, status, mfa_enrolled, created_at, updated_at
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, tenant_id, branch_id, email_encrypted, display_name, role,
    provider_role, status, mfa_enrolled, created_at, updated_at
FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: CountProviderSuperAdmins :one
-- Counts live provider super-admins under the caller tenant (the platform
-- tenant, set by WithTenant). Used by the operator bootstrap to stay a safe
-- one-shot: it refuses to create a second operator once one exists.
SELECT COUNT(*) FROM users
WHERE provider_role = $1 AND status <> 'deleted';

-- name: UpdateUser :one
UPDATE users
SET display_name = COALESCE(sqlc.narg('display_name'), display_name),
    status       = COALESCE(sqlc.narg('status'), status),
    updated_at   = now()
WHERE id = sqlc.arg('id')
RETURNING id, tenant_id, branch_id, email_encrypted, display_name, role,
    provider_role, status, mfa_enrolled, created_at, updated_at;

-- name: SoftDeleteUser :one
UPDATE users
SET status = 'deleted', updated_at = now()
WHERE id = $1 AND status <> 'deleted'
RETURNING id;
