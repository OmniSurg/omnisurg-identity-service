-- queries/credential_tokens.sql

-- name: InsertCredentialToken :one
-- credential_tokens is service-global (no RLS); this write still runs inside
-- WithTenant so it shares connection lifecycle discipline with the sibling
-- user writes, though the GUC has no bearing on this table's visibility.
INSERT INTO credential_tokens (
    tenant_id, user_id, purpose, token_hash, expires_at
) VALUES ($1, $2, $3, $4, $5)
RETURNING id, tenant_id, user_id, purpose, expires_at, consumed_at;

-- name: GetCredentialTokenByHash :one
-- Resolves a token by its unique hash with NO tenant filter: credential_tokens
-- carries no RLS policy, so this is a genuine service-global, pre-auth lookup
-- (the same posture as GetActiveDEK on crypto_keys). Isolation is the token's
-- 256-bit entropy, not a WHERE clause.
SELECT id, tenant_id, user_id, purpose, expires_at, consumed_at
FROM credential_tokens
WHERE token_hash = $1
LIMIT 1;

-- name: ConsumeCredentialToken :one
-- Single-shot conditional consume: the row updates only when consumed_at is
-- still null, so a replayed activate call (or a lost race with a concurrent
-- one) matches no row and returns pgx.ErrNoRows rather than silently
-- succeeding twice.
UPDATE credential_tokens
SET consumed_at = now()
WHERE id = $1 AND consumed_at IS NULL
RETURNING id;

-- name: InvalidateActivationTokensForUser :exec
-- Marks every outstanding (unconsumed) activation token for the user
-- consumed, so a fresh resend cannot be joined by a still-live prior link.
UPDATE credential_tokens
SET consumed_at = now()
WHERE user_id = $1 AND purpose = 'activation' AND consumed_at IS NULL;
