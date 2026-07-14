-- phone_encrypted is PII (AES-256-GCM under the keyring, same pattern as
-- email_encrypted). Nullable: only a provisioned pending admin carries one in
-- Phase 1; a directly created user (CreateUser) leaves it null. No blind
-- index: there is no lookup-by-phone need.
ALTER TABLE users ADD COLUMN phone_encrypted BYTEA;

-- credential_tokens is SERVICE-GLOBAL: no tenant_id RLS policy, exactly like
-- crypto_keys. The pre-auth account activation endpoint resolves a token by
-- its hash before any app.tenant_id is known, so a FORCE ROW LEVEL SECURITY
-- table would hide every row from that lookup. Isolation instead comes from
-- the token's 256-bit entropy: only the holder of the raw token can resolve
-- its row, and the row binds exactly one tenant and user. tenant_id here is a
-- plain data column, not an RLS key; it is carried so the write that follows a
-- successful lookup (consume the token, set the password, activate the user)
-- can run under WithTenant(tenant_id) with the users-table RLS active.
CREATE TABLE credential_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    user_id     UUID NOT NULL REFERENCES users(id),
    purpose     TEXT NOT NULL,
    token_hash  BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX credential_tokens_token_hash_key ON credential_tokens (token_hash);
CREATE INDEX credential_tokens_user_id_idx ON credential_tokens (user_id);
