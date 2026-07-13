-- crypto_keys holds the wrapped data encryption key for this service. Exactly
-- one active row. The DEK is wrapped by the KEK from OMNISURG_KEK_BASE64 and is
-- never stored in plaintext. This table is service global: no tenant_id, no RLS.
CREATE TABLE crypto_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wrapped_dek BYTEA NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- users: one row per staff or provider user. email_encrypted is AES-256-GCM
-- ciphertext. email_hash is the HMAC blind index used for login lookup, unique
-- per tenant. tenant_id is the RLS scope.
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    branch_id       UUID,
    email_encrypted BYTEA NOT NULL,
    email_hash      TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL,
    provider_role   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    mfa_enrolled    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Email hash is unique per tenant so the same email can exist across tenants.
CREATE UNIQUE INDEX users_tenant_email_hash_key ON users (tenant_id, email_hash);
CREATE INDEX users_tenant_id_idx ON users (tenant_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_scope ON users
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- idempotency_keys backs POST idempotency, scoped per tenant and route.
CREATE TABLE idempotency_keys (
    tenant_id     UUID NOT NULL,
    idem_key      TEXT NOT NULL,
    route         TEXT NOT NULL,
    status_code   INT NOT NULL,
    response_body BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idem_key, route)
);
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY idempotency_tenant_scope ON idempotency_keys
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- audit_log is the Phase 1 walking-skeleton stand-in for omnisurg-audit-service.
-- Append only. Replaced by a gRPC client to the audit-service in Plan F.
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    actor_id    UUID,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   UUID,
    request_id  TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_lookup_idx ON audit_log (tenant_id, action, actor_id);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_tenant_scope ON audit_log
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
