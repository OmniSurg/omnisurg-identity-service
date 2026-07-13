-- Enforce exactly one active data encryption key. A concurrent first boot that
-- loses the race fails this constraint with SQLSTATE 23505 and reloads the
-- winning key rather than silently creating a second active DEK.
CREATE UNIQUE INDEX crypto_keys_one_active ON crypto_keys (active) WHERE active;
