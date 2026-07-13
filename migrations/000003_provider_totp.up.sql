-- totp_secret holds the AES-256-GCM ciphertext of the provider user's TOTP
-- shared secret. It is nullable: a user with no secret has not enrolled. It is
-- encrypted under the same DEK as email_encrypted, so the plaintext base32 seed
-- never lands in the database. mfa_enrolled (added in the initial migration)
-- flips to true only after the user confirms a code against this secret.
ALTER TABLE users ADD COLUMN totp_secret BYTEA;
