-- queries/keys.sql

-- name: GetActiveDEK :one
SELECT wrapped_dek FROM crypto_keys
WHERE active = true
ORDER BY created_at DESC
LIMIT 1;

-- name: InsertDEK :one
INSERT INTO crypto_keys (wrapped_dek) VALUES ($1)
RETURNING id;
