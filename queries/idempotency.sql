-- queries/idempotency.sql

-- name: GetIdempotentResponse :one
SELECT status_code, response_body FROM idempotency_keys
WHERE idem_key = $1 AND route = $2;

-- name: SaveIdempotentResponse :exec
INSERT INTO idempotency_keys (tenant_id, idem_key, route, status_code, response_body)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, idem_key, route) DO NOTHING;
