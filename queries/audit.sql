-- queries/audit.sql

-- name: InsertAuditLog :exec
INSERT INTO audit_log (tenant_id, actor_id, action, target_type, target_id, request_id)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: QueryAuditLog :many
SELECT id, tenant_id, actor_id, action, target_type, target_id, request_id, occurred_at
FROM audit_log
WHERE action = $1
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_id = sqlc.narg('actor_id')::uuid)
ORDER BY occurred_at DESC
LIMIT 50;
