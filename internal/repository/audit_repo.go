package repository

import (
	"context"
	"fmt"

	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/db"
	"github.com/OmniSurg/omnisurg-identity-service/internal/model"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditRepository is the P1 local implementation of the audit emitter. It
// writes append only rows to audit_log under tenant scope.
type AuditRepository struct {
	pool *pgxpool.Pool
}

// NewAuditRepository builds an AuditRepository.
func NewAuditRepository(pool *pgxpool.Pool) *AuditRepository {
	return &AuditRepository{pool: pool}
}

// Emit records one audit event. Errors are returned so callers can log them;
// audit write failure is alertable per the observability standard.
func (r *AuditRepository) Emit(ctx context.Context, ev model.AuditEvent) error {
	return pg.WithTenant(ctx, r.pool, ev.TenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		err := db.New(conn).InsertAuditLog(ctx, db.InsertAuditLogParams{
			TenantID:   pgUUID(ev.TenantID),
			ActorID:    pgUUIDPtr(ev.ActorID),
			Action:     ev.Action,
			TargetType: ev.TargetType,
			TargetID:   pgUUIDPtr(ev.TargetID),
			RequestID:  ev.RequestID,
		})
		if err != nil {
			return fmt.Errorf("insert audit log: %w", err)
		}
		return nil
	})
}

// Query returns recent audit rows for an action, optionally filtered by actor.
// Used only by the non production debug endpoint the CST queries.
func (r *AuditRepository) Query(ctx context.Context, tenantID uuid.UUID, action string, actorID *uuid.UUID) ([]model.AuditRow, error) {
	var out []model.AuditRow
	err := pg.WithTenant(ctx, r.pool, tenantID.String(), func(ctx context.Context, conn pg.Conn) error {
		rows, qerr := db.New(conn).QueryAuditLog(ctx, db.QueryAuditLogParams{
			Action:  action,
			ActorID: pgUUIDPtr(actorID),
		})
		if qerr != nil {
			return fmt.Errorf("query audit log: %w", qerr)
		}
		for _, row := range rows {
			out = append(out, model.AuditRow{
				ID:         fromPgUUID(row.ID),
				TenantID:   fromPgUUID(row.TenantID),
				ActorID:    fromPgUUIDPtr(row.ActorID),
				Action:     row.Action,
				TargetType: row.TargetType,
				TargetID:   fromPgUUIDPtr(row.TargetID),
				RequestID:  row.RequestID,
				OccurredAt: row.OccurredAt.Time,
			})
		}
		return nil
	})
	return out, err
}
