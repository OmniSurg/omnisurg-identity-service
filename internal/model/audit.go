package model

import (
	"time"

	"github.com/google/uuid"
)

// AuditEvent is one emitted audit record. In P1 it lands in the local audit_log
// table; Plan F swaps the emitter for the audit-service gRPC client.
type AuditEvent struct {
	TenantID   uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   *uuid.UUID
	RequestID  string
}

// AuditRow is a stored audit record returned by the debug query.
type AuditRow struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   *uuid.UUID
	RequestID  string
	OccurredAt time.Time
}
