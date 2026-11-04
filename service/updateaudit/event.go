// Package updateaudit stores only the bounded service.update audit contract.
// It neither authorizes operations nor exposes a product audit reader.
package updateaudit

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUnavailable = errors.New("service.update audit persistence unavailable")
	ErrConflict    = errors.New("service.update audit event identity conflict")
	ErrInvalid     = errors.New("invalid service.update audit event")
)

// RequestedFields describes presence, not changed values. No input text is kept.
type RequestedFields uint8

const (
	Name RequestedFields = 1 << iota
	Description
	MaintenanceExpiresAt
	EscalationPolicyID
)

// Event is an allowlist. Zero UUID identity/target fields mean unknown, never
// inferred from a client locator or from the actor's Home. OccurredAt is a
// server observation, not a physical PostgreSQL commit timestamp.
// commit_unknown/rollback_unconfirmed are observations of uncertainty, not
// terminal rollback claims. A committed row is a transaction's durable witness;
// it may coexist with a separately identified uncertainty observation.
type Event struct {
	EventID, AttemptID, RequestID                    uuid.UUID
	ActorKind                                        string
	ActorID, HomeOrganizationID                      uuid.UUID
	AuthoritySource, AuthorityRole, OrganizationRole string
	ServiceID, TargetOrganizationID                  uuid.UUID
	RequestedFields                                  RequestedFields
	Outcome, Reason                                  string
	OccurredAt                                       time.Time
}

func (e Event) valid() bool {
	if e.EventID == uuid.Nil || e.AttemptID == uuid.Nil || e.RequestID == uuid.Nil || e.OccurredAt.IsZero() || e.RequestedFields > 15 {
		return false
	}
	switch e.Outcome {
	case "committed", "denied", "validation_failed", "tx_failed", "commit_unknown", "rollback_unconfirmed":
	default:
		return false
	}
	switch e.Reason {
	case "updated", "authority_denied", "target_unavailable", "invalid_fields", "begin_failed", "write_failed", "audit_write_failed", "commit_rejected", "commit_unconfirmed", "rollback_unconfirmed":
	default:
		return false
	}
	if (e.ServiceID == uuid.Nil) != (e.TargetOrganizationID == uuid.Nil) {
		return false
	}
	if e.Outcome == "committed" && (e.ServiceID == uuid.Nil || e.Reason != "updated") {
		return false
	}
	switch e.ActorKind {
	case "human":
		if e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return false
		}
		if e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER" {
			return false
		}
		return e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.OrganizationRole == "ORG_ADMIN" || e.AuthorityRole == "org_member" && e.OrganizationRole == "ORG_MEMBER"
	case "internal_system":
		return e.ActorID == uuid.Nil && e.HomeOrganizationID == uuid.Nil && e.AuthoritySource == "trusted_internal_system" && e.AuthorityRole == "internal_system" && e.OrganizationRole == "unknown"
	case "unknown":
		return e.ActorID == uuid.Nil && e.HomeOrganizationID == uuid.Nil && e.AuthoritySource == "unknown" && e.AuthorityRole == "unknown" && e.OrganizationRole == "unknown" && e.Outcome != "committed"
	}
	return false
}

func nullable(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// Append stages a row on the caller's transaction; success is not evidence of
// commit until that transaction commits. Repeating the identical event is
// idempotent. Reusing its ID for different content is an explicit conflict.
// Database diagnostics never escape this package.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if !e.valid() {
		return ErrInvalid
	}
	if tx == nil {
		return ErrUnavailable
	}
	args := []any{e.EventID, e.AttemptID, e.RequestID, e.ActorKind, nullable(e.ActorID), nullable(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, nullable(e.ServiceID), nullable(e.TargetOrganizationID), int(e.RequestedFields), e.Outcome, e.Reason, e.OccurredAt.UTC().Truncate(time.Microsecond)}
	r, err := tx.ExecContext(ctx, `INSERT INTO service_update_audit_events
	 (event_id,attempt_id,request_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,service_id,target_organization_id,requested_fields,outcome,reason_code,occurred_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(event_id) DO NOTHING`, args...)
	if err != nil {
		return ErrUnavailable
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ErrUnavailable
	}
	if n == 1 {
		return nil
	}
	var same bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM service_update_audit_events WHERE event_id=$1
	 AND attempt_id=$2 AND request_id=$3 AND actor_kind=$4 AND actor_id IS NOT DISTINCT FROM $5::uuid
	 AND home_organization_id IS NOT DISTINCT FROM $6::uuid AND authority_source=$7 AND authority_role=$8 AND organization_role=$9
	 AND service_id IS NOT DISTINCT FROM $10::uuid AND target_organization_id IS NOT DISTINCT FROM $11::uuid
	 AND requested_fields=$12 AND outcome=$13 AND reason_code=$14 AND occurred_at=$15)`, args...).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}

// RecordFailure uses a fresh bounded transaction after business locks have been
// released. It detaches request cancellation and context fields deliberately.
// A failed Commit is not retried and is never reported as durable success.
func RecordFailure(db *sql.DB, e Event) (resultErr error) {
	if db == nil || e.Outcome == "committed" {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		// ErrTxDone is expected after Commit or context-driven cleanup. It is
		// not used as proof that another transaction's resources are released.
		done := make(chan error, 1)
		go func() { done <- tx.Rollback() }()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, sql.ErrTxDone) {
				resultErr = ErrUnavailable
			}
		case <-timer.C:
			resultErr = ErrUnavailable
		}
	}()
	if err := Append(ctx, tx, e); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	select {
	case err := <-done:
		if err != nil {
			return ErrUnavailable
		}
	case <-ctx.Done():
		return ErrUnavailable
	}
	return nil
}
