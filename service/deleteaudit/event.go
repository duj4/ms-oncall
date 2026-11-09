// Package deleteaudit persists only explicit Service targets in GraphQL
// DeleteAll. It grants no permission and never replays a business operation.
package deleteaudit

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var (
	ErrInvalid     = errors.New("invalid service.delete audit event")
	ErrUnavailable = errors.New("service.delete audit persistence unavailable")
	ErrConflict    = errors.New("service.delete audit event identity conflict")
)

// Event contains event-time evidence, never client input or current-state FKs.
// Zero identity/target UUIDs mean unknown. An uncertainty observation is not a
// rollback claim and can coexist with an eventually committed witness.
type Event struct {
	EventID, AttemptID, RequestID                    uuid.UUID
	ActorKind                                        string
	ActorID, HomeOrganizationID                      uuid.UUID
	AuthoritySource, AuthorityRole, OrganizationRole string
	ServiceID, TargetOrganizationID                  uuid.UUID
	Outcome, Reason                                  string
	OccurredAt                                       time.Time
}

func (e Event) valid() bool {
	if e.EventID == uuid.Nil || e.AttemptID == uuid.Nil || e.RequestID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 {
		return false
	}
	validReason := false
	switch e.Outcome {
	case "committed":
		validReason = e.Reason == "deleted"
	case "denied":
		validReason = e.Reason == "authority_denied"
	case "validation_failed":
		validReason = e.Reason == "invalid_fields" || e.Reason == "target_unavailable"
	case "tx_failed":
		validReason = e.Reason == "begin_failed" || e.Reason == "write_failed" || e.Reason == "audit_write_failed" || e.Reason == "commit_rejected"
	case "commit_unknown":
		validReason = e.Reason == "commit_unconfirmed"
	case "rollback_unconfirmed":
		validReason = e.Reason == "rollback_unconfirmed"
	}
	if !validReason || (e.ServiceID == uuid.Nil) != (e.TargetOrganizationID == uuid.Nil) || e.TargetOrganizationID.String() == organization.DefaultOrganizationID {
		return false
	}
	if e.Outcome == "committed" && e.ServiceID == uuid.Nil {
		return false
	}
	switch e.ActorKind {
	case "human":
		if e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return false
		}
		if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
			if e.OrganizationRole != "NONE" || (e.AuthorityRole != "platform_admin" && e.AuthorityRole != "none") {
				return false
			}
		} else {
			validOrgRole := e.OrganizationRole == "ORG_ADMIN" || e.OrganizationRole == "ORG_MEMBER"
			validAuthority := e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.OrganizationRole == "ORG_ADMIN" || e.AuthorityRole == "org_member" && e.OrganizationRole == "ORG_MEMBER"
			if !validOrgRole || !validAuthority {
				return false
			}
		}
		return e.Outcome != "committed" || e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.TargetOrganizationID == e.HomeOrganizationID
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

// Append stages a witness on the business transaction. Identical EventID replay
// is idempotent; different content under the same ID is an explicit conflict.
// A successful INSERT is not proof that the owning transaction committed.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if !e.valid() {
		return ErrInvalid
	}
	if tx == nil {
		return ErrUnavailable
	}
	args := []any{e.EventID, e.AttemptID, e.RequestID, e.ActorKind, nullable(e.ActorID), nullable(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, nullable(e.ServiceID), nullable(e.TargetOrganizationID), e.Outcome, e.Reason, e.OccurredAt.UTC().Truncate(time.Microsecond)}
	r, err := tx.ExecContext(ctx, `INSERT INTO service_delete_audit_events
	 (event_id,attempt_id,request_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,service_id,target_organization_id,outcome,reason_code,occurred_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(event_id) DO NOTHING`, args...)
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
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM service_delete_audit_events WHERE event_id=$1
	 AND attempt_id=$2 AND request_id=$3 AND actor_kind=$4 AND actor_id IS NOT DISTINCT FROM $5::uuid
	 AND home_organization_id IS NOT DISTINCT FROM $6::uuid AND authority_source=$7 AND authority_role=$8 AND organization_role=$9
	 AND service_id IS NOT DISTINCT FROM $10::uuid AND target_organization_id IS NOT DISTINCT FROM $11::uuid
	 AND outcome=$12 AND reason_code=$13 AND occurred_at=$14)`, args...).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}

// RecordFailures makes one bounded, atomic append after the caller proves the
// business connection released. It never retries or claims uncertain durability.
func RecordFailures(db *sql.DB, events []Event) (resultErr error) {
	if db == nil || len(events) == 0 || len(events) > 50 {
		return ErrUnavailable
	}
	for _, e := range events {
		if e.Outcome == "committed" || !e.valid() {
			return ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
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
	for _, e := range events {
		if err := Append(ctx, tx, e); err != nil {
			return err
		}
	}
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	select {
	case err := <-done:
		if err != nil {
			return ErrUnavailable
		}
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
