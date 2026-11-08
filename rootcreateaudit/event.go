// Package rootcreateaudit persists the bounded PlatformAdmin top-level four
// Root Create contract. It neither authorizes requests nor retries Creates.
package rootcreateaudit

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var ErrInvalid = errors.New("invalid global Root Create audit event")
var ErrUnavailable = errors.New("global Root Create audit persistence unavailable")

type Event struct {
	EventID, AttemptID, RequestID uuid.UUID
	ActorID, HomeOrganizationID   uuid.UUID
	OrganizationRole              string
	RootType                      string
	RootID, TargetOrganizationID  uuid.UUID
	Outcome, Reason               string
	OccurredAt                    time.Time
}

func (e Event) valid() bool {
	if e.EventID == uuid.Nil || e.AttemptID == uuid.Nil || e.RequestID == uuid.Nil || e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 {
		return false
	}
	switch e.RootType {
	case "service", "escalation_policy", "schedule", "rotation":
	default:
		return false
	}
	if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
		if e.OrganizationRole != "NONE" {
			return false
		}
	} else if e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER" {
		return false
	}
	if e.TargetOrganizationID.String() == organization.DefaultOrganizationID {
		return false
	}
	if e.RootID != uuid.Nil && e.TargetOrganizationID == uuid.Nil {
		return false
	}
	reasons := map[string]string{"committed": "created", "denied": "authority_denied", "validation_failed": "invalid_fields", "tx_failed": "write_failed", "commit_unknown": "commit_unconfirmed", "rollback_unconfirmed": "rollback_unconfirmed"}
	if reasons[e.Outcome] != e.Reason || e.Reason == "" {
		return false
	}
	return e.Outcome != "committed" || e.RootID != uuid.Nil
}

func nullable(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// Append stages an immutable event in the same transaction as the new Root.
// A staged committed witness is not proof of commit until Commit returns nil.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if !e.valid() {
		return ErrInvalid
	}
	if tx == nil {
		return ErrUnavailable
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO global_root_create_audit_events
	 (event_id,attempt_id,request_id,actor_id,home_organization_id,organization_role,root_type,root_id,target_organization_id,outcome,reason_code,occurred_at)
	 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, e.EventID, e.AttemptID, e.RequestID, e.ActorID, e.HomeOrganizationID, e.OrganizationRole, e.RootType, nullable(e.RootID), nullable(e.TargetOrganizationID), e.Outcome, e.Reason, e.OccurredAt.UTC())
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// RecordFailure is a single bounded attempt, after the business connection's
// release barrier. It never replays the Create or claims uncertain durability.
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
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}
