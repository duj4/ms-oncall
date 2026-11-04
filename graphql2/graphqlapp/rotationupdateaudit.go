package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule/updateaudit"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

// Project only this resolver's diagnostic context. Field.Name is the schema
// operation; Field.Alias is client text and must not select this policy. The
// real resolver/authentication context is never replaced by this log context.
func rotationUpdateDiagnosticContext(ctx context.Context) context.Context {
	field := graphql.GetFieldContext(ctx)
	if field == nil || field.Object != "Mutation" || field.Field.Name != "updateRotation" {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "MutationName", "updateRotation")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

func rotationUpdateAuditEvent(ctx context.Context, input graphql2.UpdateRotationInput) updateaudit.Event {
	// Reuse the accepted C5 finite identity projection without changing its contract.
	e := scheduleUpdateAuditEvent(ctx, graphql2.UpdateScheduleInput{})
	e.Operation = updateaudit.RotationUpdate
	for i, present := range []bool{input.Name != nil, input.Description != nil, input.Start != nil, input.Type != nil, input.ShiftLength != nil, input.TimeZone != nil, input.UserIDs != nil, input.ActiveUserIndex != nil} {
		if present {
			e.RequestedFields |= 1 << i
		}
	}
	return e
}

// Retain existing safe permission/field behavior and error mapping. Never let
// raw SQL diagnostics reach the outer resolver logger, tracing or HTTP output.
func rotationUpdateSafeError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		// Preserve only this operation's existing field mappings. The generic
		// mapper also handles other domains and can include their SQL hints.
		if pg.Code == "23505" && (pg.ConstraintName == "rotations_name" || pg.ConstraintName == "rotations_name_unique") {
			return validation.NewFieldError("Name", "already in use")
		}
		if pg.Code == "23503" && pg.ConstraintName == "rotation_participants_user_id_fkey" {
			return validation.NewFieldError("UserID", "user does not exist")
		}
		if pg.Code == "23514" && pg.ConstraintName == "participants_per_rotation_limit" {
			mapped := errutil.MapDBError(err)
			if errutil.IsLimitError(mapped) {
				return mapped
			}
		}
		return errors.New("rotation.update transaction failed")
	}
	if permission.IsPermissionError(err) || validation.IsValidationError(err) || errutil.IsLimitError(err) {
		return err
	}
	return errors.New("rotation.update transaction failed")
}

// Top-level Rotation Update owns the same Conn/Tx lifecycle as A1. Reuse its
// audit-neutral commitServiceUpdate/releaseServiceUpdate primitives unchanged;
// neither the legacy helper nor other Mutation transaction owners are migrated.
func rotationUpdateAuditFault(ctx context.Context, event updateaudit.Event, fault string) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "rotation.update", "AuditFault": fault,
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, updateaudit.ErrUnavailable)
}

// A confirmed Commit already persisted both business and audit rows. Report
// cleanup uncertainty separately without claiming an audit-persistence gap.
func rotationUpdateCommittedCleanupFault(ctx context.Context, event updateaudit.Event) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "rotation.update", "AuditFault": "resource_release_unconfirmed",
		"AuditOutcome": "committed",
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, errors.New("rotation.update committed; resource release unconfirmed"))
}

func finishRotationUpdateAudit(ctx context.Context, db *sql.DB, conn *sql.Conn, tx *sql.Tx, commitAttempted, commitFinalized bool, event updateaudit.Event, operationErr error) error {
	rollbackErr, released := releaseServiceUpdate(conn, tx, commitFinalized)
	if operationErr == nil {
		// Top-level UpdateRotation returns nil only after observing Commit return nil.
		// Cleanup must not replace that confirmed, atomic success with failure.
		if !released {
			rotationUpdateCommittedCleanupFault(ctx, event)
		}
		return nil
	}
	if commitAttempted {
		event.Outcome, event.Reason = serviceUpdateCommitOutcome(operationErr)
	} else {
		if event.Outcome == "validation_failed" && !validation.IsValidationError(rotationUpdateSafeError(operationErr)) && !errors.Is(operationErr, sql.ErrNoRows) {
			event.Outcome, event.Reason = "tx_failed", "write_failed"
		}
		if tx != nil {
			// ErrTxDone alone does not prove rollback; in particular cancellation
			// can race database/sql's automatic finalization.
			if rollbackErr != nil {
				event.Outcome, event.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
			}
		}
	}
	event.RotationRowWritten = false // Failed/unknown observations never claim committed effects.
	event.Before, event.After = nil, nil
	event.EventID = uuid.New() // failure/uncertainty is separate from staged success
	event.OccurredAt = time.Now()
	safe := rotationUpdateSafeError(operationErr)
	if !released {
		rotationUpdateAuditFault(ctx, event, "resource_release_unconfirmed")
		return fmt.Errorf("%w; rotation.update audit persistence unavailable", safe)
	}
	if err := updateaudit.RecordFailure(db, event); err != nil {
		rotationUpdateAuditFault(ctx, event, "persistence_unavailable")
		return fmt.Errorf("%w; rotation.update audit persistence unavailable", safe)
	}
	return safe
}

// This fixed diagnostic is NOT a durable audit event and carries no actor,
// destination, client input or inherited authentication/log fields.
func rotationUpdateLegacyDiagnostic(ctx context.Context) {
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "rotation.update", "AuditCoverage": "NOT_COVERED",
		"AuditReason": "legacy_inherited_transaction",
	})
	log.Logf(clean, "Rotation update legacy transaction coverage.")
}
