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
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule/updateaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

// Project only this resolver's diagnostic context. Field.Name is the schema
// operation; Field.Alias is client text and must not select this policy. The
// real resolver/authentication context is never replaced by this log context.
func scheduleUpdateDiagnosticContext(ctx context.Context) context.Context {
	field := graphql.GetFieldContext(ctx)
	if field == nil || field.Object != "Mutation" || field.Field.Name != "updateSchedule" {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "MutationName", "updateSchedule")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

func scheduleUpdateAuditEvent(ctx context.Context, input graphql2.UpdateScheduleInput) updateaudit.Event {
	e := updateaudit.Event{Operation: updateaudit.ScheduleUpdate, EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", OccurredAt: time.Now()}
	if input.Name != nil {
		e.RequestedFields |= updateaudit.ScheduleName
	}
	if input.Description != nil {
		e.RequestedFields |= updateaudit.ScheduleDescription
	}
	if input.TimeZone != nil {
		e.RequestedFields |= updateaudit.ScheduleTimeZone
	}
	if ctx == nil {
		return e
	}
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		e.RequestID = id
	}
	home, err := rootManagementHome(ctx)
	if err != nil {
		return e
	}
	if home == nil {
		if permission.System(ctx) && permission.UserID(ctx) == "" && !permission.Service(ctx) && auth.RequesterFromContext(ctx) == nil && executioncontext.ExecutionContextFromContext(ctx) == nil && permission.Source(ctx) == nil {
			e.ActorKind, e.AuthoritySource, e.AuthorityRole = "internal_system", "trusted_internal_system", "internal_system"
		}
		return e
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if permission.System(ctx) || permission.Service(ctx) || !permission.User(ctx) || ec == nil || ec.Privileges() == nil || ec.Privileges().PlatformAdmin() != permission.Admin(ctx) {
		return e
	}
	e.ActorKind, e.ActorID, e.HomeOrganizationID = "human", auth.RequesterFromContext(ctx).UserID(), *home
	e.AuthoritySource = "current_local_user_organization_at_admission"
	e.OrganizationRole = string(ec.Privileges().OrganizationRole())
	switch {
	case ec.Privileges().PlatformAdmin():
		e.AuthorityRole = "platform_admin"
	case ec.Privileges().OrganizationRole() == organization.OrganizationRoleAdmin:
		e.AuthorityRole = "org_admin"
	default:
		e.AuthorityRole = "org_member"
	}
	return e
}

// Retain existing safe permission/field behavior and error mapping. Never let
// raw SQL diagnostics reach the outer resolver logger, tracing or HTTP output.
func scheduleUpdateSafeError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		// Preserve only this operation's existing field mappings. The generic
		// mapper also handles other domains and can include their SQL hints.
		if pg.Code == "23505" && (pg.ConstraintName == "schedules_name" || pg.ConstraintName == "schedules_name_key") {
			return validation.NewFieldError("Name", "already in use")
		}
		return errors.New("schedule.update transaction failed")
	}
	if permission.IsPermissionError(err) || validation.IsValidationError(err) {
		return err
	}
	return errors.New("schedule.update transaction failed")
}

// Top-level Schedule Update owns the same Conn/Tx lifecycle as A1. Reuse its
// audit-neutral commitServiceUpdate/releaseServiceUpdate primitives unchanged;
// neither the legacy helper nor other Mutation transaction owners are migrated.
func scheduleUpdateAuditFault(ctx context.Context, event updateaudit.Event, fault string) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "schedule.update", "AuditFault": fault,
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, updateaudit.ErrUnavailable)
}

// A confirmed Commit already persisted both business and audit rows. Report
// cleanup uncertainty separately without claiming an audit-persistence gap.
func scheduleUpdateCommittedCleanupFault(ctx context.Context, event updateaudit.Event) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "schedule.update", "AuditFault": "resource_release_unconfirmed",
		"AuditOutcome": "committed",
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, errors.New("schedule.update committed; resource release unconfirmed"))
}

func finishScheduleUpdateAudit(ctx context.Context, db *sql.DB, conn *sql.Conn, tx *sql.Tx, commitAttempted, commitFinalized bool, event updateaudit.Event, operationErr error) error {
	rollbackErr, released := releaseServiceUpdate(conn, tx, commitFinalized)
	if operationErr == nil {
		// Top-level UpdateSchedule returns nil only after observing Commit return nil.
		// Cleanup must not replace that confirmed, atomic success with failure.
		if !released {
			scheduleUpdateCommittedCleanupFault(ctx, event)
		}
		return nil
	}
	if commitAttempted {
		event.Outcome, event.Reason = serviceUpdateCommitOutcome(operationErr)
	} else {
		if event.Outcome == "validation_failed" && !validation.IsValidationError(scheduleUpdateSafeError(operationErr)) && !errors.Is(operationErr, sql.ErrNoRows) {
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
	event.ScheduleRowWritten = false // Failed/unknown observations never claim committed effects.
	event.EventID = uuid.New()       // failure/uncertainty is separate from staged success
	event.OccurredAt = time.Now()
	safe := scheduleUpdateSafeError(operationErr)
	if !released {
		scheduleUpdateAuditFault(ctx, event, "resource_release_unconfirmed")
		return fmt.Errorf("%w; schedule.update audit persistence unavailable", safe)
	}
	if err := updateaudit.RecordFailure(db, event); err != nil {
		scheduleUpdateAuditFault(ctx, event, "persistence_unavailable")
		return fmt.Errorf("%w; schedule.update audit persistence unavailable", safe)
	}
	return safe
}

// This fixed diagnostic is NOT a durable audit event and carries no actor,
// destination, client input or inherited authentication/log fields.
func scheduleUpdateLegacyDiagnostic(ctx context.Context) {
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "schedule.update", "AuditCoverage": "NOT_COVERED",
		"AuditReason": "legacy_inherited_transaction",
	})
	log.Logf(clean, "Schedule update legacy transaction coverage.")
}
