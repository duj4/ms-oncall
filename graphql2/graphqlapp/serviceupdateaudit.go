package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service/updateaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

func serviceUpdateAuditEvent(ctx context.Context, input graphql2.UpdateServiceInput) updateaudit.Event {
	e := updateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", OccurredAt: time.Now()}
	if input.Name != nil {
		e.RequestedFields |= updateaudit.Name
	}
	if input.Description != nil {
		e.RequestedFields |= updateaudit.Description
	}
	if input.MaintenanceExpiresAt != nil {
		e.RequestedFields |= updateaudit.MaintenanceExpiresAt
	}
	if input.EscalationPolicyID != nil {
		e.RequestedFields |= updateaudit.EscalationPolicyID
	}
	if ctx == nil {
		return e
	}
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		e.RequestID = id
	}
	home, err := rootStoreOrganizationID(ctx)
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

// This classification is about evidence returned by Commit, not a guess based
// on connection errors or on a later empty read. Transport and cancellation
// failures can have committed effects and must never replay the mutation.
func serviceUpdateCommitOutcome(err error) (string, string) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && len(pg.Code) == 5 && (pg.Code[:2] == "23" || pg.Code == "40001" || pg.Code == "40P01" || pg.Code == "P0001") {
		return "tx_failed", "commit_rejected"
	}
	return "commit_unknown", "commit_unconfirmed"
}

// Retain existing safe permission/field behavior and error mapping. Never let
// raw SQL diagnostics reach the outer resolver logger, tracing or HTTP output.
func serviceUpdateSafeError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		// Preserve only this operation's existing field mappings. The generic
		// mapper also handles other domains and can include their SQL hints.
		if pg.Code == "23505" && pg.ConstraintName == "services_name_key" {
			return validation.NewFieldError("Name", "already in use")
		}
		if pg.Code == "23503" && pg.ConstraintName == "services_escalation_policy_id_fkey" {
			return validation.NewFieldError("EscalationPolicyID", "does not exist")
		}
		return errors.New("service.update transaction failed")
	}
	if permission.IsPermissionError(err) || validation.IsValidationError(err) {
		return err
	}
	return errors.New("service.update transaction failed")
}

func finishServiceUpdateAudit(ctx context.Context, db *sql.DB, tx *sql.Tx, commitAttempted bool, event updateaudit.Event, operationErr error) error {
	if operationErr == nil {
		return nil
	}
	if commitAttempted {
		event.Outcome, event.Reason = serviceUpdateCommitOutcome(operationErr)
	} else {
		if event.Outcome == "validation_failed" && !validation.IsValidationError(serviceUpdateSafeError(operationErr)) && !errors.Is(operationErr, sql.ErrNoRows) {
			event.Outcome, event.Reason = "tx_failed", "write_failed"
		}
		if tx != nil {
			// ErrTxDone alone does not prove rollback; in particular cancellation
			// can race database/sql's automatic finalization.
			if err := tx.Rollback(); err != nil {
				event.Outcome, event.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
			}
		}
	}
	event.EventID = uuid.New() // failure/uncertainty is separate from staged success
	event.OccurredAt = time.Now()
	safe := serviceUpdateSafeError(operationErr)
	if err := updateaudit.RecordFailure(db, event); err != nil {
		// Do not inherit requester, Source, input, error or arbitrary log fields.
		clean := context.Background()
		if ctx != nil {
			clean = log.FromContext(ctx).BackgroundContext()
		}
		clean = log.WithFields(clean, log.Fields{
			"AuditOperation": "service.update", "AuditFault": "persistence_unavailable",
			"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
			"AuditRequestID": event.RequestID.String(),
		})
		log.Log(clean, updateaudit.ErrUnavailable)
		return fmt.Errorf("%w; service.update audit persistence unavailable", safe)
	}
	return safe
}
