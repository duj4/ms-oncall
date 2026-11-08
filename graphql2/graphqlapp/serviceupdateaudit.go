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
	"github.com/target/goalert/service/updateaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

// Project only this resolver's diagnostic context. Field.Name is the schema
// operation; Field.Alias is client text and must not select this policy. The
// real resolver/authentication context is never replaced by this log context.
func serviceUpdateDiagnosticContext(ctx context.Context) context.Context {
	field := graphql.GetFieldContext(ctx)
	if field == nil || field.Object != "Mutation" || field.Field.Name != "updateService" {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "MutationName", "updateService")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

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

const serviceUpdateFinishTimeout = 2 * time.Second

// Commit retains database/sql's original request cancellation semantics. A
// driver that ignores cancellation must not hold this resolver indefinitely.
// A timeout is an unknown observation, never permission to replay the write.
func commitServiceUpdate(ctx context.Context, tx *sql.Tx) (err error, finalized bool) {
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	timer := time.NewTimer(serviceUpdateFinishTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		// database/sql can return these three errors before driver finalization.
		// All other Commit returns follow tx.close (including ErrBadConn's
		// synchronous connection discard). This is completion evidence, not
		// merely evidence that a Commit call was scheduled or attempted.
		return err, !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, sql.ErrTxDone)
	case <-ctx.Done():
		return ctx.Err(), false
	case <-timer.C:
		return context.DeadlineExceeded, false
	}
}

// A successful Conn.Close is the release barrier: it waits for the transaction
// to release its use of the owned connection before returning it to the pool.
// Neither Commit being attempted nor ErrTxDone provides this guarantee. In
// particular, automatic rollback may already own finalization and still be in
// the driver. ErrConnDone can race an automatic bad-connection close, so it is
// not accepted as a release barrier without separate evidence that a native
// Commit/Rollback call completed its synchronous finalization.
//
// Only this goroutine owns explicit cleanup. If a driver stalls forever, it may
// retain the connection and cleanup goroutine; the caller reports that gap in
// bounded time and does not start an independent append ahead of the barrier.
func releaseServiceUpdate(conn *sql.Conn, tx *sql.Tx, commitFinalized bool) (rollbackErr error, released bool) {
	if conn == nil {
		return nil, true
	}
	type terminal struct{ rollback, close error }
	done := make(chan terminal, 1)
	go func() {
		var rb error
		if tx != nil {
			rb = tx.Rollback()
		}
		done <- terminal{rb, conn.Close()}
	}()
	timer := time.NewTimer(serviceUpdateFinishTimeout)
	defer timer.Stop()
	select {
	case r := <-done:
		// Rollback's only early return is ErrTxDone. Any other return follows
		// synchronous tx.close, even when the driver reports rollback failure.
		// Resource release does not upgrade that failure to confirmed rollback.
		finalized := commitFinalized || tx == nil || !errors.Is(r.rollback, sql.ErrTxDone)
		return r.rollback, r.close == nil || errors.Is(r.close, sql.ErrConnDone) && finalized
	case <-timer.C:
		return context.DeadlineExceeded, false
	}
}

func serviceUpdateAuditFault(ctx context.Context, event updateaudit.Event, fault string) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "service.update", "AuditFault": fault,
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, updateaudit.ErrUnavailable)
}

// A confirmed Commit already persisted both business and audit rows. Report
// cleanup uncertainty separately without claiming an audit-persistence gap.
func serviceUpdateCommittedCleanupFault(ctx context.Context, event updateaudit.Event) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{
		"AuditOperation": "service.update", "AuditFault": "resource_release_unconfirmed",
		"AuditOutcome": "committed",
		"AuditEventID": event.EventID.String(), "AuditAttemptID": event.AttemptID.String(),
		"AuditRequestID": event.RequestID.String(),
	})
	log.Log(clean, errors.New("service.update committed; resource release unconfirmed"))
}

func finishServiceUpdateAudit(ctx context.Context, db *sql.DB, conn *sql.Conn, tx *sql.Tx, commitAttempted, commitFinalized bool, event updateaudit.Event, operationErr error) error {
	rollbackErr, released := releaseServiceUpdate(conn, tx, commitFinalized)
	if operationErr == nil {
		// UpdateService returns nil only after observing Commit return nil.
		// Cleanup must not replace that confirmed, atomic success with failure.
		if !released {
			serviceUpdateCommittedCleanupFault(ctx, event)
		}
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
			if rollbackErr != nil {
				event.Outcome, event.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
			}
		}
	}
	event.EventID = uuid.New() // failure/uncertainty is separate from staged success
	event.OccurredAt = time.Now()
	safe := serviceUpdateSafeError(operationErr)
	if !released {
		serviceUpdateAuditFault(ctx, event, "resource_release_unconfirmed")
		return fmt.Errorf("%w; service.update audit persistence unavailable", safe)
	}
	if err := updateaudit.RecordFailure(db, event); err != nil {
		serviceUpdateAuditFault(ctx, event, "persistence_unavailable")
		return fmt.Errorf("%w; service.update audit persistence unavailable", safe)
	}
	return safe
}
