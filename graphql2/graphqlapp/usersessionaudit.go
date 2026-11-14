package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	audit "github.com/target/goalert/auth/sessionaudit"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
)

func sessionAuditEvent(ctx context.Context, mode string) audit.Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "attempt_observation", Operation: "user_session.revoke", SelectionMode: mode, ActorKind: "unknown", InitiatorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", Outcome: "tx_failed", Reason: "begin_failed", OccurredAt: now, RecordedAt: now}
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		e.RequestID = id
	}
	if ec, err := executioncontext.CheckHumanAuthority(ctx); err == nil {
		e.ActorKind = "human"
		e.InitiatorKind = "human"
		e.ActorID = audit.ID(uuid.MustParse(ec.ActualActorID()))
		e.InitiatorUserID = e.ActorID
		home, _ := ec.HomeOrganizationID()
		e.HomeOrganizationID = audit.ID(home)
		e.AuthoritySource = "current_local_user_organization_at_admission"
		e.OrganizationRole = string(ec.Privileges().OrganizationRole())
		switch {
		case ec.Privileges().PlatformAdmin():
			e.AuthorityRole = "platform_admin"
		case ec.Privileges().OrganizationRole() == organization.OrganizationRoleAdmin:
			e.AuthorityRole = "org_admin"
		case ec.Privileges().OrganizationRole() == organization.OrganizationRoleMember:
			e.AuthorityRole = "org_member"
		default:
			e.AuthorityRole = "none"
		}
	} else if mode == "selected_sessions" {
		if state, err := humanOperationAdmission(ctx); err == nil && state == nonHumanAdmission && permission.System(ctx) && permission.Source(ctx) == nil && permission.UserID(ctx) == "" {
			e.ActorKind = "internal_system"
			e.InitiatorKind = "internal_system"
			e.AuthoritySource = "trusted_internal_system"
			e.AuthorityRole = "internal_system"
		}
	}
	return e
}
func sessionAuditSafeError(err error) error {
	if err == nil {
		return nil
	}
	if permission.IsUnauthorized(err) {
		return permission.Unauthorized()
	}
	if permission.IsPermissionError(err) {
		return permission.NewAccessDenied("Session revocation authority is required")
	}
	return errors.New("user_session.revoke transaction unconfirmed")
}
func sessionAuditFault(ctx context.Context, e audit.Event, code string) {
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithFields(clean, log.Fields{"AuditOperation": "user_session.revoke", "AuditFault": code, "AuditRequestID": e.RequestID.String(), "AuditExecutionID": e.ExecutionID.String(), "AuditAttemptID": e.AttemptID.String()})
	log.Logf(clean, "Session revocation finalization.")
}
func sessionObservation(e audit.Event, outcome, reason string) audit.Event {
	e.EventID = uuid.New()
	e.RecordKind = "attempt_observation"
	e.AffectedCount = 0
	e.Outcome = outcome
	e.Reason = reason
	e.OccurredAt = time.Now().UTC().Truncate(time.Microsecond)
	e.RecordedAt = e.OccurredAt
	switch outcome {
	case "tx_failed":
		switch reason {
		case "begin_failed", "receipt_invalid", "audit_write_failed", "commit_rejected", "transaction_ownership_unavailable":
		default:
			e.Reason = "mutation_failed"
		}
	case "denied":
		e.Reason = "authority_denied"
	case "validation_failed":
		e.Reason = "invalid_input"
	}
	return e
}

// The original business connection must have crossed its release barrier first.
// One bounded worker retains its own observation connection through finalization.
func recordSessionObservation(db *sql.DB, e audit.Event) (persisted, released bool) {
	if db == nil || e.Validate() != nil {
		return false, true
	}
	type result struct{ persisted, released bool }
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), serviceUpdateFinishTimeout)
	defer cancel()
	go func() {
		var conn *sql.Conn
		var tx *sql.Tx
		finalized := false
		ok := false
		defer func() { _, released := releaseServiceUpdate(conn, tx, finalized); done <- result{ok, released} }()
		var err error
		conn, err = db.Conn(ctx)
		if err != nil {
			return
		}
		tx, err = conn.BeginTx(ctx, nil)
		if err != nil {
			return
		}
		if audit.AppendObservation(ctx, tx, e) != nil {
			return
		}
		err, finalized = commitServiceUpdate(ctx, tx)
		ok = err == nil
	}()
	select {
	case r := <-done:
		return r.persisted, r.released
	case <-ctx.Done():
		return false, false
	}
}

// EndAll owns its business transaction. No retry is introduced; an unknown
// Commit must never replay an operation that could delete newly created Sessions.
func (a *Mutation) endOtherSessionsAudited(ctx context.Context) (ok bool, returnedErr error) {
	e := sessionAuditEvent(ctx, "other_sessions_of_current_user")
	var conn *sql.Conn
	var tx *sql.Tx
	commitAttempted, finalized := false, false
	outcome, reason := "tx_failed", "begin_failed"
	inherited := hasInheritedContextTx(ctx)
	defer func() {
		if recover() != nil {
			ok = false
			returnedErr = audit.ErrUnavailable
			reason = "mutation_failed"
		}
		rb, released := releaseServiceUpdate(conn, tx, finalized)
		if returnedErr == nil {
			if !released {
				sessionAuditFault(ctx, e, "committed_resource_release_unconfirmed")
			}
			return
		}
		if commitAttempted {
			outcome, reason = serviceUpdateCommitOutcome(returnedErr)
		} else if tx != nil && rb != nil {
			outcome, reason = "rollback_unconfirmed", "rollback_unconfirmed"
		}
		returnedErr = sessionAuditSafeError(returnedErr)
		if inherited || !released {
			sessionAuditFault(ctx, e, "resource_release_unconfirmed")
			return
		}
		if persisted, writerReleased := recordSessionObservation(a.DB, sessionObservation(e, outcome, reason)); !persisted || !writerReleased {
			sessionAuditFault(ctx, e, "observation_persistence_unconfirmed")
		}
	}()
	if inherited {
		reason = "transaction_ownership_unavailable"
		return false, audit.ErrInvalid
	}
	if err := defaultHumanOperation(ctx, "Mutation", "endAllAuthSessionsByCurrentUser", nil); err != nil {
		outcome, reason = "denied", "authority_denied"
		return false, err
	}
	requester := auth.RequesterFromContext(ctx)
	if e.ActorKind != "human" || e.Validate() != nil || requester == nil {
		outcome, reason = "denied", "context_missing"
		return false, permission.Unauthorized()
	}
	src := permission.Source(ctx)
	if src == nil || src.ID != requester.SessionID().String() || permission.UserID(ctx) != requester.UserID().String() {
		outcome, reason = "denied", "context_missing"
		return false, permission.Unauthorized()
	}
	if a.DB == nil {
		return false, audit.ErrUnavailable
	}
	var err error
	conn, err = a.DB.Conn(ctx)
	if err != nil {
		return false, err
	}
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	var isolation string
	if err = tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil || isolation != "read committed" {
		return false, audit.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`); err != nil {
		return false, err
	}
	reason = "mutation_failed"
	receipt, err := a.AuthHandler.EndOtherUserSessionsForAuditTx(ctx, tx, e)
	if err != nil {
		return false, err
	}
	reason = "audit_write_failed"
	if err = receipt.Append(ctx, tx, e); err != nil {
		return false, err
	}
	commitAttempted = true
	err, finalized = commitServiceUpdate(ctx, tx)
	if err != nil {
		return false, err
	}
	return true, nil
}
