package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
	audit "github.com/target/goalert/user/authsubjectdeleteaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

type authSubjectDeleteLogKey struct{}

// WithAuthSubjectDeleteLogState connects the parsed field to the enclosing
// request logger without carrying input, authority or credentials.
func WithAuthSubjectDeleteLogState(ctx context.Context) (context.Context, *atomic.Bool) {
	state := new(atomic.Bool)
	return context.WithValue(ctx, authSubjectDeleteLogKey{}, state), state
}

func authSubjectDeleteField(ctx context.Context) bool {
	f := graphql.GetFieldContext(ctx)
	return f != nil && f.Object == "Mutation" && f.Field.Name == "deleteAuthSubject"
}

func authSubjectDeleteOperation(ctx context.Context) bool {
	if !graphql.HasOperationContext(ctx) {
		return false
	}
	op := graphql.GetOperationContext(ctx)
	if op.Operation == nil {
		return true // unexecutable operation: diagnostics fail closed
	}
	for _, field := range graphql.CollectFields(op, op.Operation.SelectionSet, []string{"Mutation"}) {
		if field.Name == "deleteAuthSubject" {
			return true
		}
	}
	return false
}

func authSubjectDeleteDiagnosticContext(ctx context.Context) context.Context {
	selected := authSubjectDeleteField(ctx) || authSubjectDeleteOperation(ctx)
	if state, ok := ctx.Value(authSubjectDeleteLogKey{}).(*atomic.Bool); ok && state.Load() {
		selected = true
	}
	if !selected {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	name := "graphql"
	if f := graphql.GetFieldContext(ctx); f != nil {
		name = f.Field.Name
	}
	clean = log.WithField(clean, "MutationName", name)
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

func authSubjectDeleteEvent(ctx context.Context) audit.Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), Operation: "auth_subject.delete", RootType: "auth_subject", ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", TargetOrgResolution: "unknown", OccurredAt: now, RecordedAt: now}
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		e.RequestID = id
	}
	ec, err := executioncontext.CheckHumanAuthority(ctx)
	if err == nil {
		home, _ := ec.HomeOrganizationID()
		e.ActorKind = "human"
		e.ActorID = audit.ID(auth.RequesterFromContext(ctx).UserID())
		e.HomeOrganizationID = audit.ID(home)
		e.AuthoritySource = "current_local_user_organization_at_admission"
		e.OrganizationRole = string(ec.Privileges().OrganizationRole())
		switch {
		case ec.Privileges().PlatformAdmin():
			e.AuthorityRole = "platform_admin"
		case ec.Privileges().OrganizationRole() == organization.OrganizationRoleAdmin:
			e.AuthorityRole = "org_admin"
		case ec.Privileges().OrganizationRole() == organization.OrganizationRoleNone:
			e.AuthorityRole = "none"
		default:
			e.AuthorityRole = "org_member"
		}
	} else if state, err := humanOperationAdmission(ctx); err == nil && state == nonHumanAdmission && permission.System(ctx) {
		e.ActorKind = "internal_system"
		e.AuthorityRole = "internal_system"
		e.AuthoritySource = "trusted_internal_system"
	}
	return e
}

// Reconstruct safe categories; never pass a wrapped SQL message, arbitrary
// permission reason, field name or validation input to the shared presenter.
func authSubjectDeleteSafeError(err error) error {
	if errors.Is(err, errAuthSubjectDeleteOwnership) {
		return errAuthSubjectDeleteOwnership
	}
	if permission.IsUnauthorized(err) {
		return permission.Unauthorized()
	}
	if permission.IsPermissionError(err) {
		return permission.NewAccessDenied("AuthSubject management authority is required")
	}
	var multiple validation.MultiFieldError
	if errors.As(err, &multiple) {
		var fields []validation.FieldError
		for _, field := range multiple.FieldErrors() {
			var safe validation.FieldError
			if !errors.As(authSubjectDeleteSafeError(field), &safe) {
				return errors.New("auth_subject.delete transaction failed")
			}
			fields = append(fields, safe)
		}
		return validation.NewMultiFieldError(fields)
	}
	var field validation.FieldError
	if errors.As(err, &field) {
		switch field.Field() {
		case "UserID":
			return validation.NewFieldError("UserID", "must be a valid UUID")
		case "ProviderID", "SubjectID":
			for _, reason := range []string{"must not contain non-ASCII characters", "must not be empty", "cannot exceed 255 characters"} {
				if field.Reason() == reason {
					return validation.NewFieldError(field.Field(), reason)
				}
			}
		}
	}
	return errors.New("auth_subject.delete transaction failed")
}

func authSubjectDeleteFault(ctx context.Context, e audit.Event, fault, outcome string) {
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithFields(clean, log.Fields{"AuditOperation": "auth_subject.delete", "AuditFault": fault, "AuditOutcome": outcome, "AuditEventID": e.EventID.String(), "AuditRequestID": e.RequestID.String(), "AuditExecutionID": e.ExecutionID.String(), "AuditAttemptID": e.AttemptID.String()})
	log.Logf(clean, "AuthSubject audit finalization.")
}

// The single writer retains ownership after a bounded caller timeout. No
// second writer is started; release is independently observed after Commit.
func recordAuthSubjectFailure(db *sql.DB, e audit.Event) (persisted, released bool) {
	if db == nil {
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
		if audit.Append(ctx, tx, e) != nil {
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

// deleteAuthSubjectAudited is the only business Commit owner. The Store and
// receipt appender stage work exclusively on this transaction.
func (a *Mutation) deleteAuthSubjectAudited(ctx context.Context, input user.AuthSubject) (ok bool, returnedErr error) {
	isDefault, err := isDefaultHuman(ctx)
	if err != nil {
		return false, authSubjectDeleteSafeError(err)
	}
	e := authSubjectDeleteEvent(ctx)
	inherited := hasInheritedContextTx(ctx)
	var conn *sql.Conn
	var tx *sql.Tx
	commitAttempted, commitFinalized := false, false
	outcome, reason := "tx_failed", "begin_failed"
	defer func() {
		if recover() != nil {
			ok = false
			returnedErr = errors.New("auth_subject.delete transaction failed")
			outcome, reason = "tx_failed", "panic"
		}
		rb, released := releaseServiceUpdate(conn, tx, commitFinalized)
		if returnedErr == nil {
			if !released {
				authSubjectDeleteFault(ctx, e, "resource_release_unconfirmed", "committed")
			}
			return
		}
		if commitAttempted {
			outcome, reason = serviceUpdateCommitOutcome(returnedErr)
			if outcome == "commit_unknown" {
				authSubjectDeleteFault(ctx, e, "commit_unconfirmed", outcome)
			}
		} else if tx != nil && rb != nil {
			outcome, reason = "rollback_unconfirmed", "rollback_unconfirmed"
		}
		returnedErr = authSubjectDeleteSafeError(returnedErr)
		if inherited {
			authSubjectDeleteFault(ctx, e, "failure_audit_persistence_unavailable", outcome)
			return
		}
		if !released {
			authSubjectDeleteFault(ctx, e, "failure_audit_persistence_unavailable", outcome)
			return
		}
		e.EventID = uuid.New()
		e.RecordKind = "attempt_observation"
		e.Outcome = outcome
		e.Reason = reason
		e.OccurredAt = time.Now().UTC().Truncate(time.Microsecond)
		e.RecordedAt = e.OccurredAt
		persisted, writerReleased := recordAuthSubjectFailure(a.DB, e)
		if !persisted || !writerReleased {
			authSubjectDeleteFault(ctx, e, "failure_audit_persistence_unavailable", outcome)
		}
	}()
	if inherited {
		reason = "transaction_ownership_unavailable"
		return false, errAuthSubjectDeleteOwnership
	}
	if !isDefault {
		if err = permission.LimitCheckAny(ctx, permission.System, permission.Admin); err != nil {
			outcome, reason = "denied", "authority_denied"
			return false, err
		}
		if _, err = input.Normalize(); err != nil {
			outcome, reason = "validation_failed", "invalid_input"
			return false, err
		}
	}
	if a.DB == nil {
		return false, audit.ErrUnavailable
	}
	conn, err = a.DB.Conn(ctx)
	if err != nil {
		return false, err
	}
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	var isolation string
	if err = tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation); err != nil {
		return false, err
	}
	if isolation != "read committed" {
		return false, errors.New("auth_subject.delete transaction isolation unavailable")
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`); err != nil {
		return false, err
	}
	if isDefault {
		outcome, reason = "denied", "guard_denied"
		if err = authorizeDefaultUserTarget(ctx, tx, input.UserID); err != nil {
			if !permission.IsPermissionError(err) {
				outcome, reason = "tx_failed", "capture_failed"
			}
			if validation.IsValidationError(err) {
				outcome, reason = "validation_failed", "invalid_input"
			}
			return false, err
		}
	}
	outcome, reason = "tx_failed", "delete_failed"
	result, err := a.UserStore.DeleteAuthSubjectTx(ctx, tx, &input, e)
	if err != nil {
		if errors.Is(err, audit.ErrInvalid) {
			reason = "receipt_invalid"
		}
		if errors.Is(err, audit.ErrCapture) {
			reason = "capture_failed"
		}
		if errors.Is(err, audit.ErrPostcheck) {
			reason = "postcheck_failed"
		}
		if permission.IsPermissionError(err) {
			outcome, reason = "denied", "authority_denied"
		} else if validation.IsValidationError(err) {
			outcome, reason = "validation_failed", "invalid_input"
		}
		return false, err
	}
	if result.DeletedCount == 1 {
		reason = "audit_write_failed"
		if err = audit.AppendReceipt(ctx, tx, result.Receipt, e); err != nil {
			return false, err
		}
	} else if result.DeletedCount != 0 || result.Receipt != nil {
		reason = "receipt_invalid"
		return false, audit.ErrInvalid
	}
	commitAttempted = true
	err, commitFinalized = commitServiceUpdate(ctx, tx)
	if err != nil {
		return false, err
	}
	return true, nil
}

var errAuthSubjectDeleteOwnership = errors.New("auth_subject.delete transaction ownership unavailable")
