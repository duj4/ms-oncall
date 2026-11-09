package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

type serviceDeleteAudit struct {
	ctx      context.Context
	db       *sql.DB
	identity deleteaudit.Event
	started  bool
}

func newServiceDeleteAudit(ctx context.Context, db *sql.DB, input []assignment.RawTarget) *serviceDeleteAudit {
	hasService := false
	for _, target := range input {
		hasService = hasService || target.TargetType() == assignment.TargetTypeService
	}
	if !hasService {
		return nil
	}
	e := deleteaudit.Event{RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown"}
	if ctx != nil {
		if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
			e.RequestID = id
		}
		if ec, err := executioncontext.CheckHumanAuthority(ctx); err == nil {
			e.ActorKind, e.ActorID = "human", uuid.MustParse(ec.ActualActorID())
			e.HomeOrganizationID, _ = ec.HomeOrganizationID()
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
		} else if home, err := serviceManagementAuthority(ctx, serviceManagementDelete); err == nil && home == nil {
			// Only the existing strict trusted internal System path can do this.
			e.ActorKind, e.AuthoritySource, e.AuthorityRole = "internal_system", "trusted_internal_system", "internal_system"
		}
	}
	return &serviceDeleteAudit{ctx: ctx, db: db, identity: e}
}

type serviceDeleteAttempt struct {
	plan                                  *serviceDeleteAudit
	event                                 deleteaudit.Event
	conn                                  *sql.Conn
	tx                                    *sql.Tx
	targets                               []deleteaudit.Event
	commitAttempted, finalized, committed bool
	beginFailed, auditFailed              bool
}

func (p *serviceDeleteAudit) nextAttempt() *serviceDeleteAttempt {
	p.started = true
	e := p.identity
	e.EventID, e.AttemptID, e.OccurredAt = uuid.New(), uuid.New(), time.Now()
	return &serviceDeleteAttempt{plan: p, event: e}
}

func (a *serviceDeleteAttempt) begin(ctx context.Context) (*sql.Tx, error) {
	a.beginFailed = true
	var err error
	a.conn, err = a.plan.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	a.tx, err = a.conn.BeginTx(ctx, nil)
	if err == nil {
		a.beginFailed = false
	}
	return a.tx, err
}

// This read is confined to the Service group's existing position and authorized
// scope. It grants no scope, changes no parent lock order and reads no fields
// beyond immutable audit attribution. The Store still validates the full set.
func (a *serviceDeleteAttempt) capture(ctx context.Context, ids []string, scope *uuid.UUID) error {
	if _, err := validate.ParseManyUUID("ServiceID", ids, 50); err != nil {
		return err
	}
	query := `SELECT id, organization_id FROM services WHERE id=ANY($1)`
	args := []any{sqlutil.UUIDArray(ids)}
	if scope != nil {
		query += ` AND organization_id=$2`
		args = append(args, *scope)
	}
	query += ` ORDER BY id FOR UPDATE`
	rows, err := a.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var targets []deleteaudit.Event
	for rows.Next() {
		e := a.event
		if err := rows.Scan(&e.ServiceID, &e.TargetOrganizationID); err != nil {
			return err
		}
		e.EventID = uuid.New()
		targets = append(targets, e)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	a.targets = targets
	return nil
}

func (a *serviceDeleteAttempt) witness(ctx context.Context) error {
	for _, e := range a.targets {
		// The trusted System Store preserves missing/no-op semantics. Never
		// manufacture a deletion event for a row a trigger left in place.
		var exists bool
		if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM services WHERE id=$1)`, e.ServiceID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		e.Outcome, e.Reason, e.OccurredAt = "committed", "deleted", time.Now()
		if err := deleteaudit.Append(ctx, a.tx, e); err != nil {
			a.auditFailed = true
			return err
		}
	}
	return nil
}

func (a *serviceDeleteAttempt) commit(ctx context.Context) error {
	a.commitAttempted = true
	err, finalized := commitServiceUpdate(ctx, a.tx)
	a.finalized, a.committed = finalized, err == nil
	return err
}

func serviceDeleteSafeError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	if permission.IsPermissionError(err) || validation.IsValidationError(err) {
		return err
	}
	if db := sqlutil.MapError(err); db != nil {
		// Preserve the existing mixed-group field/limit mappings while passing
		// only structural metadata and bounded categories to the shared mapper.
		// In particular, its override mapping must never receive a raw SQL Hint.
		clean := &pgconn.PgError{Code: db.Code, TableName: db.TableName, ConstraintName: db.ConstraintName}
		if db.ConstraintName == "services_escalation_policy_id_fkey" {
			if strings.Contains(db.Detail, "is still referenced") {
				clean.Detail = "is still referenced"
			} else if strings.Contains(db.Detail, "is not present") {
				clean.Detail = "is not present"
			}
		}
		if strings.HasPrefix(db.Hint, "max=") {
			if max, err := strconv.Atoi(strings.TrimPrefix(db.Hint, "max=")); err == nil {
				clean.Hint = "max=" + strconv.Itoa(max)
			}
		}
		mapped := errutil.MapDBError(clean)
		if validation.IsValidationError(mapped) || errutil.IsLimitError(mapped) {
			return mapped
		}
	}
	return errors.New("service.delete transaction failed")
}

func (a *serviceDeleteAttempt) fault(code string) {
	ctx := context.Background()
	if a.plan.ctx != nil {
		ctx = log.FromContext(a.plan.ctx).BackgroundContext()
	}
	ctx = log.WithFields(ctx, log.Fields{"AuditOperation": "service.delete", "AuditFault": code, "AuditRequestID": a.event.RequestID.String(), "AuditAttemptID": a.event.AttemptID.String(), "AuditEventID": a.event.EventID.String()})
	if code == "committed_resource_release_unconfirmed" {
		log.Log(ctx, errors.New("service.delete committed; resource release unconfirmed"))
		return
	}
	log.Log(ctx, deleteaudit.ErrUnavailable)
}

// finish alone decides whether an error is safe for the existing five-attempt
// loop. Raw driver/SQL errors never reach that loop or its retry logger.
func (a *serviceDeleteAttempt) finish(operationErr error) error {
	rb, released := releaseServiceUpdate(a.conn, a.tx, a.finalized)
	if a.committed {
		if !released {
			a.fault("committed_resource_release_unconfirmed")
		}
		return nil
	}
	outcome, reason := "tx_failed", "write_failed"
	safe := serviceDeleteSafeError(operationErr)
	safeRetry := false
	switch {
	case a.commitAttempted:
		outcome, reason = serviceUpdateCommitOutcome(operationErr)
		// A returned, explicit PG rejection is evidence of non-commit. Every
		// transport/timeout/unknown observation is permanent for this request.
		safeRetry = outcome == "tx_failed" && a.finalized && released
	case a.tx != nil && rb != nil:
		outcome, reason = "rollback_unconfirmed", "rollback_unconfirmed"
	case permission.IsPermissionError(operationErr):
		outcome, reason = "denied", "authority_denied"
	case errors.Is(operationErr, sql.ErrNoRows):
		outcome, reason = "validation_failed", "target_unavailable"
	case validation.IsValidationError(safe), errutil.IsLimitError(safe):
		outcome, reason = "validation_failed", "invalid_fields"
	case a.auditFailed:
		reason = "audit_write_failed"
	case a.beginFailed:
		reason = "begin_failed"
		safeRetry = released // No business statement was issued.
	default:
		safeRetry = a.tx != nil && rb == nil && released
	}
	events := a.targets
	if len(events) == 0 {
		events = []deleteaudit.Event{a.event}
	}
	for i := range events {
		events[i].EventID = uuid.New()
		events[i].Outcome, events[i].Reason, events[i].OccurredAt = outcome, reason, time.Now()
	}
	a.event.EventID = events[0].EventID
	if !released {
		a.fault("resource_release_unconfirmed")
		return fmt.Errorf("%w; service.delete audit persistence unavailable", safe)
	}
	if err := deleteaudit.RecordFailures(a.plan.db, events); err != nil {
		a.fault("persistence_unavailable")
		return fmt.Errorf("%w; service.delete audit persistence unavailable", safe)
	}
	if safeRetry && retry.IsTemporaryError(operationErr) {
		return retry.TemporaryError(safe)
	}
	return safe
}
