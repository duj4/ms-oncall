package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service/deleteaudit"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

// deleteAllAudit is deliberately confined to DeleteAll requests that contain
// explicit Service/CM/NR inputs. Uncovered requests retain their old lifecycle.
// Service's capture, witness and event contract stay in its existing adapter.
type deleteAllAudit struct {
	ctx                   context.Context
	db                    *sql.DB
	service               *serviceDeleteAudit
	identity              audit.Event
	hasCM, hasNR, started bool
	explicitNR            map[uuid.UUID]bool
}

func newDeleteAllAudit(ctx context.Context, db *sql.DB, input []assignment.RawTarget) *deleteAllAudit {
	p := &deleteAllAudit{ctx: ctx, db: db, service: newServiceDeleteAudit(ctx, db, input), explicitNR: map[uuid.UUID]bool{}}
	for _, t := range input {
		switch t.TargetType() {
		case assignment.TargetTypeContactMethod:
			p.hasCM = true
		case assignment.TargetTypeNotificationRule:
			p.hasNR = true
			if id, err := uuid.Parse(t.TargetID()); err == nil {
				p.explicitNR[id] = true
			}
		}
	}
	if p.service == nil && !p.hasCM && !p.hasNR {
		return nil
	}
	e := audit.Event{RequestID: uuid.New(), ExecutionID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", TargetOrgResolution: "unknown"}
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
		} else if _, err := executioncontext.CheckCMNRMutationAuthority(ctx); err == nil && permission.System(ctx) {
			e.ActorKind, e.AuthoritySource, e.AuthorityRole = "internal_system", "trusted_internal_system", "internal_system"
		}
	}
	if p.service != nil {
		e.RequestID = p.service.identity.RequestID
	}
	p.identity = e
	return p
}

type deleteAllAttempt struct {
	plan                                                                                     *deleteAllAudit
	event                                                                                    audit.Event
	service                                                                                  *serviceDeleteAttempt
	conn                                                                                     *sql.Conn
	tx                                                                                       *sql.Tx
	targets, successes                                                                       []audit.Event
	commitAttempted, finalized, committed, beginFailed, auditFailed, groupsStarted, finished bool
}

func (p *deleteAllAudit) nextAttempt() *deleteAllAttempt {
	p.started = true
	e := p.identity
	e.EventID, e.AttemptID, e.OccurredAt = uuid.New(), uuid.New(), time.Now()
	a := &deleteAllAttempt{plan: p, event: e}
	if p.service != nil {
		a.service = p.service.nextAttempt()
		a.service.event.RequestID, a.service.event.AttemptID = e.RequestID, e.AttemptID
	}
	return a
}

func (p *deleteAllAudit) retryContext() context.Context {
	clean := context.Background()
	if p.ctx != nil {
		clean = log.FromContext(p.ctx).BackgroundContext()
	}
	return log.WithFields(clean, log.Fields{"AuditOperation": "deleteAll", "AuditRequestID": p.identity.RequestID.String(), "AuditExecutionID": p.identity.ExecutionID.String()})
}

func (a *deleteAllAttempt) begin(ctx context.Context) (*sql.Tx, error) {
	a.beginFailed = true
	var err error
	if a.plan.db == nil {
		return nil, audit.ErrUnavailable
	}
	a.conn, err = a.plan.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	a.tx, err = a.conn.BeginTx(ctx, nil)
	if err == nil {
		a.beginFailed = false
	}
	if a.service != nil {
		a.service.tx = a.tx
	}
	return a.tx, err
}

func (a *deleteAllAttempt) capture(ctx context.Context, ids []string, scope *uuid.UUID) error {
	return a.service.capture(ctx, ids, scope)
}
func (a *deleteAllAttempt) witness(ctx context.Context) error {
	err := a.service.witness(ctx)
	a.auditFailed = a.auditFailed || a.service.auditFailed
	return err
}

func (a *deleteAllAttempt) target(t audit.Target, typ string) audit.Event {
	e := a.event
	e.EventID = uuid.New()
	e.RootType, e.RootID, e.RootOwnerUserID = typ, t.ID, t.OwnerID
	e.Operation = typ + ".delete"
	e.ParentCMID = t.ParentCMID
	e.TargetOrganizationID, e.TargetOrgResolution = t.OrganizationID, t.OrgResolution
	return e
}

func (a *deleteAllAttempt) collect(result audit.DeleteResult, typ string) {
	for _, t := range result.Targets {
		e := a.target(t, typ)
		a.targets = append(a.targets, e)
		if !t.Deleted {
			continue
		}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism = "EXPLICIT", "explicit_sql"
		e.Effects = t.Effects
		a.successes = append(a.successes, e)
	}
	if typ != audit.ContactMethod {
		return
	}
	for _, t := range result.CascadeRules {
		if !t.Deleted {
			continue
		}
		var parent *audit.Event
		for i := range a.successes {
			if a.successes[i].RootType == audit.ContactMethod && a.successes[i].RootID == t.ParentCMID {
				parent = &a.successes[i]
				break
			}
		}
		if parent == nil {
			continue
		}
		if a.plan.explicitNR[t.ID] {
			// This NR was missing in its original group and appeared before the
			// parent's lock. It is still an explicit input, actually deleted by FK.
			e := a.target(t, audit.NotificationRule)
			e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
			e.Provenance, e.DeletionMechanism, e.CauseEventID = "EXPLICIT", "fk_cascade", parent.EventID
			a.targets = append(a.targets, e)
			a.successes = append(a.successes, e)
		} else {
			parent.Effects = append(parent.Effects, audit.Effect{EffectID: uuid.New(), ResourceType: audit.NotificationRule, ResourceUUID: audit.NullableID(t.ID), OwnerUserID: t.OwnerID, TargetOrganizationID: audit.NullableID(t.OrganizationID), OrgResolution: t.OrgResolution, Relation: "contact_method.notification_rule", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE"})
		}
	}
}

func (a *deleteAllAttempt) appendCMNR(ctx context.Context) error {
	for i := range a.successes {
		e := &a.successes[i]
		if e.RootType == audit.ContactMethod {
			for _, nr := range a.successes {
				if nr.RootType == audit.NotificationRule && nr.ParentCMID == e.RootID {
					e.RelatedExplicitEvents = append(e.RelatedExplicitEvents, audit.RelatedExplicitEvent{EventID: nr.EventID, Relation: "parent_cm"})
				}
			}
		}
		*e = e.Canonical()
		if err := audit.Append(ctx, a.tx, *e); err != nil {
			a.auditFailed = true
			return err
		}
	}
	return nil
}

func (a *deleteAllAttempt) commit(ctx context.Context) error {
	if a.commitAttempted || a.finished {
		return errors.New("deleteAll duplicate Commit refused")
	}
	if err := a.appendCMNR(ctx); err != nil {
		return err
	}
	a.commitAttempted = true
	err, finalized := commitServiceUpdate(ctx, a.tx)
	a.finalized, a.committed = finalized, err == nil
	return err
}

func (a *deleteAllAttempt) safeError(err error) error {
	safe := serviceDeleteSafeError(err)
	if a.plan.hasCM || a.plan.hasNR {
		if safe.Error() == "service.delete transaction failed" {
			return errors.New("deleteAll transaction failed")
		}
	}
	return safe
}

func (a *deleteAllAttempt) fault(code string) {
	clean := context.Background()
	if a.plan.ctx != nil {
		clean = log.FromContext(a.plan.ctx).BackgroundContext()
	}
	op := "deleteAll"
	if a.plan.service != nil && !a.plan.hasCM && !a.plan.hasNR {
		op = "service.delete"
	}
	clean = log.WithFields(clean, log.Fields{"AuditOperation": op, "AuditFault": code, "AuditRequestID": a.event.RequestID.String(), "AuditExecutionID": a.event.ExecutionID.String(), "AuditAttemptID": a.event.AttemptID.String()})
	if code == "committed_resource_release_unconfirmed" {
		log.Log(clean, errors.New(op+" committed; resource release unconfirmed"))
	} else if op == "service.delete" {
		log.Log(clean, deleteaudit.ErrUnavailable)
	} else {
		log.Log(clean, audit.ErrUnavailable)
	}
}

func (a *deleteAllAttempt) failureEvents(outcome, reason string) ([]deleteaudit.Event, []audit.Event) {
	var services []deleteaudit.Event
	if a.service != nil {
		services = append(services, a.service.targets...)
		if len(services) == 0 {
			services = append(services, a.service.event)
		}
		for i := range services {
			services[i].EventID = uuid.New()
			services[i].Outcome, services[i].Reason, services[i].OccurredAt = outcome, reason, time.Now()
		}
	}
	var events []audit.Event
	if !a.plan.hasCM && !a.plan.hasNR {
		return services, events
	}
	if !a.groupsStarted {
		e := a.event
		e.Operation = "cmnr.delete_attempt"
		events = append(events, e)
	} else {
		for _, typ := range []string{audit.ContactMethod, audit.NotificationRule} {
			if typ == audit.ContactMethod && !a.plan.hasCM || typ == audit.NotificationRule && !a.plan.hasNR {
				continue
			}
			found := false
			for _, e := range a.targets {
				if e.RootType == typ {
					events = append(events, e)
					found = true
				}
			}
			if !found {
				e := a.event
				e.Operation = typ + ".delete"
				events = append(events, e)
			}
		}
	}
	for i := range events {
		e := &events[i]
		e.EventID = uuid.New()
		e.RecordKind = "attempt_observation"
		e.Outcome, e.Reason, e.OccurredAt = outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.CauseEventID = "", "", uuid.Nil
		e.Effects = nil
		e.RelatedExplicitEvents = nil
	}
	return services, events
}

// recordDeleteAllFailureBatch owns a separate bounded connection/transaction.
// Both adapters commit together. Even confirmed persistence does not authorize
// retry until its own release barrier has completed.
func recordDeleteAllFailureBatch(db *sql.DB, services []deleteaudit.Event, events []audit.Event) (persisted, released bool) {
	if db == nil || len(services)+len(events) == 0 || len(services) > 50 || len(events) > 100 || len(services)+len(events) > 150 {
		return false, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// A faulty driver may ignore the context in Connect/Begin/Append as well
	// as Commit. One worker retains ownership until its native call completes;
	// the caller returns at the deadline without starting a replacement writer
	// or replaying business. A late append/Commit is never claimed absent.
	type result struct{ persisted, released bool }
	done := make(chan result, 1)
	var confirmed atomic.Bool
	go func() {
		persisted, released := writeDeleteAllFailureBatch(ctx, db, services, events, &confirmed)
		done <- result{persisted, released}
	}()
	select {
	case r := <-done:
		return r.persisted, r.released
	case <-ctx.Done():
		return confirmed.Load(), false
	}
}

// The worker owns every native operation and its single explicit cleanup.
// confirmed distinguishes durable observations from unconfirmed connection
// release even when the caller's bounded wait has already ended.
func writeDeleteAllFailureBatch(ctx context.Context, db *sql.DB, services []deleteaudit.Event, events []audit.Event, confirmed *atomic.Bool) (persisted, released bool) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, true
	}
	var tx *sql.Tx
	finalized := false
	defer func() { _, released = releaseServiceUpdate(conn, tx, finalized) }()
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		return false, false
	}
	for _, e := range services {
		if e.Outcome == "committed" || deleteaudit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	for _, e := range events {
		if e.RecordKind != "attempt_observation" || audit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	err, finalized = commitServiceUpdate(ctx, tx)
	if err == nil {
		confirmed.Store(true)
	}
	return err == nil, false
}

// finish is the single finalization and retry gate for the shared attempt.
func (a *deleteAllAttempt) finish(operationErr error) error {
	if a.finished {
		return errors.New("deleteAll duplicate finalization refused")
	}
	a.finished = true
	rb, released := releaseServiceUpdate(a.conn, a.tx, a.finalized)
	if a.committed {
		if !released {
			a.fault("committed_resource_release_unconfirmed")
		}
		return nil
	}
	outcome, reason := "tx_failed", "write_failed"
	safe := a.safeError(operationErr)
	safeRetry := false
	switch {
	case a.commitAttempted:
		outcome, reason = serviceUpdateCommitOutcome(operationErr)
		safeRetry = outcome == "tx_failed" && a.finalized && released
	case a.tx != nil && rb != nil:
		outcome, reason = "rollback_unconfirmed", "rollback_unconfirmed"
	case permission.IsPermissionError(operationErr):
		outcome, reason = "denied", "authority_denied"
	case errors.Is(operationErr, sql.ErrNoRows):
		outcome, reason = "validation_failed", "target_unavailable"
	case validation.IsValidationError(safe), errutil.IsLimitError(safe):
		outcome, reason = "validation_failed", "invalid_fields"
	case a.auditFailed || errors.Is(operationErr, audit.ErrCapacity):
		reason = "audit_write_failed"
	case a.beginFailed:
		reason = "begin_failed"
		safeRetry = released
	default:
		safeRetry = a.tx != nil && rb == nil && released
	}
	op := "deleteAll"
	if a.plan.service != nil && !a.plan.hasCM && !a.plan.hasNR {
		op = "service.delete"
	}
	if !released {
		a.fault("resource_release_unconfirmed")
		return fmt.Errorf("%w; %s audit persistence unavailable", safe, op)
	}
	services, events := a.failureEvents(outcome, reason)
	persisted, failureReleased := recordDeleteAllFailureBatch(a.plan.db, services, events)
	if !persisted || !failureReleased {
		fault := "persistence_unavailable"
		if persisted {
			fault = "failure_observation_persisted_release_unconfirmed"
		}
		a.fault(fault)
		return fmt.Errorf("%w; %s audit persistence unavailable", safe, op)
	}
	if safeRetry && !a.auditFailed && a.plan.ctx != nil && a.plan.ctx.Err() == nil && retry.IsTemporaryError(operationErr) {
		return retry.TemporaryError(safe)
	}
	return safe
}
