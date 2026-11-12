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
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/executioncontext"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
	"github.com/target/goalert/organization"
	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/service/deleteaudit"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	useraudit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

// deleteAllAudit is deliberately confined to DeleteAll requests that contain
// explicit Service/CM/NR/IntegrationKey/EP/Schedule/Rotation/UserOverride inputs. Uncovered requests retain their old lifecycle.
// Service's capture, witness and event contract stay in its existing adapter.
type deleteAllAudit struct {
	ctx                                  context.Context
	db                                   *sql.DB
	service                              *serviceDeleteAudit
	identity                             audit.Event
	hasCM, hasNR, hasKey, hasEP, started bool
	explicitNR                           map[uuid.UUID]bool
	hasUser                              bool
	userIntents                          []useraudit.ExplicitIntent
	hasSchedule, hasRotation, hasUO      bool
}

func newDeleteAllAudit(ctx context.Context, db *sql.DB, input []assignment.RawTarget) *deleteAllAudit {
	p := &deleteAllAudit{ctx: ctx, db: db, service: newServiceDeleteAudit(ctx, db, input), explicitNR: map[uuid.UUID]bool{}}
	p.userIntents = userExplicitIntents(input)
	for _, t := range input {
		switch t.TargetType() {
		case assignment.TargetTypeUser:
			p.hasUser = true
		case assignment.TargetTypeUserOverride:
			p.hasUO = true
		case assignment.TargetTypeSchedule:
			p.hasSchedule = true
		case assignment.TargetTypeRotation:
			p.hasRotation = true
		case assignment.TargetTypeEscalationPolicy:
			p.hasEP = true
		case assignment.TargetTypeIntegrationKey:
			p.hasKey = true
		case assignment.TargetTypeContactMethod:
			p.hasCM = true
		case assignment.TargetTypeNotificationRule:
			p.hasNR = true
			if id, err := uuid.Parse(t.TargetID()); err == nil {
				p.explicitNR[id] = true
			}
		}
	}
	if p.service == nil && !p.hasCM && !p.hasNR && !p.hasKey && !p.hasEP && !p.hasSchedule && !p.hasRotation && !p.hasUO && !p.hasUser {
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
	userBase                                                                                 useraudit.Event
	userReceipts                                                                             []useraudit.Receipt
	userTargets                                                                              []useraudit.Event
	uoBase                                                                                   uoaudit.Event
	uoTargets, uoSuccesses                                                                   []uoaudit.Event
	event                                                                                    audit.Event
	service                                                                                  *serviceDeleteAttempt
	keyEvent                                                                                 keyaudit.Event
	epEvent                                                                                  epaudit.Event
	srBase                                                                                   map[string]sraudit.Event
	srTargets, srSuccesses                                                                   []sraudit.Event
	epTargets, epSuccesses                                                                   []epaudit.Event
	epChildren                                                                               []epaudit.Effect
	epBytes                                                                                  int
	epInUse                                                                                  bool
	keyTargets                                                                               []keyaudit.Event
	keyReceipts                                                                              []serviceKeyReceipt
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
	if p.hasUser {
		a.userBase = useraudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OccurredAt: e.OccurredAt, Operation: "user.delete", RootType: "user", ActorKind: e.ActorKind, ActorID: useraudit.ID(e.ActorID), HomeOrganizationID: useraudit.ID(e.HomeOrganizationID), AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, TargetOrgResolution: "unknown"}
	}
	if p.hasUO {
		a.uoBase = uoaudit.Event{SchemaVersion: 1, Operation: "user_override.delete", RootType: "user_override", EventID: uuid.New(), RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OccurredAt: e.OccurredAt, ActorKind: e.ActorKind, ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, TargetOrgResolution: "unknown"}
		if e.ActorKind == "internal_system" {
			scope, err := epManagementAuthority(p.ctx, epManagementDelete)
			if err != nil || scope != nil {
				a.uoBase.ActorKind, a.uoBase.AuthoritySource, a.uoBase.AuthorityRole = "unknown", "unknown", "unknown"
			}
		}
	}
	if p.hasKey {
		a.keyEvent = keyaudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OccurredAt: e.OccurredAt, ActorKind: e.ActorKind, ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, TargetOrgResolution: "unknown"}
		// System classification must satisfy this capability's stricter authority.
		if e.ActorKind == "internal_system" {
			auth, err := integrationKeyManagementAuthority(p.ctx)
			if err != nil || !auth.system {
				a.keyEvent.ActorKind, a.keyEvent.AuthoritySource, a.keyEvent.AuthorityRole = "unknown", "unknown", "unknown"
			}
		}
	}
	if p.hasEP {
		a.epEvent = epaudit.Event{SchemaVersion: 1, EffectsVersion: 1, EventID: uuid.New(), RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OccurredAt: e.OccurredAt, ActorKind: e.ActorKind, ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, TargetOrgResolution: "unknown"}
		if e.ActorKind == "internal_system" {
			scope, err := epManagementAuthority(p.ctx, epManagementDelete)
			if err != nil || scope != nil {
				a.epEvent.ActorKind, a.epEvent.AuthoritySource, a.epEvent.AuthorityRole = "unknown", "unknown", "unknown"
			}
		}
	}
	a.srBase = map[string]sraudit.Event{}
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		if typ == sraudit.Schedule && !p.hasSchedule || typ == sraudit.Rotation && !p.hasRotation {
			continue
		}
		ev := sraudit.Event{SchemaVersion: 1, EffectsVersion: 1, RootType: typ, Operation: typ + ".delete", EventID: uuid.New(), RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OccurredAt: e.OccurredAt, ActorKind: e.ActorKind, ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, TargetOrgResolution: "unknown"}
		if e.ActorKind == "internal_system" {
			scope, err := epManagementAuthority(p.ctx, epManagementDelete)
			if err != nil || scope != nil {
				ev.ActorKind, ev.AuthoritySource, ev.AuthorityRole = "unknown", "unknown", "unknown"
			}
		}
		a.srBase[typ] = ev
	}
	if p.service != nil {
		a.service = p.service.nextAttempt()
		a.service.event.RequestID, a.service.event.AttemptID, a.service.event.ExecutionID, a.service.event.EffectsVersion = e.RequestID, e.AttemptID, e.ExecutionID, 1
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
		if err == nil {
			var isolation string
			err = a.tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation)
			if err == nil && isolation != "read committed" {
				err = deleteaudit.ErrInvalid
			}
			if err != nil {
				err = a.service.captureError(err)
				a.auditFailed = a.auditFailed || a.service.auditFailed
			}
		}
	}
	if err == nil && (a.plan.hasSchedule || a.plan.hasRotation || a.plan.hasUO || a.plan.hasUser) {
		var isolation string
		err = a.tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation)
		if err == nil && isolation != "read committed" {
			err = sraudit.ErrInvalid
		}
		err = a.srCaptureError(err)
	}

	if err == nil {
		// The shared entry precedes Default target and every business row lock,
		// including requests containing only pre-existing covered families.
		var isolation string
		err = a.tx.QueryRowContext(ctx, `SHOW transaction_isolation`).Scan(&isolation)
		if err == nil && isolation != "read committed" {
			err = useraudit.ErrInvalid
		}
		if err == nil {
			_, err = a.tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`)
		}
		if err == nil && a.plan.hasUser {
			_, err = a.tx.ExecContext(ctx, `LOCK TABLE rotation_participants,rotation_state IN EXCLUSIVE MODE`)
			if err == nil {
				_, err = a.tx.ExecContext(ctx, `LOCK TABLE user_overrides IN EXCLUSIVE MODE`)
			}
		}
		err = a.userCaptureError(err)
	}
	return a.tx, err
}

func (a *deleteAllAttempt) capture(ctx context.Context, ids []string, scope *uuid.UUID) error {
	err := a.service.capture(ctx, ids, scope)
	a.auditFailed = a.auditFailed || a.service.auditFailed
	return err
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
	if a.service != nil {
		if err := a.service.verifyBudget(ctx); err != nil {
			a.auditFailed = a.auditFailed || a.service.auditFailed
			return err
		}
	}
	if err := a.prepareUsers(); err != nil {
		a.auditFailed = true
		return err
	}
	if err := a.appendUsers(ctx); err != nil {
		a.auditFailed = true
		return err
	}
	if err := a.appendKeys(ctx); err != nil {
		a.auditFailed = true
		return err
	}
	if err := a.appendCMNR(ctx); err != nil {
		return err
	}
	if err := a.appendEP(ctx); err != nil {
		a.auditFailed = true
		return err
	}
	if err := a.appendSR(ctx); err != nil {
		a.auditFailed = true
		return err
	}
	if err := a.appendUO(ctx); err != nil {
		a.auditFailed = true
		return err
	}
	a.commitAttempted = true
	err, finalized := commitServiceUpdate(ctx, a.tx)
	a.finalized, a.committed = finalized, err == nil
	return err
}

func (a *deleteAllAttempt) safeError(err error) error {
	safe := serviceDeleteSafeError(err)
	if a.plan.hasCM || a.plan.hasNR || a.plan.hasKey || a.plan.hasEP || a.plan.hasSchedule || a.plan.hasRotation || a.plan.hasUO || a.plan.hasUser {
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
	if a.plan.service != nil && !a.plan.hasCM && !a.plan.hasNR && !a.plan.hasKey && !a.plan.hasEP && !a.plan.hasSchedule && !a.plan.hasRotation && !a.plan.hasUO && !a.plan.hasUser {
		op = "service.delete"
	}
	clean = log.WithFields(clean, log.Fields{"AuditOperation": op, "AuditFault": code, "AuditRequestID": a.event.RequestID.String(), "AuditExecutionID": a.event.ExecutionID.String(), "AuditAttemptID": a.event.AttemptID.String()})
	if code == "committed_resource_release_unconfirmed" {
		log.Log(clean, errors.New(op+" committed; resource release unconfirmed"))
	} else if op == "service.delete" {
		log.Log(clean, deleteaudit.ErrUnavailable)
	} else if a.plan.hasUser {
		log.Log(clean, useraudit.ErrUnavailable)
	} else if a.plan.hasUO {
		log.Log(clean, uoaudit.ErrUnavailable)
	} else if a.plan.hasSchedule || a.plan.hasRotation {
		log.Log(clean, sraudit.ErrUnavailable)
	} else if a.plan.hasEP {
		log.Log(clean, epaudit.ErrUnavailable)
	} else if a.plan.hasKey && !a.plan.hasCM && !a.plan.hasNR {
		log.Log(clean, keyaudit.ErrUnavailable)
	} else {
		log.Log(clean, audit.ErrUnavailable)
	}
}

func (a *deleteAllAttempt) failureEvents(outcome, reason string) ([]deleteaudit.Event, []audit.Event, []keyaudit.Event, []epaudit.Event) {
	keys := a.keyFailureEvents(outcome, reason)
	eps := a.epFailureEvents(outcome, reason)
	var services []deleteaudit.Event
	if a.service != nil {
		services = append(services, a.service.targets...)
		if len(services) == 0 {
			services = append(services, a.service.event)
		}
		for i := range services {
			services[i].EventID = uuid.New()
			services[i].Outcome, services[i].Reason, services[i].OccurredAt = outcome, reason, time.Now()
			services[i].Effects = nil // Non-assertive observation, even after an unknown Commit.
		}
	}
	var events []audit.Event
	if !a.plan.hasCM && !a.plan.hasNR {
		return services, events, keys, eps
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
		e.SchemaVersion, e.CauseRootType, e.CauseRootID, e.UserCauseWitness = 1, "", uuid.Nil, nil
		e.Effects = nil
		e.RelatedExplicitEvents = nil
	}
	return services, events, keys, eps
}

// recordDeleteAllFailureBatch owns a separate bounded connection/transaction.
// All typed adapters commit together. Even confirmed persistence does not authorize
// retry until its own release barrier has completed.
func recordDeleteAllFailureBatch(db *sql.DB, services []deleteaudit.Event, events []audit.Event, keys []keyaudit.Event, eps []epaudit.Event, srBatches ...[]sraudit.Event) (persisted, released bool) {
	return recordDeleteAllFailureBatchWithUO(db, services, events, keys, eps, nil, srBatches...)
}

func recordDeleteAllFailureBatchWithUO(db *sql.DB, services []deleteaudit.Event, events []audit.Event, keys []keyaudit.Event, eps []epaudit.Event, uo []uoaudit.Event, srBatches ...[]sraudit.Event) (persisted, released bool) {
	return recordDeleteAllFailureBatchWithUser(db, services, events, keys, eps, uo, nil, srBatches...)
}

func recordDeleteAllFailureBatchWithUser(db *sql.DB, services []deleteaudit.Event, events []audit.Event, keys []keyaudit.Event, eps []epaudit.Event, uo []uoaudit.Event, users []useraudit.Event, srBatches ...[]sraudit.Event) (persisted, released bool) {
	sr, ok := deleteAllSRFailureBatch(srBatches)
	schedules, rotations := 0, 0
	for _, e := range sr {
		switch e.RootType {
		case sraudit.Schedule:
			schedules++
		case sraudit.Rotation:
			rotations++
		default:
			ok = false
		}
	}
	cm, nr := 0, 0
	for _, e := range events {
		if e.RootType == audit.ContactMethod {
			cm++
		}
		if e.RootType == audit.NotificationRule {
			nr++
		}
	}
	if db == nil || !ok || cm > 50 || nr > 50 || uoaudit.ValidateBatch(uo) != nil || !deleteAllFailureCapacityWithUser(len(services), len(events), len(keys), len(eps), schedules, rotations, len(uo), len(users)) {
		return false, true
	}
	for _, e := range services {
		if e.Outcome == "committed" || e.Canonical().Validate() != nil {
			return false, true
		}
	}
	for _, e := range events {
		if e.RecordKind != "attempt_observation" || e.Canonical().Validate() != nil {
			return false, true
		}
	}
	for _, e := range keys {
		if e.RecordKind != "attempt_observation" || e.Validate() != nil {
			return false, true
		}
	}
	for _, e := range eps {
		if e.RecordKind != "attempt_observation" || e.Validate() != nil {
			return false, true
		}
	}
	for _, e := range sr {
		if e.RecordKind != "attempt_observation" || e.Validate() != nil {
			return false, true
		}
	}
	for _, e := range users {
		if e.RecordKind != "attempt_observation" || e.Validate() != nil {
			return false, true
		}
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
		var persisted, released bool
		if len(users) == 0 {
			persisted, released = writeDeleteAllFailureBatch(ctx, db, services, events, keys, eps, uo, &confirmed, sr)
		} else {
			persisted, released = writeDeleteAllFailureBatchWithUser(ctx, db, services, events, keys, eps, uo, users, &confirmed, sr)
		}
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
func writeDeleteAllFailureBatch(ctx context.Context, db *sql.DB, services []deleteaudit.Event, events []audit.Event, keys []keyaudit.Event, eps []epaudit.Event, uo []uoaudit.Event, confirmed *atomic.Bool, srBatches ...[]sraudit.Event) (persisted, released bool) {
	return writeDeleteAllFailureBatchWithUser(ctx, db, services, events, keys, eps, uo, nil, confirmed, srBatches...)
}

func writeDeleteAllFailureBatchWithUser(ctx context.Context, db *sql.DB, services []deleteaudit.Event, events []audit.Event, keys []keyaudit.Event, eps []epaudit.Event, uo []uoaudit.Event, users []useraudit.Event, confirmed *atomic.Bool, srBatches ...[]sraudit.Event) (persisted, released bool) {
	sr, ok := deleteAllSRFailureBatch(srBatches)
	if !ok {
		return false, true
	}
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
	for _, e := range keys {
		if e.RecordKind != "attempt_observation" || keyaudit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	for _, e := range eps {
		if e.RecordKind != "attempt_observation" || epaudit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	for _, e := range sr {
		if e.RecordKind != "attempt_observation" || sraudit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	for _, e := range uo {
		if e.RecordKind != "attempt_observation" || uoaudit.Append(ctx, tx, e) != nil {
			return false, false
		}
	}
	for _, e := range users {
		if e.RecordKind != "attempt_observation" || useraudit.Append(ctx, tx, e) != nil {
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
	if a.service != nil {
		a.auditFailed = a.auditFailed || a.service.auditFailed
	}
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
	if a.plan.service != nil && !a.plan.hasCM && !a.plan.hasNR && !a.plan.hasKey && !a.plan.hasEP && !a.plan.hasSchedule && !a.plan.hasRotation && !a.plan.hasUO && !a.plan.hasUser {
		op = "service.delete"
	}
	if !released {
		a.fault("resource_release_unconfirmed")
		return fmt.Errorf("%w; %s audit persistence unavailable", safe, op)
	}
	services, events, keys, eps := a.failureEvents(outcome, reason)
	persisted, failureReleased := recordDeleteAllFailureBatchWithUser(a.plan.db, services, events, keys, eps, a.uoFailureEvents(outcome, reason), a.userFailureEvents(outcome, reason), a.srFailureEvents(outcome, reason))
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

// Validate each typed component and the aggregate independently before opening
// the failure transaction. No truncation or partial batch is allowed.
func deleteAllFailureCapacity(services, cmnr, keys, eps int, sr ...int) bool {
	schedules, rotations, overrides := 0, 0, 0
	if len(sr) != 0 {
		if len(sr) != 2 && len(sr) != 3 {
			return false
		}
		schedules, rotations = sr[0], sr[1]
		if len(sr) == 3 {
			overrides = sr[2]
		}
	}
	return deleteAllFailureCapacityWithUser(services, cmnr, keys, eps, schedules, rotations, overrides, 0)
}

// A single optional typed SR batch keeps existing adapter callers compatible.
func deleteAllSRFailureBatch(batches [][]sraudit.Event) ([]sraudit.Event, bool) {
	if len(batches) > 1 {
		return nil, false
	}
	if len(batches) == 0 {
		return nil, true
	}
	return batches[0], true
}

// Each family is independently bounded. User100 extends the aggregate to 500;
// it never changes a legacy family budget or the writer's two-second deadline.
func deleteAllFailureCapacityWithUser(services, cmnr, keys, eps, schedules, rotations, overrides, users int) bool {
	sizes := []int{services, cmnr, keys, eps, schedules, rotations, overrides, users}
	caps := []int{50, 100, 50, 50, 50, 50, 50, 100}
	total := 0
	for i, n := range sizes {
		if n < 0 || n > caps[i] {
			return false
		}
		total += n
	}
	return total > 0 && total <= 500
}
