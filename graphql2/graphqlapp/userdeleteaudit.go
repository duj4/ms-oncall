package graphqlapp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	cmnr "github.com/target/goalert/user/cmnrdeleteaudit"
	audit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
)

func (a *deleteAllAttempt) userCaptureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}

func userExplicitIntents(input []assignment.RawTarget) []audit.ExplicitIntent {
	// Invalid raw families are still checked by their original late Stores.
	// They cannot create any success, including a User-caused derived witness.
	counts := map[assignment.TargetType]int{}
	for _, t := range input {
		counts[t.TargetType()]++
	}
	positions := map[assignment.TargetType]int{}
	seen := map[string]bool{}
	var intents []audit.ExplicitIntent
	for _, t := range input {
		typ := ""
		switch t.TargetType() {
		case assignment.TargetTypeContactMethod:
			typ = cmnr.ContactMethod
		case assignment.TargetTypeNotificationRule:
			typ = cmnr.NotificationRule
		default:
			continue
		}
		ordinal := positions[t.TargetType()]
		positions[t.TargetType()]++
		id, err := uuid.Parse(t.TargetID())
		key := typ + id.String()
		if counts[t.TargetType()] > 50 || err != nil || id == uuid.Nil || seen[key] {
			continue
		}
		seen[key] = true
		intents = append(intents, audit.ExplicitIntent{ResourceType: typ, ID: id, Ordinal: ordinal})
	}
	return intents
}

func (a *deleteAllAttempt) prepareUsers() error {
	if len(a.userTargets) != len(a.userReceipts) {
		return audit.ErrInvalid
	}
	for i, r := range a.userReceipts {
		t := a.userTargets[i]
		e := r.Event
		if t.RootID == nil || e.RootID == nil || *t.RootID != *e.RootID || t.RootOrdinal == nil || e.RootOrdinal == nil || *t.RootOrdinal != *e.RootOrdinal || t.TargetOrgResolution != e.TargetOrgResolution || !equalNullableIDs(t.TargetOrganizationID, e.TargetOrganizationID) {
			return audit.ErrInvalid
		}
	}

	seen := map[string]bool{}
	for _, e := range a.successes {
		seen[e.RootType+e.RootID.String()] = true
	}
	for _, r := range a.userReceipts {
		e := r.Event
		if r.Validate() != nil || e.RequestID != a.event.RequestID || e.ExecutionID != a.event.ExecutionID || e.AttemptID != a.event.AttemptID || e.ActorKind != a.event.ActorKind || e.AuthoritySource != a.event.AuthoritySource || e.AuthorityRole != a.event.AuthorityRole || e.OrganizationRole != a.event.OrganizationRole || !sameUserID(e.ActorID, a.event.ActorID) || !sameUserID(e.HomeOrganizationID, a.event.HomeOrganizationID) {
			return audit.ErrInvalid
		}
		for _, w := range r.Witnesses {
			key := w.ResourceType + w.ResourceID.String()
			if seen[key] {
				return audit.ErrInvalid
			}
			seen[key] = true
			ev := a.event
			ev.SchemaVersion = 2
			ev.EventID = w.EventID
			ev.RootType = w.ResourceType
			ev.Operation = w.ResourceType + ".delete"
			ev.RootID = w.ResourceID
			ev.RootOwnerUserID = w.OwnerID
			if w.ParentCMID != nil {
				ev.ParentCMID = *w.ParentCMID
			}
			if w.TargetOrganizationID != nil {
				ev.TargetOrganizationID = *w.TargetOrganizationID
			}
			ev.TargetOrgResolution = w.TargetOrgResolution
			ev.RecordKind, ev.Outcome, ev.Reason = "success_witness", "committed", "deleted"
			ev.Provenance, ev.DeletionMechanism, ev.CauseEventID = "EXPLICIT", "fk_cascade", w.CauseEventID
			ev.CauseRootType, ev.CauseRootID, ev.UserCauseWitness = "user", w.CauseUserID, &w
			ev.Effects = nil
			ev.RelatedExplicitEvents = nil
			if ev.Validate() != nil {
				return audit.ErrInvalid
			}
			a.targets = append(a.targets, ev)
			a.successes = append(a.successes, ev)
		}
	}
	return nil
}

func sameUserID(a *uuid.UUID, b uuid.UUID) bool {
	return a == nil && b == uuid.Nil || a != nil && *a == b
}

func (a *deleteAllAttempt) appendUsers(ctx context.Context) error {
	if !a.plan.hasUser {
		return nil
	}
	if len(a.userReceipts) > 100 {
		return audit.ErrInvalid
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range a.userReceipts {
		if seen[r.DeletedUserID] {
			return audit.ErrInvalid
		}
		seen[r.DeletedUserID] = true
		if err := audit.AppendReceipt(ctx, a.tx, r); err != nil {
			return err
		}
	}
	return nil
}

func (a *deleteAllAttempt) userFailureEvents(outcome, reason string) []audit.Event {
	if !a.plan.hasUser {
		return nil
	}
	events := append([]audit.Event(nil), a.userTargets...)
	if len(events) == 0 {
		events = append(events, a.userBase)
	}
	for i := range events {
		e := &events[i]
		e.EventID, e.RecordKind, e.Outcome, e.Reason, e.OccurredAt = uuid.New(), "attempt_observation", outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		e.BeforeContext = nil
		e.EffectCount, e.EffectJSONBytes = 0, 0
		e.Manifest = nil
		e.RelatedExplicitEvents = nil
	}
	return events
}

func equalNullableIDs(a, b *uuid.UUID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
