package graphqlapp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/override"
	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
)

func (a *deleteAllAttempt) uoCaptureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}

func (a *deleteAllAttempt) collectUO(result override.DeleteResult) {
	for _, b := range result.Targets {
		e := a.uoBase
		e.EventID, e.RootID, e.ParentScheduleID, e.TargetOrganizationID = uuid.New(), b.RootID, b.ParentScheduleID, b.TargetOrganizationID
		e.TargetOrgResolution = "known_normal"
		if b.TargetOrganizationID.String() == organization.DefaultOrganizationID {
			e.TargetOrgResolution = "known_default"
		}
		a.uoTargets = append(a.uoTargets, e)
	}
	// A partial or inconsistent receipt is never turned into a success witness.
	if uoaudit.ValidateReceipts(result.Targets, result.Receipts) != nil {
		return
	}
	for i, b := range result.Targets {
		e := a.uoTargets[len(a.uoTargets)-len(result.Targets)+i]
		e.BeforeContext = &b
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		a.uoSuccesses = append(a.uoSuccesses, e.Canonical())
	}
}

func (a *deleteAllAttempt) appendUO(ctx context.Context) error {
	if !a.plan.hasUO {
		return nil
	}
	if len(a.uoTargets) != len(a.uoSuccesses) {
		return uoaudit.ErrInvalid
	}
	if err := uoaudit.ValidateBatch(a.uoSuccesses); err != nil {
		return err
	}
	for i, e := range a.uoSuccesses {
		t := a.uoTargets[i]
		if e.RootID != t.RootID || e.ParentScheduleID != t.ParentScheduleID || e.TargetOrganizationID != t.TargetOrganizationID || e.AttemptID != a.event.AttemptID || e.ExecutionID != a.event.ExecutionID || e.RequestID != a.event.RequestID {
			return uoaudit.ErrInvalid
		}
		if err := uoaudit.Append(ctx, a.tx, e); err != nil {
			return err
		}
	}
	var roots, size, maxSize int
	if err := a.tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(octet_length(to_jsonb(e)::text)),0),coalesce(max(octet_length(to_jsonb(e)::text)),0) FROM user_override_delete_audit_events e WHERE attempt_id=$1 AND execution_id=$2 AND record_kind='success_witness'`, a.event.AttemptID, a.event.ExecutionID).Scan(&roots, &size, &maxSize); err != nil {
		return err
	}
	if roots != len(a.uoSuccesses) {
		return uoaudit.ErrInvalid
	}
	if roots > uoaudit.MaxRoots || size > uoaudit.MaxJSONBytes || maxSize > uoaudit.MaxRootJSONBytes {
		return uoaudit.ErrCapacity
	}
	return nil
}

func (a *deleteAllAttempt) uoFailureEvents(outcome, reason string) []uoaudit.Event {
	if !a.plan.hasUO {
		return nil
	}
	events := append([]uoaudit.Event(nil), a.uoTargets...)
	if len(events) == 0 {
		events = append(events, a.uoBase)
	}
	for i := range events {
		e := &events[i]
		e.EventID, e.RecordKind, e.Outcome, e.Reason, e.OccurredAt = uuid.New(), "attempt_observation", outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		e.BeforeContext = nil
	}
	return events
}
