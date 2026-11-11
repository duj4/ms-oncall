package graphqlapp

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/integrationkey"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
)

func (a *deleteAllAttempt) keyCaptureError(err error) error {
	if err != nil {
		pg := sqlutil.MapError(err)
		if pg == nil || pg.Code != "40001" && pg.Code != "40P01" {
			a.auditFailed = true
		}
	}
	return err
}

func (a *deleteAllAttempt) collectKeyReceipts(candidates []serviceKeyReceipt, result []integrationkey.DeleteReceipt) error {
	if len(candidates) > 50 || len(result) > 50 {
		return keyaudit.ErrCapacity
	}
	captured := map[uuid.UUID]serviceKeyReceipt{}
	for _, r := range candidates {
		if r.resource == uuid.Nil || r.root == uuid.Nil || r.org == uuid.Nil {
			return keyaudit.ErrInvalid
		}
		if _, exists := captured[r.resource]; exists {
			return keyaudit.ErrInvalid
		}
		captured[r.resource] = r
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range result {
		c, ok := captured[r.ResourceID]
		if !ok || seen[r.ResourceID] || c.root != r.ServiceID {
			return keyaudit.ErrInvalid
		}
		seen[r.ResourceID] = true
		a.keyReceipts = append(a.keyReceipts, c)
		if a.service != nil && a.service.plan.serviceIDs[c.root] {
			a.service.keyReceipts = append(a.service.keyReceipts, c)
		}
	}
	return nil
}

// Partition against actual, already validated Service success witnesses. A
// requested Service is never enough to suppress an independent Key root.
func (a *deleteAllAttempt) partitionKeys() ([]keyaudit.Event, error) {
	if len(a.keyTargets) > 50 || len(a.keyReceipts) > 50 {
		return nil, keyaudit.ErrCapacity
	}
	targets := map[uuid.UUID]keyaudit.Event{}
	for _, e := range a.keyTargets {
		if _, exists := targets[e.ResourceID]; exists {
			return nil, keyaudit.ErrInvalid
		}
		targets[e.ResourceID] = e
	}
	roots := map[uuid.UUID]uuid.UUID{}
	effects := map[uuid.UUID]serviceKeyReceipt{}
	if a.service != nil {
		for _, e := range a.service.successes {
			if _, exists := roots[e.ServiceID]; exists {
				return nil, keyaudit.ErrInvalid
			}
			roots[e.ServiceID] = e.TargetOrganizationID
			for _, f := range e.Effects {
				if f.ResourceType != deleteaudit.IntegrationKey {
					continue
				}
				if f.ResourceUUID == nil {
					return nil, keyaudit.ErrInvalid
				}
				id := *f.ResourceUUID
				if _, exists := effects[id]; exists {
					return nil, keyaudit.ErrInvalid
				}
				effects[id] = serviceKeyReceipt{id, e.ServiceID, f.TargetOrganizationID}
			}
		}
	}
	// Suppressed explicit SQL may instead be represented by an actual Service
	// FK deletion. Such candidates retain the accepted late EXPLICIT provenance.
	for _, e := range a.keyTargets {
		if f, ok := effects[e.ResourceID]; ok {
			if f.root != e.ParentServiceID || f.org != e.TargetOrganizationID {
				return nil, keyaudit.ErrInvalid
			}
			if _, ok := roots[f.root]; !ok {
				return nil, keyaudit.ErrInvalid
			}
		}
	}
	seen := map[uuid.UUID]bool{}
	var result []keyaudit.Event
	for _, r := range a.keyReceipts {
		e, ok := targets[r.resource]
		if !ok || seen[r.resource] || e.ParentServiceID != r.root || e.TargetOrganizationID != r.org {
			return nil, keyaudit.ErrInvalid
		}
		seen[r.resource] = true
		f, hasEffect := effects[r.resource]
		org, rootDeleted := roots[r.root]
		if rootDeleted {
			if org != r.org || !hasEffect || f != r {
				return nil, keyaudit.ErrInvalid
			}
			// The existing SD3 contract must represent this receipt as explicit SQL.
			matches := 0
			for _, se := range a.service.successes {
				for _, sf := range se.Effects {
					if sf.ResourceType == deleteaudit.IntegrationKey && sf.ResourceUUID != nil && *sf.ResourceUUID == r.resource && sf.Provenance == "EXPLICIT" && sf.DeletionMechanism == "explicit_sql" && sf.Cause == "explicit_target" {
						matches++
					}
				}
			}
			if matches != 1 {
				return nil, keyaudit.ErrInvalid
			}
			continue
		}
		if hasEffect {
			return nil, keyaudit.ErrInvalid
		}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		if err := e.Validate(); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, nil
}
func (a *deleteAllAttempt) appendKeys(ctx context.Context) error {
	if !a.plan.hasKey {
		return nil
	}
	events, err := a.partitionKeys()
	if err != nil {
		return err
	}
	// Every explicit receipt must be absent, including receipts assigned to SD3.
	for _, r := range a.keyReceipts {
		var exists bool
		if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=$1)`, r.resource).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return keyaudit.ErrInvalid
		}
	}
	if len(events) > 50 || len(a.successes) > 100 || a.service != nil && len(a.service.successes) > 50 {
		return keyaudit.ErrCapacity
	}
	serviceCount := 0
	if a.service != nil {
		serviceCount = len(a.service.successes)
	}
	if len(events)+len(a.successes)+serviceCount > 200 {
		return keyaudit.ErrCapacity
	}
	// Captured candidates without an explicit DELETE receipt must either remain
	// at their locked parent, or have an exact SD3 EXPLICIT/fk_cascade witness.
	for _, e := range a.keyTargets {
		received := false
		for _, r := range a.keyReceipts {
			received = received || r.resource == e.ResourceID
		}
		if received {
			continue
		}
		witnessed := false
		if a.service != nil {
			for _, se := range a.service.successes {
				for _, f := range se.Effects {
					if f.ResourceType == deleteaudit.IntegrationKey && f.ResourceUUID != nil && *f.ResourceUUID == e.ResourceID {
						if witnessed || se.ServiceID != e.ParentServiceID || se.TargetOrganizationID != e.TargetOrganizationID || f.TargetOrganizationID != e.TargetOrganizationID || f.Provenance != "EXPLICIT" || f.DeletionMechanism != "fk_cascade" || f.Cause != "service_delete" {
							return keyaudit.ErrInvalid
						}
						witnessed = true
					}
				}
			}
		}
		var exists, unchanged bool
		if err := a.tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=$1),EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=$1 AND service_id=$2)`, e.ResourceID, e.ParentServiceID).Scan(&exists, &unchanged); err != nil {
			return err
		}
		if witnessed && exists || !witnessed && !unchanged {
			return keyaudit.ErrInvalid
		}
	}
	for _, e := range events {
		if err := keyaudit.Append(ctx, a.tx, e); err != nil {
			return err
		}
	}
	return nil
}
func (a *deleteAllAttempt) keyFailureEvents(outcome, reason string) []keyaudit.Event {
	if !a.plan.hasKey {
		return nil
	}
	events := append([]keyaudit.Event{}, a.keyTargets...)
	if len(events) == 0 {
		events = append(events, a.keyEvent)
	}
	for i := range events {
		e := &events[i]
		e.EventID, e.RecordKind, e.Outcome, e.Reason, e.OccurredAt = uuid.New(), "attempt_observation", outcome, reason, time.Now()
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
	}
	return events
}
