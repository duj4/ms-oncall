package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// SD6FailureBatchForTest exposes only the existing writer to the external
// PostgreSQL test package. It is absent from the production binary/API.
func SD6FailureBatchForTest(db *sql.DB, schedules, rotations int) (bool, bool) {
	ctx := permission.SystemContext(context.Background(), "SD6Test")
	input := []assignment.RawTarget{}
	for _, typ := range []assignment.TargetType{assignment.TargetTypeService, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeIntegrationKey, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeSchedule, assignment.TargetTypeRotation} {
		input = append(input, assignment.RawTarget{Type: typ})
	}
	p := newDeleteAllAudit(ctx, db, input)
	a := p.nextAttempt()
	for i := 0; i < 50; i++ {
		e := a.service.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), uuid.New()
		a.service.targets = append(a.service.targets, e)
		k := a.keyEvent
		k.ResourceID, k.ParentServiceID, k.TargetOrganizationID, k.TargetOrgResolution = uuid.New(), uuid.New(), uuid.New(), "known_normal"
		a.keyTargets = append(a.keyTargets, k)
		ep := a.epEvent
		ep.RootID, ep.TargetOrganizationID, ep.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
		a.epTargets = append(a.epTargets, ep)
	}
	for i := 0; i < 100; i++ {
		e := a.event
		e.RootID, e.RootOwnerUserID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), uuid.New(), "known_normal"
		e.RootType, e.Operation = "contact_method", "contact_method.delete"
		if i >= 50 {
			e.RootType, e.Operation, e.ParentCMID = "notification_rule", "notification_rule.delete", uuid.New()
		}
		a.targets = append(a.targets, e)
	}
	for typ, n := range map[string]int{sraudit.Schedule: schedules, sraudit.Rotation: rotations} {
		for i := 0; i < n; i++ {
			e := a.srBase[typ]
			e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
			a.srTargets = append(a.srTargets, e)
		}
	}
	a.groupsStarted = true
	sv, cm, keys, eps := a.failureEvents("tx_failed", "write_failed")
	return recordDeleteAllFailureBatch(db, sv, cm, keys, eps, a.srFailureEvents("tx_failed", "write_failed"))
}

// SD6AggregateBudgetForTest stages two individually valid roots whose combined
// PG JSONB text exceeds the shared budget, while compact Go JSON still fits.
func SD6AggregateBudgetForTest(ctx context.Context, db *sql.DB) error {
	p := newDeleteAllAudit(permission.SystemContext(context.Background(), "SD6Test"), db, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule}})
	a := p.nextAttempt()
	tx, err := a.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(); _ = a.conn.Close() }()
	for i := 0; i < 2; i++ {
		e := a.srBase[sraudit.Schedule]
		e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
		e.EventID = uuid.New()
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "deleted", "EXPLICIT", "explicit_sql", "explicit_target"
		owner, org := uuid.New(), uuid.New()
		for j := 0; j < 7500; j++ {
			id := int64(10000 + i*7500 + j)
			e.Effects = append(e.Effects, sraudit.Effect{EffectID: uuid.New(), ResourceType: sraudit.Favorite, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "schedule.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "schedule_delete", ResourceNumericID: &id, Favorite: &sraudit.FavoriteDetail{OwnerUserID: owner, OwnerOrganizationID: &org, OwnerOrgResolution: "known_normal"}})
		}
		a.srTargets = append(a.srTargets, e)
		a.srSuccesses = append(a.srSuccesses, e)
	}
	if err := sraudit.ValidateBatch(a.srSuccesses); err != nil {
		return err
	}
	return a.appendSR(ctx)
}
