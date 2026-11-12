package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	useraudit "github.com/target/goalert/user/deleteaudit"

	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// SD7FailureBatchForTest exposes only the existing writer to the external
// PostgreSQL test package. It is absent from the production binary/API.
func SD7FailureBatchForTest(db *sql.DB, schedules, rotations, overrides int) (bool, bool) {
	return SD8FailureBatchForTest(db, schedules, rotations, overrides, 0)
}
func SD8FailureBatchForTest(db *sql.DB, schedules, rotations, overrides, users int) (bool, bool) {
	ctx := permission.SystemContext(context.Background(), "SD7Test")
	input := []assignment.RawTarget{}
	for _, typ := range []assignment.TargetType{assignment.TargetTypeService, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeIntegrationKey, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeSchedule, assignment.TargetTypeRotation, assignment.TargetTypeUserOverride} {
		input = append(input, assignment.RawTarget{Type: typ})
	}
	if users != 0 {
		input = append(input, assignment.RawTarget{Type: assignment.TargetTypeUser})
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
	for i := 0; i < overrides; i++ {
		e := a.uoBase
		e.RootID, e.ParentScheduleID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), uuid.New(), "known_normal"
		a.uoTargets = append(a.uoTargets, e)
	}
	for i := 0; i < users; i++ {
		e := a.userBase
		e.RootID = useraudit.ID(uuid.New())
		ordinal := i
		e.RootOrdinal = &ordinal
		a.userTargets = append(a.userTargets, e)
	}
	a.groupsStarted = true
	sv, cm, keys, eps := a.failureEvents("tx_failed", "write_failed")
	return recordDeleteAllFailureBatchWithUser(db, sv, cm, keys, eps, a.uoFailureEvents("tx_failed", "write_failed"), a.userFailureEvents("tx_failed", "write_failed"), a.srFailureEvents("tx_failed", "write_failed"))
}
