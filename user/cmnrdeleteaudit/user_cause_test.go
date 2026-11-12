package cmnrdeleteaudit

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	useraudit "github.com/target/goalert/user/deleteaudit"
	"testing"
)

func userCausedEvent() Event {
	e := validEvent()
	e.SchemaVersion = 2
	e.AuthorityRole = "platform_admin"
	e.DeletionMechanism = "fk_cascade"
	e.CauseRootType = "user"
	e.CauseRootID = e.RootOwnerUserID
	e.CauseEventID = uuid.New()
	e.UserCauseWitness = &useraudit.ExplicitWitness{EventID: e.EventID, ResourceType: e.RootType, ResourceID: e.RootID, OwnerID: e.RootOwnerUserID, TargetOrganizationID: useraudit.ID(e.TargetOrganizationID), TargetOrgResolution: e.TargetOrgResolution, RowVersion: 1, CauseUserID: e.CauseRootID, CauseEventID: e.CauseEventID, RequestID: e.RequestID, ExecutionID: e.ExecutionID, AttemptID: e.AttemptID, OwnerFK: true, Verified: true}
	return e
}
func TestUserCauseVersionBoundaries(t *testing.T) {
	require.Equal(t, 1, validEvent().Canonical().SchemaVersion)
	require.NoError(t, validEvent().Validate())
	for _, resolution := range []string{"known_normal", "known_default", "unknown"} {
		e := userCausedEvent()
		org := uuid.New()
		if resolution == "known_default" {
			org = uuid.MustParse("296e2656-7221-53fe-bd0a-832d24ccfd03")
		}
		if resolution == "unknown" {
			org = uuid.Nil
		}
		e.TargetOrganizationID, e.TargetOrgResolution = org, resolution
		e.UserCauseWitness.TargetOrganizationID, e.UserCauseWitness.TargetOrgResolution = useraudit.ID(org), resolution
		require.NoError(t, e.Validate())
		e.SchemaVersion = 1
		require.Error(t, e.Validate(), "v2 cause cannot enter legacy branch")
	}
	for name, change := range map[string]func(*Event){"ordinary owner": func(e *Event) { e.AuthorityRole = "org_member" }, "missing witness": func(e *Event) { e.UserCauseWitness = nil }, "different attempt": func(e *Event) { e.AttemptID = uuid.New() }, "cause forged": func(e *Event) { e.CauseEventID = uuid.New() }, "owner": func(e *Event) { e.RootOwnerUserID = uuid.New() }, "parent": func(e *Event) { e.ParentCMID = uuid.New() }, "root": func(e *Event) { e.CauseRootID = uuid.New() }, "provenance": func(e *Event) { e.Provenance = "CASCADE" }, "missing cause type": func(e *Event) { e.CauseRootType = "" }, "unknown version": func(e *Event) { e.SchemaVersion = 3 }, "pending witness": func(e *Event) { e.UserCauseWitness.Verified = false }} {
		t.Run(name, func(t *testing.T) { e := userCausedEvent(); change(&e); require.Error(t, e.Validate()) })
	}
}
