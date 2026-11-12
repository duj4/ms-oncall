package deleteaudit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func testEvent() Event {
	u := uuid.New()
	b := &Before{Version: 1, RootID: uuid.New(), ParentScheduleID: uuid.New(), TargetOrganizationID: uuid.New(), AddUserID: &u, Start: time.Date(9998, 1, 1, 0, 0, 0, 123456000, time.UTC), End: time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC), RowVersion: 4294967295}
	return Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user_override.delete", RootType: "user_override", RootID: b.RootID, ParentScheduleID: b.ParentScheduleID, TargetOrganizationID: b.TargetOrganizationID, TargetOrgResolution: "known_normal", BeforeContext: b, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: b.TargetOrganizationID, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestEventClosedIdentityAndBefore(t *testing.T) {
	e := testEvent()
	require.NoError(t, e.Validate())
	for name, change := range map[string]func(*Event){
		"operation": func(e *Event) { e.Operation = "user.delete" }, "root": func(e *Event) { e.RootType = "schedule" }, "missing_context": func(e *Event) { e.BeforeContext = nil }, "parent": func(e *Event) { e.ParentScheduleID = uuid.New() }, "org": func(e *Event) { e.TargetOrganizationID = uuid.New() }, "version": func(e *Event) { e.BeforeContext.Version = 2 }, "row_version": func(e *Event) { e.BeforeContext.RowVersion = 0 }, "no_users": func(e *Event) { e.BeforeContext.AddUserID = nil }, "zero_user": func(e *Event) { u := uuid.Nil; e.BeforeContext.AddUserID = &u }, "time": func(e *Event) { e.BeforeContext.End = e.BeforeContext.Start }, "unknown_actor": func(e *Event) { e.ActorKind = "unknown" }, "foreign_pa": func(e *Event) { e.HomeOrganizationID = uuid.New() }, "default_pa": func(e *Event) {
			e.HomeOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
			e.OrganizationRole = "NONE"
		}, "false_success": func(e *Event) { e.Outcome = "commit_unknown" }, "false_provenance": func(e *Event) { e.Provenance = "CASCADE" },
	} {
		t.Run(name, func(t *testing.T) { e := testEvent(); change(&e); require.Error(t, e.Validate()) })
	}
	for _, role := range []string{"org_member", "org_admin", "platform_admin"} {
		e := testEvent()
		e.AuthorityRole = role
		if role == "org_admin" {
			e.OrganizationRole = "ORG_ADMIN"
		}
		require.NoError(t, e.Validate())
	}
	e = testEvent()
	e.RecordKind, e.Outcome, e.Reason = "attempt_observation", "commit_unknown", "commit_unconfirmed"
	e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
	e.BeforeContext = nil
	require.NoError(t, e.Validate())
	e.BeforeContext = testEvent().BeforeContext
	require.Error(t, e.Validate())
}

func TestReceiptExactSet(t *testing.T) {
	b := *testEvent().BeforeContext
	require.NoError(t, ValidateReceipts([]Before{b}, []Before{b}))
	for name, change := range map[string]func(*Before){"root": func(b *Before) { b.RootID = uuid.New() }, "parent": func(b *Before) { b.ParentScheduleID = uuid.New() }, "org": func(b *Before) { b.TargetOrganizationID = uuid.New() }, "user": func(b *Before) { b.AddUserID = nil; b.RemoveUserID = testEvent().BeforeContext.AddUserID }, "time": func(b *Before) { b.End = b.End.Add(-time.Second) }, "row_version": func(b *Before) { b.RowVersion-- }} {
		t.Run(name, func(t *testing.T) {
			r := b
			change(&r)
			require.ErrorIs(t, ValidateReceipts([]Before{b}, []Before{r}), ErrInvalid)
		})
	}
	require.Error(t, ValidateReceipts([]Before{b}, nil))
	require.Error(t, ValidateReceipts([]Before{b}, []Before{b, b}))
	require.Error(t, ValidateReceipts([]Before{b, b}, []Before{b, b}))
	require.NoError(t, ValidateReceipts(nil, nil))
}

func TestCompleteSafeProjectionBudget(t *testing.T) {
	var events []Event
	total := 0
	for range MaxRoots {
		e := testEvent()
		r := uuid.New()
		e.BeforeContext.RemoveUserID = &r
		b, err := json.Marshal(e.Canonical())
		require.NoError(t, err)
		require.LessOrEqual(t, len(b), MaxRootJSONBytes)
		total += len(b)
		events = append(events, e)
	}
	require.NoError(t, ValidateBatch(events))
	require.LessOrEqual(t, total, MaxJSONBytes)
	t.Logf("complete canonical Go JSON: roots=%d total=%d maximum root=%d; limits %d/%d", len(events), total, total/len(events), MaxRootJSONBytes, MaxJSONBytes)
	require.ErrorIs(t, ValidateBatch(append(events, testEvent())), ErrCapacity)
	require.ErrorIs(t, ValidateBatch(append(events[:1], events[0])), ErrInvalid)
	// The aggregate byte ceiling is conservative: 50 * 4096 < 256 KiB.
	// Closed fixed fields cannot manufacture arbitrary padding to hit it.
	require.Less(t, MaxRoots*MaxRootJSONBytes, MaxJSONBytes)
}
