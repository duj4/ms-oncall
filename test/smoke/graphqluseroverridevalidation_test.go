package smoke

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func TestGraphQLUserOverrideCreateValidationPrecedence(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	before := userOverrideOrganizationSnapshot(t, h)
	const start, end = "2090-09-01T00:00:00Z", "2090-09-02T00:00:00Z"
	const equalMessage = "cannot be the same as the user being replaced"
	const uuidMessage = "must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	for _, tc := range []struct {
		name, add, remove, start, end, field, message string
	}{
		{"equal-existing-users", h.UUID("user-a"), h.UUID("user-a"), start, end, "AddUserID", equalMessage},
		{"equal-casefold-users", h.UUID("user-a"), strings.ToUpper(h.UUID("user-a")), start, end, "AddUserID", equalMessage},
		{"equal-missing-users", h.UUID("missing"), h.UUID("missing"), start, end, "AddUserID", equalMessage},
		{"equal-casefold-missing-users", h.UUID("missing"), strings.ToUpper(h.UUID("missing")), start, end, "AddUserID", equalMessage},
		{"missing-add-only", h.UUID("missing"), "", start, end, "AddUserID", "user does not exist"},
		{"missing-remove-only", "", h.UUID("missing"), start, end, "RemoveUserID", "user does not exist"},
		{"missing-add-with-existing-remove", h.UUID("missing"), h.UUID("user-b"), start, end, "AddUserID", "user does not exist"},
		{"missing-remove-with-existing-add", h.UUID("user-a"), h.UUID("missing"), start, end, "RemoveUserID", "user does not exist"},
		{"distinct-missing-users-add-first", h.UUID("missing"), h.UUID("other-missing"), start, end, "AddUserID", "user does not exist"},
		{"malformed-add", "bad", "", start, end, "AddUserID", uuidMessage},
		{"malformed-remove", "", "bad", start, end, "RemoveUserID", uuidMessage},
		{"invalid-range-before-equal-users", h.UUID("user-a"), h.UUID("user-a"), end, start, "End", "must occur after Start time"},
		{"expired-before-equal-users", h.UUID("user-a"), h.UUID("user-a"), "2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z", "End", "must be in the future"},
		{"no-users", "", "", start, end, "UserID", "must specify AddUserID and/or RemoveUserID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var own *stepOrganizationResponse
			for _, parent := range []struct{ name, id string }{
				{"own-schedule", h.UUID("schedule-a")},
				{"foreign-schedule", h.UUID("schedule-b")},
				{"missing-schedule", h.UUID("missing")},
			} {
				t.Run(parent.name, func(t *testing.T) {
					response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createUserOverride(input:{scheduleID:%q,start:%q,end:%q,addUserID:%q,removeUserID:%q}) {id}}`, parent.id, tc.start, tc.end, tc.add, tc.remove))
					require.Len(t, response.Errors, 1)
					require.Equal(t, tc.message, response.Errors[0].Message)
					require.Equal(t, harness.QLPath("createUserOverride"), response.Errors[0].Path)
					require.Equal(t, map[string]any{"fieldName": tc.field, "isFieldError": true}, response.Errors[0].Extensions)
					require.JSONEq(t, `{"createUserOverride":null}`, string(response.Data))
					if own == nil {
						own = response
					} else {
						require.Equal(t, own, response, "safe User validation must precede parent authorization")
					}
					require.Equal(t, before, userOverrideOrganizationSnapshot(t, h), "validation failure must preserve durable state")
				})
			}
		})
	}
}

func TestGraphQLUserOverrideCreateConflictAfterParentAuthorization(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	before := userOverrideOrganizationSnapshot(t, h)
	create := func(parent string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createUserOverride(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-03T00:00:00Z",addUserID:%q}) {id}}`, h.UUID(parent), h.UUID("user-a")))
	}
	own := create("schedule-a")
	require.Len(t, own.Errors, 1)
	require.Equal(t, "UserID", own.Errors[0].Extensions["fieldName"])
	require.Contains(t, own.Errors[0].Message, "CONFLICTING_ID="+h.UUID("override-a1"))
	foreign, missing := create("schedule-b"), create("missing")
	require.Len(t, foreign.Errors, 1)
	require.Equal(t, map[string]any{"fieldName": "TargetID", "isFieldError": true}, foreign.Errors[0].Extensions)
	require.Equal(t, "schedule does not exist", foreign.Errors[0].Message)
	require.Equal(t, missing, foreign, "foreign override conflicts must be hidden by parent authorization")
	require.NotContains(t, fmt.Sprint(foreign), "CONFLICTING_ID")
	require.NotContains(t, fmt.Sprint(foreign), h.UUID("override-b"))
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
}
