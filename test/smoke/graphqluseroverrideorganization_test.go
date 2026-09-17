package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/override"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/test/smoke/harness"
)

const userOverrideOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Override Organization B', 'override.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'override:organization-b', 'Etc/UTC');
INSERT INTO users (id, name, email, role)
VALUES ({{uuid "user-a"}}, 'Override User A', '', 'user'),
       ({{uuid "user-b"}}, 'Override User B', '', 'user');
INSERT INTO user_organization_assignments (
    user_id, effective_organization_id, effective_organization_classification,
    effective_normal_organization_id, organization_role, mapping_outcome,
    authoritative_evaluated_at, source_config_version, matched_count
) VALUES ({{uuid "user-b"}}, {{uuid "org-b"}}, 'NORMAL', {{uuid "org-b"}},
    'ORG_MEMBER', 'EXACTLY_ONE', now(), 'override-test', 1);
INSERT INTO schedules (id, organization_id, name, time_zone)
VALUES ({{uuid "schedule-a"}}, {{smokeOrganizationID}}, 'Override Schedule A', 'Etc/UTC'),
       ({{uuid "schedule-b"}}, {{uuid "org-b"}}, 'Override Schedule B', 'Etc/UTC');
INSERT INTO rotations (id, organization_id, name, type, start_time, shift_length, time_zone)
VALUES ({{uuid "rotation-a"}}, {{smokeOrganizationID}}, 'Override Batch Rotation A', 'daily', now(), 1, 'Etc/UTC');
INSERT INTO user_overrides (id, tgt_schedule_id, add_user_id, remove_user_id, start_time, end_time)
VALUES ({{uuid "override-a1"}}, {{uuid "schedule-a"}}, {{uuid "user-a"}}, {{uuid "user-b"}}, '2090-01-01Z', '2090-01-02Z'),
       ({{uuid "override-a2"}}, {{uuid "schedule-a"}}, {{uuid "user-a"}}, {{uuid "user-b"}}, '2090-01-03Z', '2090-01-04Z'),
       ({{uuid "override-b"}}, {{uuid "schedule-b"}}, {{uuid "user-a"}}, {{uuid "user-b"}}, '2090-01-02Z', '2090-01-03Z');
`

func userOverrideOrganizationHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, userOverrideOrganizationSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func userOverrideOrganizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{"schedules", "user_overrides", "rotations"} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text FROM `+table+` r`).Scan(&rows))
		result[table] = rows
	}
	return result
}

func TestGraphQLUserOverrideOrganizationReadSearch(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	read := func(id string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`query {userOverride(id:%q) {id start end addUserID removeUserID addUser {id name} removeUser {id name} target {id type name}}}`, id))
	}
	own := read(h.UUID("override-a1"))
	require.Empty(t, own.Errors)
	for _, name := range []string{"override-a1", "schedule-a", "user-a", "user-b"} {
		require.Contains(t, string(own.Data), h.UUID(name))
	}
	foreign, missing := read(h.UUID("override-b")), read(h.UUID("missing"))
	require.Equal(t, missing, foreign)
	require.JSONEq(t, `{"userOverride":null}`, string(foreign.Data))

	list := func(input string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, `query {userOverrides(input:{`+input+`}) {nodes {id target {id}} pageInfo {endCursor hasNextPage}}}`)
	}
	for _, input := range []string{"", fmt.Sprintf("scheduleID:%q", h.UUID("schedule-a")),
		fmt.Sprintf("filterAddUserID:[%q]", h.UUID("user-a")),
		fmt.Sprintf("filterRemoveUserID:[%q]", h.UUID("user-b")),
		fmt.Sprintf("filterAnyUserID:[%q]", h.UUID("user-b"))} {
		response := list(input)
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), h.UUID("override-a1"))
		require.Contains(t, string(response.Data), h.UUID("override-a2"))
		require.NotContains(t, string(response.Data), h.UUID("override-b"))
	}
	for _, input := range []string{fmt.Sprintf("scheduleID:%q", h.UUID("schedule-b")), fmt.Sprintf("scheduleID:%q", h.UUID("missing"))} {
		response := list(input)
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), `"nodes":[]`)
	}
	omit := list(fmt.Sprintf("omit:[%q,%q]", h.UUID("override-a1"), h.UUID("override-b")))
	require.Empty(t, omit.Errors)
	require.NotContains(t, string(omit.Data), h.UUID("override-a1"))
	require.Contains(t, string(omit.Data), h.UUID("override-a2"))
	for _, anchor := range []string{"override-b", "missing"} {
		cursor, err := search.Cursor(override.SearchOptions{After: override.SearchCursor{ID: h.UUID(anchor)}})
		require.NoError(t, err)
		response := list(fmt.Sprintf("after:%q", cursor))
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), `"nodes":[]`, "foreign anchors must behave as missing anchors")
	}
	for _, value := range []any{h.UUID("org-b"), nil, uuid.Nil.String()} {
		cursor, err := search.Cursor(map[string]any{"OrganizationID": value, "organization_id": value, "organizationID": value})
		require.NoError(t, err)
		response := list(fmt.Sprintf("after:%q", cursor))
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), h.UUID("override-a1"))
		require.NotContains(t, string(response.Data), h.UUID("override-b"))
	}
	page := list("first:1")
	require.Empty(t, page.Errors)
	var data struct {
		UserOverrides struct {
			PageInfo struct {
				EndCursor   string
				HasNextPage bool
			}
		}
	}
	require.NoError(t, json.Unmarshal(page.Data, &data))
	require.True(t, data.UserOverrides.PageInfo.HasNextPage)
	require.Contains(t, string(page.Data), h.UUID("override-a1"))
	next := list(fmt.Sprintf("first:1,after:%q", data.UserOverrides.PageInfo.EndCursor))
	require.Empty(t, next.Errors)
	require.Contains(t, string(next.Data), h.UUID("override-a2"))
	require.NotContains(t, string(next.Data), h.UUID("override-a1"))
	require.NotContains(t, string(next.Data), h.UUID("override-b"))

	_, err := h.App().DB().Exec(`UPDATE users SET role='admin' WHERE id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	require.Equal(t, missing, read(h.UUID("override-b")), "legacy human Admin remains scoped")
	require.NotContains(t, string(list("").Data), h.UUID("override-b"))
	require.Empty(t, read(h.UUID("override-a1")).Errors)
	before := userOverrideOrganizationSnapshot(t, h)
	for _, query := range []string{
		fmt.Sprintf(`mutation {createUserOverride(input:{scheduleID:%q,start:"2090-06-01T00:00:00Z",end:"2090-06-02T00:00:00Z",addUserID:%q}) {id}}`, h.UUID("schedule-b"), h.UUID("user-a")),
		fmt.Sprintf(`mutation {updateUserOverride(input:{id:%q,end:"2090-01-05T00:00:00Z"})}`, h.UUID("override-b")),
	} {
		require.NotEmpty(t, stepOrganizationQuery(t, h, query).Errors)
	}
	wait := h.ExpectBackendError("sql: no rows in result set")
	require.NotEmpty(t, stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {deleteAll(input:[{type:userOverride,id:%q}])}`, h.UUID("override-b"))).Errors)
	wait()
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
}

func TestGraphQLUserOverrideOrganizationCreateAndNested(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	create := func(scheduleID, start, end, add string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createUserOverride(input:{scheduleID:%q,start:%q,end:%q,addUserID:%q}) {id target {id}}}`, scheduleID, start, end, add))
	}
	before := userOverrideOrganizationSnapshot(t, h)
	foreign := create(h.UUID("schedule-b"), "2090-01-02T00:00:00Z", "2090-01-03T00:00:00Z", h.UUID("user-a"))
	missing := create(h.UUID("missing"), "2090-01-02T00:00:00Z", "2090-01-03T00:00:00Z", h.UUID("user-a"))
	require.NotEmpty(t, foreign.Errors)
	require.Equal(t, missing, foreign)
	require.NotContains(t, fmt.Sprint(foreign), h.UUID("override-b"), "foreign conflict hints stay hidden")
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
	for _, values := range [][3]string{
		{"2090-02-02T00:00:00Z", "2090-02-01T00:00:00Z", h.UUID("user-a")},
		{"2000-01-01T00:00:00Z", "2000-01-02T00:00:00Z", h.UUID("user-a")},
		{"2090-02-01T00:00:00Z", "2090-02-02T00:00:00Z", "invalid"},
	} {
		own := create(h.UUID("schedule-a"), values[0], values[1], values[2])
		require.NotEmpty(t, own.Errors)
		for _, name := range []string{"schedule-b", "missing"} {
			require.Equal(t, own, create(h.UUID(name), values[0], values[1], values[2]), "local validation still precedes Schedule authorization")
		}
	}
	// User affiliation is deliberately not constrained by Schedule ownership.
	require.Empty(t, create(h.UUID("schedule-a"), "2090-02-01T00:00:00Z", "2090-02-02T00:00:00Z", h.UUID("user-b")).Errors)
	conflict := create(h.UUID("schedule-a"), "2090-01-01T00:00:00Z", "2090-01-02T00:00:00Z", h.UUID("user-a"))
	require.NotEmpty(t, conflict.Errors)
	require.Contains(t, conflict.Errors[0].Message, "cannot override the same user twice")
	nested := func(name, end string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createSchedule(input:{name:%q,timeZone:"Etc/UTC",newUserOverrides:[{scheduleID:%q,start:"2090-03-01T00:00:00Z",end:%q,addUserID:%q}]}) {id}}`, name, h.UUID("schedule-b"), end, h.UUID("user-b")))
	}
	response := nested("Nested override", "2090-03-02T00:00:00Z")
	require.Empty(t, response.Errors)
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedules s JOIN user_overrides o ON o.tgt_schedule_id=s.id WHERE s.name='Nested override' AND s.organization_id=$1`, harness.SmokeOrganizationID).Scan(&count))
	require.Equal(t, 1, count)
	before = userOverrideOrganizationSnapshot(t, h)
	require.NotEmpty(t, nested("Rejected nested override", "2090-02-01T00:00:00Z").Errors)
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h), "nested failure rolls back parent and children")
	secondFails := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createSchedule(input:{name:"Rejected second override",timeZone:"Etc/UTC",newUserOverrides:[{start:"2090-03-01T00:00:00Z",end:"2090-03-02T00:00:00Z",addUserID:%q},{start:"2090-03-01T00:00:00Z",end:"2090-03-02T00:00:00Z",addUserID:"invalid"}]}) {id}}`, h.UUID("user-a")))
	require.NotEmpty(t, secondFails.Errors)
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h), "failure of the second child rolls back the first child too")
}

func TestGraphQLUserOverrideOrganizationUpdateAndDelete(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	update := func(id, fields string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {updateUserOverride(input:{id:%q,%s})}`, id, fields))
	}
	before := userOverrideOrganizationSnapshot(t, h)
	for _, fields := range []string{`end:"2090-01-05T00:00:00Z"`, `addUserID:"invalid"`, `end:"2000-01-01T00:00:00Z"`} {
		foreign, missing := update(h.UUID("override-b"), fields), update(h.UUID("missing"), fields)
		require.NotEmpty(t, foreign.Errors)
		require.Equal(t, missing, foreign)
		require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
	}
	require.Empty(t, update(h.UUID("override-a2"), `end:"2090-01-05T00:00:00Z"`).Errors)
	before = userOverrideOrganizationSnapshot(t, h)
	deleteTargets := func(targets string, wantError bool) *stepOrganizationResponse {
		if wantError {
			wait := h.ExpectBackendError("sql: no rows in result set")
			defer wait()
		}
		return stepOrganizationQuery(t, h, `mutation {deleteAll(input:[`+targets+`])}`)
	}
	target := func(typ, name string) string { return fmt.Sprintf(`{type:%s,id:%q}`, typ, h.UUID(name)) }
	for _, prefix := range []string{"", target("userOverride", "override-a1") + ",", target("rotation", "rotation-a") + ","} {
		foreign := deleteTargets(prefix+target("userOverride", "override-b"), true)
		missing := deleteTargets(prefix+target("userOverride", "missing"), true)
		require.NotEmpty(t, foreign.Errors)
		require.Equal(t, missing, foreign)
		require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
	}
	// The override is deleted first; a later foreign Schedule must roll it back.
	require.NotEmpty(t, deleteTargets(target("userOverride", "override-a1")+","+target("schedule", "schedule-b"), true).Errors)
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
	// Duplicates, including UUID spelling variants, denote one requested object.
	duplicate := target("userOverride", "override-a1") + "," + fmt.Sprintf(`{type:userOverride,id:%q}`, strings.ToUpper(h.UUID("override-a1")))
	require.Empty(t, deleteTargets(duplicate, false).Errors)
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_overrides WHERE id=$1`, h.UUID("override-a1")).Scan(&count))
	require.Zero(t, count)
	require.Empty(t, deleteTargets(target("userOverride", "override-a2")+","+target("schedule", "schedule-a"), false).Errors)
}

func TestUserOverrideOrganizationStoreAndNonHumanCompatibility(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	ctx := permission.SystemContext(context.Background(), "Smoketest")
	s := h.App().OverrideStore
	org := uuid.MustParse(harness.SmokeOrganizationID)
	foreignID := h.UUID("override-b")
	foreign, err := s.FindOneUserOverrideTx(ctx, nil, foreignID, false)
	require.NoError(t, err)
	require.NotNil(t, foreign)
	rows, err := s.Search(ctx, h.App().DB(), nil)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	// Explicit Store scope also protects raw/forged parent input.
	for _, name := range []string{"override-b", "missing"} {
		row, err := s.FindOneUserOverrideTxScoped(ctx, nil, h.UUID(name), false, &org)
		require.NoError(t, err)
		require.Nil(t, row)
	}
	before := userOverrideOrganizationSnapshot(t, h)
	forged := *foreign
	forged.Target = assignment.ScheduleTarget(h.UUID("schedule-a"))
	require.Error(t, s.UpdateUserOverrideTxScoped(ctx, nil, &forged, &org))
	forged.ID = h.UUID("override-a1")
	forged.Target = assignment.ScheduleTarget(h.UUID("schedule-b"))
	require.Error(t, s.UpdateUserOverrideTxScoped(ctx, nil, &forged, &org))
	require.ErrorIs(t, s.DeleteUserOverrideTxScoped(ctx, nil, []string{h.UUID("override-a1"), foreignID}, &org), sql.ErrNoRows)
	require.Equal(t, before, userOverrideOrganizationSnapshot(t, h), "Store-owned transactions roll back on error")
	// Nil scope retains global access and existing-subset deletion semantics.
	foreign.End = foreign.End.Add(time.Hour)
	require.NoError(t, s.UpdateUserOverrideTx(ctx, nil, foreign))
	app := &graphqlapp.App{DB: h.App().DB(), OverrideStore: s}
	apiCtx := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})
	row, err := app.Query().UserOverride(apiCtx, foreignID)
	require.NoError(t, err)
	require.NotNil(t, row)
	conn, err := app.Query().UserOverrides(apiCtx, nil)
	require.NoError(t, err)
	require.Len(t, conn.Nodes, 3)
	start := time.Date(2090, 4, 1, 0, 0, 0, 0, time.UTC)
	scheduleID, userID := h.UUID("schedule-b"), h.UUID("user-b")
	created, err := app.Mutation().CreateUserOverride(apiCtx, graphql2.CreateUserOverrideInput{ScheduleID: &scheduleID, AddUserID: &userID, Start: start, End: start.Add(time.Hour)})
	require.NoError(t, err)
	require.NotNil(t, created)
	ok, err := app.Mutation().UpdateUserOverride(apiCtx, graphql2.UpdateUserOverrideInput{ID: foreignID})
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = app.Mutation().DeleteAll(apiCtx, []assignment.RawTarget{
		{Type: assignment.TargetTypeUserOverride, ID: foreignID},
		{Type: assignment.TargetTypeUserOverride, ID: foreignID},
		{Type: assignment.TargetTypeUserOverride, ID: h.UUID("missing")},
	})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestGraphQLUserOverrideOrganizationNonOperationalAuthority(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	queries := []string{
		fmt.Sprintf(`query {userOverride(id:%q) {id target {id}}}`, h.UUID("override-a1")),
		`query {userOverrides {nodes {id}}}`,
		fmt.Sprintf(`mutation {createUserOverride(input:{scheduleID:%q,start:"2090-06-01T00:00:00Z",end:"2090-06-02T00:00:00Z",addUserID:%q}) {id}}`, h.UUID("schedule-a"), h.UUID("user-a")),
		fmt.Sprintf(`mutation {updateUserOverride(input:{id:%q})}`, h.UUID("override-a1")),
		fmt.Sprintf(`mutation {deleteAll(input:[{type:userOverride,id:%q}])}`, h.UUID("override-a1")),
	}
	// Create the authenticated session before removing its operational authority.
	h.GraphQLToken(h.UUID("user-a"))
	_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET
		effective_organization_id=$2, effective_organization_classification='DEFAULT',
		effective_normal_organization_id=NULL, organization_role='NONE', mapping_outcome='ZERO', matched_count=0
		WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
	require.NoError(t, err)
	before := userOverrideOrganizationSnapshot(t, h)
	for _, state := range []string{"Default", "missing assignment"} {
		if state == "missing assignment" {
			_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
			require.NoError(t, err)
		}
		for _, query := range queries {
			response := stepOrganizationQuery(t, h, query)
			require.NotEmpty(t, response.Errors, state)
			require.NotContains(t, string(response.Data), h.UUID("override-a1"))
		}
		require.Equal(t, before, userOverrideOrganizationSnapshot(t, h))
	}
}

func TestUserOverrideOrganizationNonLockingParent(t *testing.T) {
	h := userOverrideOrganizationHarness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	for _, operation := range []string{"read", "update", "delete", "search", "create"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(permission.SystemContext(context.Background(), "Smoketest"), 5*time.Second)
			defer cancel()
			parent, err := h.App().DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer parent.Rollback()
			// FOR UPDATE represents the row lock taken by Schedule deletion.
			// Create's pre-existing FK check requires KEY SHARE, so its control
			// holds the compatible NO KEY UPDATE lock of a Schedule edit.
			lock := "FOR UPDATE"
			if operation == "create" {
				lock = "FOR NO KEY UPDATE"
			}
			_, err = parent.ExecContext(ctx, `SELECT id FROM schedules WHERE id=$1 `+lock, h.UUID("schedule-a"))
			require.NoError(t, err)
			child, err := h.App().DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer child.Rollback()
			_, err = child.ExecContext(ctx, `SET LOCAL lock_timeout='1s'`)
			require.NoError(t, err)
			s := h.App().OverrideStore
			switch operation {
			case "read", "update":
				row, err := s.FindOneUserOverrideTxScoped(ctx, child, h.UUID("override-a1"), operation == "update", &org)
				require.NoError(t, err)
				require.NotNil(t, row)
				if operation == "update" {
					require.NoError(t, s.UpdateUserOverrideTxScoped(ctx, child, row, &org))
				}
			case "delete":
				require.NoError(t, s.DeleteUserOverrideTxScoped(ctx, child, []string{h.UUID("override-a1")}, &org))
			case "search":
				rows, err := s.SearchScoped(ctx, child, nil, &org)
				require.NoError(t, err)
				require.Len(t, rows, 2)
			case "create":
				start := time.Date(2090, 5, 1, 0, 0, 0, 0, time.UTC)
				_, err := s.CreateUserOverrideTxScoped(ctx, child, &override.UserOverride{Target: assignment.ScheduleTarget(h.UUID("schedule-a")), AddUserID: h.UUID("user-a"), Start: start, End: start.Add(time.Hour)}, &org)
				require.NoError(t, err)
			}
		})
	}
}
