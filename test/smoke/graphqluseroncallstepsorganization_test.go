package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user"
)

// Stable, synthetic IDs make exact-base observations directly comparable.
func onCallStepsID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("on-call-steps-organization-test:"+name)).String()
}

func onCallStepsExpected(names ...string) []escalation.Step {
	result := make([]escalation.Step, 0, len(names))
	for _, name := range names {
		policy, delay, number := "policy-a", 3, 0
		switch name {
		case "a2":
			delay, number = 7, 1
		case "a3":
			policy, delay = "policy-a-extra", 13
		case "b1":
			policy, delay = "policy-b", 11
		}
		result = append(result, escalation.Step{ID: uuid.MustParse(onCallStepsID(name)),
			PolicyID: onCallStepsID(policy), DelayMinutes: delay, StepNumber: number})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PolicyID == result[j].PolicyID {
			return result[i].StepNumber < result[j].StepNumber
		}
		return result[i].PolicyID < result[j].PolicyID
	})
	return result
}

func onCallStepsHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	db := h.App().DB()
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := db.ExecContext(t.Context(), query, args...)
		require.NoError(t, err)
	}
	exec(`INSERT INTO organizations(id, classification, display_name, canonical_name)
	 VALUES ($1, 'NORMAL', 'On Call Steps B', 'on-call-steps.b')`, onCallStepsID("org-b"))
	exec(`INSERT INTO normal_organizations(organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
	 VALUES ($1, 'NORMAL', 'on-call-steps:b', 'Etc/UTC')`, onCallStepsID("org-b"))
	for _, name := range []string{"user-a", "same-a", "user-b", "foreign-only", "own-only", "none", "ended", "future", "admin-a", "missing", "default"} {
		role := "user"
		if name == "admin-a" {
			role = "admin"
		}
		exec(`INSERT INTO users(id, name, email, role) VALUES ($1, $2, '', $3)`, onCallStepsID(name), name, role)
		if name == "missing" {
			continue
		}
		if name == "default" {
			exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
			 effective_organization_classification, effective_normal_organization_id, organization_role,
			 mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
			 VALUES ($1, $2, 'DEFAULT', NULL, 'NONE', 'ZERO', now(), 'on-call-steps-test', 0)`,
				onCallStepsID(name), organization.DefaultOrganizationID)
			continue
		}
		org := harness.SmokeOrganizationID
		if name == "user-b" || name == "foreign-only" {
			org = onCallStepsID("org-b")
		}
		exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
		 effective_organization_classification, effective_normal_organization_id, organization_role,
		 mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
		 VALUES ($1, $2, 'NORMAL', $2, 'ORG_MEMBER', 'EXACTLY_ONE', now(), 'on-call-steps-test', 1)`, onCallStepsID(name), org)
	}
	for _, policy := range []string{"policy-a", "policy-a-extra", "policy-b"} {
		org := harness.SmokeOrganizationID
		if policy == "policy-b" {
			org = onCallStepsID("org-b")
		}
		exec(`INSERT INTO escalation_policies(id, organization_id, name) VALUES ($1, $2, $3)`, onCallStepsID(policy), org, policy)
	}
	for _, step := range onCallStepsExpected("a1", "a2", "a3", "b1") {
		exec(`INSERT INTO escalation_policy_steps(id, escalation_policy_id, delay, step_number) VALUES ($1, $2, $3, $4)`,
			step.ID, step.PolicyID, step.DelayMinutes, step.StepNumber)
	}
	for _, side := range []string{"a", "b"} {
		org := harness.SmokeOrganizationID
		if side == "b" {
			org = onCallStepsID("org-b")
		}
		exec(`INSERT INTO schedules(id, organization_id, name, time_zone) VALUES ($1, $2, $3, 'Etc/UTC')`,
			onCallStepsID("schedule-"+side), org, "schedule-"+side)
		exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id, schedule_id) VALUES ($1, $2)`,
			onCallStepsID(side+"1"), onCallStepsID("schedule-"+side))
	}
	// Multiple Services cannot multiply rows; the extra Policy has no Service.
	for _, name := range []string{"service-a1", "service-a2"} {
		exec(`INSERT INTO services(id, organization_id, name, escalation_policy_id) VALUES ($1, $2, $3, $4)`,
			onCallStepsID(name), harness.SmokeOrganizationID, name, onCallStepsID("policy-a"))
	}
	for target, steps := range map[string][]string{
		"user-a": {"a1", "a2", "a3", "b1"}, "same-a": {"a1", "a2", "a3", "b1"},
		"user-b": {"a1", "a2", "a3", "b1"}, "admin-a": {"a1", "a2", "a3", "b1"},
		"foreign-only": {"b1"}, "own-only": {"a1", "a2", "a3"}, "missing": {"b1"}, "default": {"b1"},
	} {
		for _, step := range steps {
			exec(`INSERT INTO ep_step_on_call_users(user_id, ep_step_id, start_time) VALUES ($1, $2, now()-interval '1 hour')`,
				onCallStepsID(target), onCallStepsID(step))
		}
	}
	// An ended duplicate must not multiply a current row. Future/null-end rows
	// deliberately retain exact-base semantics; no start-time cutoff is added.
	for _, target := range []string{"user-a", "ended"} {
		exec(`INSERT INTO ep_step_on_call_users(user_id, ep_step_id, start_time, end_time)
		 VALUES ($1, $2, now()-interval '2 hours', now()-interval '1 hour')`, onCallStepsID(target), onCallStepsID("a1"))
	}
	exec(`INSERT INTO ep_step_on_call_users(user_id, ep_step_id, start_time) VALUES ($1, $2, now()+interval '1 day')`,
		onCallStepsID("future"), onCallStepsID("a2"))
	return h
}

func onCallStepsRecord(t *testing.T, outcome any) {
	t.Helper()
	data, err := json.Marshal(struct {
		Case    string `json:"case"`
		Outcome any    `json:"outcome"`
	}{t.Name(), outcome})
	require.NoError(t, err)
	t.Log("ON_CALL_STEPS_CASE " + string(data))
}

const onCallStepsDocument = `query OnCallSteps($id: ID!) {
	user(id: $id) { id onCallSteps {
		id stepNumber delayMinutes escalationPolicy { id name }
		actions { type args } targets { id type }
	} }
}`

func onCallStepsHTTP(t *testing.T, h *harness.Harness, target, token string, apiKey bool) *stepOrganizationResponse {
	t.Helper()
	body := map[string]any{"operationName": "OnCallSteps", "variables": map[string]string{"id": onCallStepsID(target)}}
	if !apiKey {
		body["query"] = onCallStepsDocument
	}
	return stepOrganizationPost(t, h, body, token, apiKey)
}

func onCallStepsCheckHTTP(t *testing.T, response *stepOrganizationResponse, target string, names ...string) {
	t.Helper()
	onCallStepsRecord(t, response)
	require.Empty(t, response.Errors)
	steps := make([]map[string]any, 0, len(names))
	for _, step := range onCallStepsExpected(names...) {
		policyName := "policy-a"
		if step.PolicyID == onCallStepsID("policy-a-extra") {
			policyName = "policy-a-extra"
		} else if step.PolicyID == onCallStepsID("policy-b") {
			policyName = "policy-b"
		}
		actions, targets := []any{}, []any{}
		for _, side := range []string{"a", "b"} {
			if step.ID.String() == onCallStepsID(side+"1") {
				scheduleID := onCallStepsID("schedule-" + side)
				actions = append(actions, map[string]any{"type": "builtin-schedule", "args": map[string]string{"schedule_id": scheduleID}})
				targets = append(targets, map[string]string{"id": scheduleID, "type": "schedule"})
			}
		}
		steps = append(steps, map[string]any{"id": step.ID, "stepNumber": step.StepNumber, "delayMinutes": step.DelayMinutes,
			"escalationPolicy": map[string]string{"id": step.PolicyID, "name": policyName}, "actions": actions, "targets": targets})
	}
	want, err := json.Marshal(map[string]any{"user": map[string]any{"id": onCallStepsID(target), "onCallSteps": steps}})
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(response.Data))
}

func TestGraphQLUserOnCallStepsOrganizationScoped(t *testing.T) {
	h := onCallStepsHarness(t)
	for _, tc := range []struct {
		name, requester, target string
		want                    []string
	}{
		{"self mixed", "user-a", "user-a", []string{"a1", "a2", "a3"}},
		{"same organization mixed", "user-a", "same-a", []string{"a1", "a2", "a3"}},
		{"visible foreign user mixed", "user-a", "user-b", []string{"a1", "a2", "a3"}},
		{"foreign only", "user-a", "foreign-only", nil},
		{"own only", "user-a", "own-only", []string{"a1", "a2", "a3"}},
		{"no assignments", "user-a", "none", nil},
		{"ended", "user-a", "ended", nil},
		{"future null end", "user-a", "future", []string{"a2"}},
		{"admin self mixed", "admin-a", "admin-a", []string{"a1", "a2", "a3"}},
		{"admin foreign user", "admin-a", "user-b", []string{"a1", "a2", "a3"}},
		{"admin foreign only", "admin-a", "foreign-only", nil},
		{"reciprocal self", "user-b", "user-b", []string{"b1"}},
		{"reciprocal foreign user", "user-b", "user-a", []string{"b1"}},
		{"reciprocal foreign only", "user-b", "own-only", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := onCallStepsHTTP(t, h, tc.target, h.GraphQLToken(onCallStepsID(tc.requester)), false)
			onCallStepsCheckHTTP(t, response, tc.target, tc.want...)
		})
	}
	for _, target := range []string{"nonexistent", "bad"} {
		t.Run(target+" user", func(t *testing.T) {
			id := onCallStepsID(target)
			if target == "bad" {
				id = target
			}
			response := stepOrganizationPost(t, h, map[string]any{"query": onCallStepsDocument,
				"variables": map[string]string{"id": id}}, h.GraphQLToken(onCallStepsID("user-a")), false)
			onCallStepsRecord(t, response)
			if target == "bad" {
				require.NotEmpty(t, response.Errors)
				require.Contains(t, response.Errors[0].Message, "must be valid UUID")
			} else {
				require.Empty(t, response.Errors)
			}
			require.JSONEq(t, `{"user":null}`, string(response.Data))
		})
	}
}

func TestGraphQLUserOnCallStepsMissingOrganization(t *testing.T) {
	h := onCallStepsHarness(t)
	for _, principal := range []string{"missing", "default"} {
		t.Run(principal, func(t *testing.T) {
			response := onCallStepsHTTP(t, h, principal, h.GraphQLToken(onCallStepsID(principal)), false)
			onCallStepsRecord(t, response)
			require.Len(t, response.Errors, 1)
			require.Equal(t, "access denied: normal Organization scoped authority is required", response.Errors[0].Message)
			require.Equal(t, harness.QLPath("user.onCallSteps"), response.Errors[0].Path)
			require.JSONEq(t, `{"user":null}`, string(response.Data))
		})
	}
}

func onCallStepsFind(ctx context.Context, store *escalation.Store, tx *sql.Tx, userID string, organizationID *uuid.UUID) ([]escalation.Step, error) {
	return store.FindAllOnCallStepsForUserTx(ctx, tx, userID, organizationID)
}

func onCallStepsStoreOutcome(steps []escalation.Step, err error) any {
	message := ""
	if err != nil {
		message = err.Error()
	}
	return struct {
		Steps []escalation.Step
		Error string
	}{steps, message}
}

func TestUserOnCallStepsStoreOrganizationCompatibility(t *testing.T) {
	h := onCallStepsHarness(t)
	ctx := permission.SystemContext(t.Context(), "Smoketest")
	orgA, orgB := uuid.MustParse(harness.SmokeOrganizationID), uuid.MustParse(onCallStepsID("org-b"))
	for _, scope := range []struct {
		name string
		id   *uuid.UUID
	}{
		{"nil", nil}, {"A", &orgA}, {"B", &orgB},
	} {
		for _, withTx := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tx=%t", scope.name, withTx), func(t *testing.T) {
				var tx *sql.Tx
				if withTx {
					var err error
					tx, err = h.App().DB().BeginTx(ctx, nil)
					require.NoError(t, err)
					defer tx.Rollback()
				}
				for _, tc := range []struct {
					target string
					want   []string
				}{
					{"user-a", []string{"a1", "a2", "a3", "b1"}},
					{"foreign-only", []string{"b1"}},
					{"own-only", []string{"a1", "a2", "a3"}},
					{"none", nil}, {"ended", nil}, {"future", []string{"a2"}},
					{"nonexistent", nil}, {"bad", nil},
				} {
					t.Run(tc.target, func(t *testing.T) {
						id := onCallStepsID(tc.target)
						if tc.target == "bad" {
							id = "bad"
							// The legacy error must leave a supplied transaction usable.
						}
						steps, err := onCallStepsFind(ctx, h.App().EscalationStore, tx, id, scope.id)
						onCallStepsRecord(t, onCallStepsStoreOutcome(steps, err))
						if tc.target == "bad" {
							require.Nil(t, steps)
							require.EqualError(t, err, "invalid value for 'UserID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
							return
						}
						require.NoError(t, err)
						var want []escalation.Step
						for _, step := range onCallStepsExpected(tc.want...) {
							foreign := step.PolicyID == onCallStepsID("policy-b")
							if scope.name == "A" && foreign || scope.name == "B" && !foreign {
								continue
							}
							want = append(want, step)
						}
						require.Equal(t, want, steps) // Includes nil empty result, scalars, ordering and cardinality.
					})
				}
				if tx != nil {
					var one int
					require.NoError(t, tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one))
					require.Equal(t, 1, one)
				}
			})
		}
	}
	for _, org := range []*uuid.UUID{nil, &orgA} {
		t.Run(fmt.Sprintf("permission denied scoped=%t", org != nil), func(t *testing.T) {
			steps, err := onCallStepsFind(t.Context(), h.App().EscalationStore, nil, "bad", org)
			onCallStepsRecord(t, onCallStepsStoreOutcome(steps, err))
			require.Nil(t, steps)
			require.True(t, permission.IsPermissionError(err))
		})
	}
	t.Run("transaction visibility", func(t *testing.T) {
		tx, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer tx.Rollback()
		_, err = tx.ExecContext(ctx, `INSERT INTO ep_step_on_call_users(user_id, ep_step_id) VALUES ($1, $2)`,
			onCallStepsID("none"), onCallStepsID("a1"))
		require.NoError(t, err)
		for _, scope := range []struct {
			name string
			id   *uuid.UUID
		}{{"nil", nil}, {"A", &orgA}, {"B", &orgB}} {
			for _, currentTx := range []*sql.Tx{nil, tx} {
				t.Run(fmt.Sprintf("%s/tx=%t", scope.name, currentTx != nil), func(t *testing.T) {
					steps, err := onCallStepsFind(ctx, h.App().EscalationStore, currentTx, onCallStepsID("none"), scope.id)
					onCallStepsRecord(t, onCallStepsStoreOutcome(steps, err))
					require.NoError(t, err)
					if currentTx != nil && scope.name != "B" {
						require.Equal(t, onCallStepsExpected("a1"), steps)
					} else {
						require.Nil(t, steps)
					}
				})
			}
		}
	})
}

func TestUserOnCallStepsResolverAuthority(t *testing.T) {
	h := onCallStepsHarness(t)
	session, id := uuid.NewString(), onCallStepsID("user-a")
	legacy := permission.UserSourceContext(t.Context(), id, permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	requester, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	human := auth.WithRequester(legacy, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := constructor.Construct(human)
	require.NoError(t, err)
	valid := executioncontext.WithExecutionContext(human, authority)
	app := &graphqlapp.App{DB: h.App().DB(), PolicyStore: h.App().EscalationStore}
	contexts := map[string]context.Context{
		"missing requester": legacy,
		"missing authority": human,
		"zero authority":    executioncontext.WithExecutionContext(human, executioncontext.ExecutionContext{}),
		"inconsistent source": permission.UserSourceContext(valid, id, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: session}),
		"inconsistent session": permission.UserSourceContext(valid, id, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"inconsistent user": permission.UserSourceContext(valid, onCallStepsID("user-b"), permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session}),
	}
	for _, otherID := range []string{id, onCallStepsID("user-b")} {
		otherSession := uuid.NewString()
		other, err := auth.NewRequester(otherID, otherSession)
		require.NoError(t, err)
		otherContext := auth.WithRequester(permission.UserSourceContext(t.Context(), otherID, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: otherSession}), other)
		otherAuthority, err := constructor.Construct(otherContext)
		require.NoError(t, err)
		name := "inconsistent authority source"
		if otherID != id {
			name = "inconsistent authority actor"
		}
		contexts[name] = executioncontext.WithExecutionContext(valid, otherAuthority)
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			steps, err := app.User().OnCallSteps(ctx, &user.User{ID: id})
			onCallStepsRecord(t, onCallStepsStoreOutcome(steps, err))
			require.Nil(t, steps)
			require.True(t, permission.IsPermissionError(err))
		})
	}
	for _, target := range []string{"user-b", "own-only", "none", "bad", "nonexistent"} {
		t.Run("valid authority/"+target, func(t *testing.T) {
			targetID := onCallStepsID(target)
			if target == "bad" {
				targetID = target
			}
			steps, err := app.User().OnCallSteps(valid, &user.User{ID: targetID})
			onCallStepsRecord(t, onCallStepsStoreOutcome(steps, err))
			if target == "bad" {
				require.Nil(t, steps)
				require.EqualError(t, err, "invalid value for 'UserID': must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
				return
			}
			require.NoError(t, err)
			if target == "user-b" || target == "own-only" {
				require.Equal(t, onCallStepsExpected("a1", "a2", "a3"), steps)
			} else {
				require.Nil(t, steps)
			}
		})
	}
}

func TestGraphQLUserOnCallStepsAPIKeyCompatibility(t *testing.T) {
	h := onCallStepsHarness(t)
	created := stepOrganizationPost(t, h, map[string]any{
		"query": `mutation CreateKey($expires: ISOTimestamp!, $query: String!) {
		 createGQLAPIKey(input: {name: "on-call-steps-compatibility", description: "on-call steps compatibility test", expiresAt: $expires, role: admin, query: $query}) {token}
		}`,
		"variables": map[string]any{"expires": time.Now().Add(time.Hour).Format(time.RFC3339), "query": onCallStepsDocument},
	}, h.GraphQLToken(harness.DefaultGraphQLAdminUserID), false)
	require.Empty(t, created.Errors)
	var key struct{ CreateGQLAPIKey struct{ Token string } }
	require.NoError(t, json.Unmarshal(created.Data, &key))
	require.True(t, key.CreateGQLAPIKey.Token != "", "test API key must be created")
	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"user-a", []string{"a1", "a2", "a3", "b1"}},
		{"user-b", []string{"a1", "a2", "a3", "b1"}},
		{"foreign-only", []string{"b1"}},
	} {
		t.Run(tc.target, func(t *testing.T) {
			response := onCallStepsHTTP(t, h, tc.target, key.CreateGQLAPIKey.Token, true)
			onCallStepsCheckHTTP(t, response, tc.target, tc.want...)
		})
	}
}
