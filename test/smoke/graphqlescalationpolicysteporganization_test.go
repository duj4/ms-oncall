package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

const stepParentOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Step Parent Organization B', 'step-parent.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'step-parent:organization-b', 'Etc/UTC');

INSERT INTO users (id, name, email, role)
VALUES
    ({{uuid "user-a"}}, 'Step Parent Organization A User', '', 'user'),
    ({{uuid "user-other"}}, 'Step Parent Other User', '', 'user');

INSERT INTO escalation_policies (id, organization_id, name, description, repeat)
VALUES
    ({{uuid "policy-a"}}, {{smokeOrganizationID}}, 'Step Parent Policy A', 'original A', 1),
    ({{uuid "policy-b"}}, {{uuid "org-b"}}, 'Step Parent Policy B', 'original B', 2);
INSERT INTO escalation_policy_steps (id, escalation_policy_id, delay, step_number)
VALUES
    ({{uuid "step-a1"}}, {{uuid "policy-a"}}, 1, 0),
    ({{uuid "step-a2"}}, {{uuid "policy-a"}}, 2, 1),
    ({{uuid "step-a3"}}, {{uuid "policy-a"}}, 3, 2),
    ({{uuid "step-b1"}}, {{uuid "policy-b"}}, 4, 0),
    ({{uuid "step-b2"}}, {{uuid "policy-b"}}, 5, 1);
INSERT INTO escalation_policy_actions (escalation_policy_step_id, user_id)
VALUES
    ({{uuid "step-a1"}}, {{uuid "user-a"}}),
    ({{uuid "step-a1"}}, {{uuid "user-other"}}),
    ({{uuid "step-a2"}}, {{uuid "user-a"}}),
    ({{uuid "step-b1"}}, {{uuid "user-a"}}),
    ({{uuid "step-b1"}}, {{uuid "user-other"}});
`

type stepOrganizationResponse struct {
	Data   json.RawMessage
	Errors []struct {
		Message    string
		Path       harness.QLPath
		Extensions map[string]any
	}
}

func pauseStepOrganizationEngine(t *testing.T, h *harness.Harness) {
	t.Helper()
	// These tests isolate repository mutations and durable rows from Engine
	// processing. The existing API-key create/update path can deadlock with an
	// Engine cycle on the implementation base as well as on the candidate.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, h.App().Engine.Pause(ctx))
}

// Keep all error extensions so comparisons cover field names, codes and paths.
func stepOrganizationPost(t *testing.T, h *harness.Harness, body map[string]any, token string, apiKey bool) *stepOrganizationResponse {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if apiKey {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result stepOrganizationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return &result
}

func stepOrganizationQuery(t *testing.T, h *harness.Harness, query string) *stepOrganizationResponse {
	t.Helper()
	return stepOrganizationPost(t, h, map[string]any{"query": query}, h.GraphQLToken(h.UUID("user-a")), false)
}

// Full durable rows detect partial changes that GraphQL materialization could hide.
func stepOrganizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{
		"escalation_policies", "escalation_policy_steps", "escalation_policy_actions",
		"schedules", "schedule_rules", "rotations", "rotation_participants", "rotation_state", "user_favorites",
	} {
		var rows string
		err := h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text FROM ` + table + ` r`).Scan(&rows)
		require.NoError(t, err, table)
		result[table] = rows
	}
	return result
}

func stepOrganizationUnavailable(t *testing.T, response *stepOrganizationResponse, mutation, field string) {
	t.Helper()
	require.Len(t, response.Errors, 1)
	require.Equal(t, "does not exist", response.Errors[0].Message)
	require.Equal(t, harness.QLPath(mutation), response.Errors[0].Path)
	require.Equal(t, map[string]any{"fieldName": field, "isFieldError": true}, response.Errors[0].Extensions)
}

func stepOrganizationCreateID(t *testing.T, response *stepOrganizationResponse) string {
	t.Helper()
	require.Empty(t, response.Errors)
	var result struct{ CreateEscalationPolicyStep struct{ ID string } }
	require.NoError(t, json.Unmarshal(response.Data, &result))
	require.NotEmpty(t, result.CreateEscalationPolicyStep.ID)
	return result.CreateEscalationPolicyStep.ID
}

func TestGraphQLEscalationPolicyStepParentOrganizationCreate(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	children := []struct{ name, input string }{
		{"plain", ""},
		{"schedule", `newSchedule: {name: "Step Parent New Schedule", timeZone: "Etc/UTC", favorite: true}`},
		{"rotation", fmt.Sprintf(`newRotation: {
			name: "Step Parent New Rotation", timeZone: "Etc/UTC", start: %q,
			type: daily, favorite: true, userIDs: [%q, %q]
		}`, h.Now().Format(time.RFC3339), h.UUID("user-a"), h.UUID("user-other"))},
		{"actions", `actions: [{type: "builtin-user", args: {user_id: "__current_user"}}]`},
	}
	create := func(t *testing.T, policyID, child string) *stepOrganizationResponse {
		t.Helper()
		// Request only the Step ID, so a nested Policy resolver cannot mask a write.
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
			createEscalationPolicyStep(input: {escalationPolicyID: %q, delayMinutes: 7, %s}) {id}
		}`, policyID, child))
	}

	t.Run("foreign and missing parents reject before any child persists", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, child := range children {
			t.Run(child.name, func(t *testing.T) {
				var foreign *stepOrganizationResponse
				for _, policy := range []string{"policy-b", "policy-missing"} {
					response := create(t, h.UUID(policy), child.input)
					stepOrganizationUnavailable(t, response, "createEscalationPolicyStep", "EscalationPolicyID")
					if foreign == nil {
						foreign = response
					} else {
						require.Equal(t, foreign, response)
					}
					require.Equal(t, before, stepOrganizationSnapshot(t, h))
				}
			})
		}
	})

	t.Run("parent authorization precedes nested resource validation", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, policy := range []string{"policy-b", "policy-missing"} {
			for _, input := range []string{
				`newSchedule: {name: "", timeZone: "invalid"}`,
				`newRotation: {name: "", timeZone: "invalid", start: "2026-09-10T00:00:00Z", type: daily}`,
			} {
				stepOrganizationUnavailable(t, create(t, h.UUID(policy), input), "createEscalationPolicyStep", "EscalationPolicyID")
				require.Equal(t, before, stepOrganizationSnapshot(t, h))
			}
		}
	})

	t.Run("own parent accepts the same plain and nested inputs", func(t *testing.T) {
		for _, child := range children {
			t.Run(child.name, func(t *testing.T) {
				id := stepOrganizationCreateID(t, create(t, h.UUID("policy-a"), child.input))
				var policyID, organizationID string
				var delay int
				err := h.App().DB().QueryRow(`
					SELECT s.escalation_policy_id, p.organization_id, s.delay
					FROM escalation_policy_steps s JOIN escalation_policies p ON p.id = s.escalation_policy_id
					WHERE s.id = $1
				`, id).Scan(&policyID, &organizationID, &delay)
				require.NoError(t, err)
				require.Equal(t, h.UUID("policy-a"), policyID)
				require.Equal(t, harness.SmokeOrganizationID, organizationID)
				require.Equal(t, 7, delay)
				if child.name == "actions" {
					var userID string
					require.NoError(t, h.App().DB().QueryRow(`SELECT user_id FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, id).Scan(&userID))
					require.Equal(t, h.UUID("user-a"), userID, "__current_user must still resolve")
				}
			})
		}
		for _, check := range []struct {
			table string
			count int
		}{
			{"schedules", 1}, {"rotations", 1}, {"rotation_participants", 2}, {"user_favorites", 2},
		} {
			var count int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM `+check.table).Scan(&count))
			require.Equal(t, check.count, count, check.table)
		}
	})

	t.Run("new policy and nested steps share the transaction", func(t *testing.T) {
		response := stepOrganizationQuery(t, h, `mutation {
			createEscalationPolicy(input: {name: "Step Parent Nested Policy", steps: [
				{delayMinutes: 2, actions: [{type: "builtin-user", args: {user_id: "__current_user"}}]},
				{delayMinutes: 3, newSchedule: {name: "Step Parent Nested Policy Schedule", timeZone: "Etc/UTC"}}
			]}) {id}
		}`)
		require.Empty(t, response.Errors)
		var result struct{ CreateEscalationPolicy struct{ ID string } }
		require.NoError(t, json.Unmarshal(response.Data, &result))
		var organizationID string
		var steps, actions, ownSchedules int
		err := h.App().DB().QueryRow(`
			SELECT p.organization_id,
				(SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id = p.id),
				(SELECT count(*) FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id = a.escalation_policy_step_id WHERE s.escalation_policy_id = p.id),
				(SELECT count(*) FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id = a.escalation_policy_step_id
				 JOIN schedules sc ON sc.id = a.schedule_id WHERE s.escalation_policy_id = p.id AND sc.organization_id = p.organization_id)
			FROM escalation_policies p WHERE p.id = $1
		`, result.CreateEscalationPolicy.ID).Scan(&organizationID, &steps, &actions, &ownSchedules)
		require.NoError(t, err)
		require.Equal(t, harness.SmokeOrganizationID, organizationID)
		require.Equal(t, []int{2, 2, 1}, []int{steps, actions, ownSchedules})
	})

	t.Run("nested step failure rolls back policy and earlier nested schedule", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		response := stepOrganizationQuery(t, h, `mutation {
			createEscalationPolicy(input: {name: "Step Parent Rejected Nested Policy", steps: [
				{delayMinutes: 2, newSchedule: {name: "Step Parent Rolled Back Schedule", timeZone: "Etc/UTC", favorite: true}},
				{delayMinutes: 0}
			]}) {id}
		}`)
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, stepOrganizationSnapshot(t, h))
	})
}

func TestGraphQLEscalationPolicyStepValidationCompatibility(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	const invalidUUID = "must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	fieldError := func(field string) map[string]any {
		return map[string]any{"fieldName": field, "isFieldError": true}
	}
	multiError := func(fields ...map[string]any) map[string]any {
		values := make([]any, len(fields))
		for i := range fields {
			values[i] = fields[i]
		}
		return map[string]any{"isMultiFieldError": true, "fieldErrors": values}
	}
	const schedule = `newSchedule: {name: "Validation Schedule", timeZone: "Etc/UTC"}`
	const rotation = `newRotation: {name: "Validation Rotation", timeZone: "Etc/UTC", start: "2026-09-10T00:00:00Z", type: daily}`
	const actions = `actions: [{type: "builtin-user", args: {user_id: "__current_user"}}]`
	tests := []struct {
		name, input, message, path string
		extensions                 map[string]any
	}{
		{"malformed parent", `escalationPolicyID: "invalid", delayMinutes: 1`, invalidUUID, "", fieldError("PolicyID")},
		{"malformed parent with actions", `escalationPolicyID: "invalid", delayMinutes: 1, ` + actions, invalidUUID, "", fieldError("PolicyID")},
		{"omitted parent", `delayMinutes: 1`, invalidUUID, "", fieldError("PolicyID")},
		{"low delay", fmt.Sprintf(`escalationPolicyID: %q, delayMinutes: 0`, h.UUID("policy-a")), "must not be below 1", "", fieldError("DelayMinutes")},
		{"high delay", fmt.Sprintf(`escalationPolicyID: %q, delayMinutes: 9001`, h.UUID("policy-a")), "must not be over 9000", "", fieldError("DelayMinutes")},
		{"delay before foreign parent lookup", fmt.Sprintf(`escalationPolicyID: %q, delayMinutes: 0`, h.UUID("policy-b")), "must not be below 1", "", fieldError("DelayMinutes")},
		{"delay before missing parent lookup", fmt.Sprintf(`escalationPolicyID: %q, delayMinutes: 0`, h.UUID("policy-missing")), "must not be below 1", "", fieldError("DelayMinutes")},
		{"parent and delay validation order", `escalationPolicyID: "invalid", delayMinutes: 0`, "Multiple fields failed validation.", "", multiError(
			map[string]any{"fieldName": "PolicyID", "message": invalidUUID},
			map[string]any{"fieldName": "DelayMinutes", "message": "must not be below 1"})},
		{"actions delay precedes UUID and conflicts", `escalationPolicyID: "invalid", delayMinutes: 0, ` + actions + `, ` + rotation, "must not be below 1", ".input.delayMinutes", map[string]any{"code": "INVALID_INPUT_VALUE"}},
		{"empty actions coded delay", `escalationPolicyID: "invalid", delayMinutes: 9001, actions: []`, "must not be over 9000", ".input.delayMinutes", map[string]any{"code": "INVALID_INPUT_VALUE"}},
		{"actions rotation conflict precedes UUID", `escalationPolicyID: "invalid", delayMinutes: 1, ` + actions + `, ` + rotation, "Multiple fields failed validation.", "", multiError(
			map[string]any{"fieldName": "actions", "message": "cannot be used with `newRotation`"},
			map[string]any{"fieldName": "newRotation", "message": "cannot be used with `targets`"})},
		{"actions schedule conflict precedes UUID", `escalationPolicyID: "invalid", delayMinutes: 1, ` + actions + `, ` + schedule, "Multiple fields failed validation.", "", multiError(
			map[string]any{"fieldName": "actions", "message": "cannot be used with `newSchedule`"},
			map[string]any{"fieldName": "newSchedule", "message": "cannot be used with `targets`"})},
		{"schedule rotation conflict precedes normalization", `escalationPolicyID: "invalid", delayMinutes: 0, ` + schedule + `, ` + rotation, "Multiple fields failed validation.", "", multiError(
			map[string]any{"fieldName": "newSchedule", "message": "cannot be used with `newRotation`"},
			map[string]any{"fieldName": "newRotation", "message": "cannot be used with `newSchedule`"})},
	}
	before := stepOrganizationSnapshot(t, h)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := stepOrganizationQuery(t, h, `mutation {createEscalationPolicyStep(input: {`+test.input+`}) {id}}`)
			require.Len(t, response.Errors, 1)
			require.Equal(t, test.message, response.Errors[0].Message)
			require.Equal(t, harness.QLPath("createEscalationPolicyStep"+test.path), response.Errors[0].Path)
			require.Equal(t, test.extensions, response.Errors[0].Extensions)
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		})
	}
	t.Run("malformed step UUID before delay or action mutation", func(t *testing.T) {
		response := stepOrganizationQuery(t, h, `mutation {updateEscalationPolicyStep(input: {id: "invalid", delayMinutes: 0, actions: []})}`)
		require.Len(t, response.Errors, 1)
		require.Equal(t, invalidUUID, response.Errors[0].Message)
		require.Equal(t, harness.QLPath("updateEscalationPolicyStep"), response.Errors[0].Path)
		// Preserve the existing field name, including its trailing space.
		require.Equal(t, fieldError("EscalationPolicyStepID "), response.Errors[0].Extensions)
		require.Equal(t, before, stepOrganizationSnapshot(t, h))
	})
}

func TestGraphQLEscalationPolicyStepParentOrganizationUpdate(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	update := func(t *testing.T, stepID, input string) *stepOrganizationResponse {
		t.Helper()
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {updateEscalationPolicyStep(input: {id: %q, %s})}`, stepID, input))
	}

	t.Run("own delay update and existing user action replacement", func(t *testing.T) {
		response := update(t, h.UUID("step-a1"), `delayMinutes: 9`)
		require.Empty(t, response.Errors)
		require.JSONEq(t, `{"updateEscalationPolicyStep": true}`, string(response.Data))
		var delay int
		require.NoError(t, h.App().DB().QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id = $1`, h.UUID("step-a1")).Scan(&delay))
		require.Equal(t, 9, delay)
		response = update(t, h.UUID("step-a1"), fmt.Sprintf(`actions: [{type: "builtin-user", args: {user_id: %q}}]`, h.UUID("user-other")))
		require.Empty(t, response.Errors)
		var userID string
		require.NoError(t, h.App().DB().QueryRow(`SELECT user_id FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, h.UUID("step-a1")).Scan(&userID))
		require.Equal(t, h.UUID("user-other"), userID)
	})

	t.Run("foreign and missing step reject before delay or action mutation", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, input := range []string{
			`delayMinutes: 12`,
			`delayMinutes: 12, actions: []`,
			fmt.Sprintf(`delayMinutes: 12, actions: [{type: "builtin-user", args: {user_id: %q}}]`, h.UUID("user-other")),
			`delayMinutes: 0, actions: []`,
		} {
			var foreign *stepOrganizationResponse
			for _, step := range []string{"step-b1", "step-missing"} {
				response := update(t, h.UUID(step), input)
				stepOrganizationUnavailable(t, response, "updateEscalationPolicyStep", "EscalationPolicyStepID")
				if foreign == nil {
					foreign = response
				} else {
					require.Equal(t, foreign, response)
				}
				require.Equal(t, before, stepOrganizationSnapshot(t, h))
			}
		}
	})

	t.Run("own action failure rolls back delay and action deletion", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		wait := h.ExpectBackendError(`violates foreign key constraint "escalation_policy_actions_user_id_fkey"`)
		response := update(t, h.UUID("step-a1"), fmt.Sprintf(`delayMinutes: 13, actions: [{type: "builtin-user", args: {user_id: %q}}]`, h.UUID("missing-user")))
		wait()
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, stepOrganizationSnapshot(t, h))
	})

	t.Run("own actions can still be removed", func(t *testing.T) {
		response := update(t, h.UUID("step-a1"), `actions: []`)
		require.Empty(t, response.Errors)
		var count int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, h.UUID("step-a1")).Scan(&count))
		require.Zero(t, count)
	})
}

func TestGraphQLEscalationPolicyStepParentOrganizationPolicyUpdate(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	update := func(t *testing.T, policy, ids string) *stepOrganizationResponse {
		t.Helper()
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
			updateEscalationPolicy(input: {id: %q, name: "Step Parent Reordered Policy", stepIDs: [%s]})
		}`, h.UUID(policy), ids))
	}
	order := func(t *testing.T) []string {
		t.Helper()
		var data string
		require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_agg(id ORDER BY step_number)::text FROM escalation_policy_steps WHERE escalation_policy_id = $1`, h.UUID("policy-a")).Scan(&data))
		var ids []string
		require.NoError(t, json.Unmarshal([]byte(data), &ids))
		return ids
	}
	t.Run("own reorder", func(t *testing.T) {
		response := update(t, "policy-a", fmt.Sprintf(`%q, %q, %q`, h.UUID("step-a3"), h.UUID("step-a1"), h.UUID("step-a2")))
		require.Empty(t, response.Errors)
		require.Equal(t, []string{h.UUID("step-a3"), h.UUID("step-a1"), h.UUID("step-a2")}, order(t))
	})
	t.Run("invalid or foreign step rolls back earlier parent and step changes", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, id := range []string{h.UUID("step-b1"), h.UUID("step-missing"), "invalid"} {
			response := update(t, "policy-a", fmt.Sprintf(`%q, %q`, h.UUID("step-a1"), id))
			require.NotEmpty(t, response.Errors)
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
		// The existing parent mutation maps no rows through its legacy error path.
		wait := h.ExpectBackendError("sql: no rows in result set")
		response := update(t, "policy-b", fmt.Sprintf(`%q`, h.UUID("step-b1")))
		wait()
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, stepOrganizationSnapshot(t, h))
	})
	t.Run("own deletion and reorder remain transactional", func(t *testing.T) {
		response := update(t, "policy-a", fmt.Sprintf(`%q, %q`, h.UUID("step-a2"), h.UUID("step-a3")))
		require.Empty(t, response.Errors)
		require.Equal(t, []string{h.UUID("step-a2"), h.UUID("step-a3")}, order(t))
		var stepCount, actionCount int
		require.NoError(t, h.App().DB().QueryRow(`SELECT
			(SELECT count(*) FROM escalation_policy_steps WHERE id = $1),
			(SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id = $1)
		`, h.UUID("step-a1")).Scan(&stepCount, &actionCount))
		require.Zero(t, stepCount)
		require.Zero(t, actionCount)
	})
}

func TestGraphQLEscalationPolicyStepParentOrganizationAPIKeyCompatibility(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	const document = `mutation StepCompatibility($policy: ID!, $step: ID!, $user: String!) {
		created: createEscalationPolicyStep(input: {escalationPolicyID: $policy, delayMinutes: 6,
			actions: [{type: "builtin-user", args: {user_id: $user}}]}) {id}
		updated: updateEscalationPolicyStep(input: {id: $step, delayMinutes: 8, actions: []})
	}`
	created := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
		mutation CreateStepCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
			createGQLAPIKey(input: {name: "step-parent-compatibility", description: "Step compatibility smoke",
				expiresAt: $expires, role: admin, query: $query}) {token}
		}
	`, "CreateStepCompatibilityKey", map[string]any{
		"expires": time.Now().Add(time.Hour).Format(time.RFC3339), "query": document,
	})
	require.Empty(t, created.Errors)
	var key struct{ CreateGQLAPIKey struct{ Token string } }
	require.NoError(t, json.Unmarshal(created.Data, &key))
	require.NotEmpty(t, key.CreateGQLAPIKey.Token)
	response := stepOrganizationPost(t, h, map[string]any{
		"operationName": "StepCompatibility",
		"variables":     map[string]string{"policy": h.UUID("policy-b"), "step": h.UUID("step-b1"), "user": h.UUID("user-a")},
	}, key.CreateGQLAPIKey.Token, true)
	require.Empty(t, response.Errors)
	var result struct {
		Created struct{ ID string }
		Updated bool
	}
	require.NoError(t, json.Unmarshal(response.Data, &result))
	require.True(t, result.Updated)
	var policyID, userID string
	var delay, actionCount int
	err := h.App().DB().QueryRow(`
		SELECT s.escalation_policy_id, a.user_id
		FROM escalation_policy_steps s JOIN escalation_policy_actions a ON a.escalation_policy_step_id = s.id WHERE s.id = $1
	`, result.Created.ID).Scan(&policyID, &userID)
	require.NoError(t, err)
	require.Equal(t, h.UUID("policy-b"), policyID)
	require.Equal(t, h.UUID("user-a"), userID)
	require.NoError(t, h.App().DB().QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id = $1`, h.UUID("step-b1")).Scan(&delay))
	require.Equal(t, 8, delay)
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, h.UUID("step-b1")).Scan(&actionCount))
	require.Zero(t, actionCount)
}

func TestGraphQLEscalationPolicyStepParentOrganizationFailsClosed(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	// Add these humans after harness admission fixtures, so missing/default
	// authority cannot silently acquire the harness's Normal Organization.
	_, err := h.App().DB().Exec(`INSERT INTO users (id, name, email, role) VALUES
		($1, 'Step Missing Organization User', '', 'user'),
		($2, 'Step Default Organization User', '', 'user')
	`, h.UUID("missing-org-user"), h.UUID("default-org-user"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO user_organization_assignments (
		user_id, effective_organization_id, effective_organization_classification, effective_normal_organization_id,
		organization_role, mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count
	) VALUES ($1, $2, 'DEFAULT', NULL, 'NONE', 'ZERO', now(), 'step-parent-default-smoke-v1', 0)
	`, h.UUID("default-org-user"), organization.DefaultOrganizationID)
	require.NoError(t, err)
	before := stepOrganizationSnapshot(t, h)
	for _, principal := range []string{"missing-org-user", "default-org-user"} {
		for _, query := range []string{
			fmt.Sprintf(`mutation {createEscalationPolicyStep(input: {escalationPolicyID: %q, delayMinutes: 1}) {id}}`, h.UUID("policy-a")),
			fmt.Sprintf(`mutation {updateEscalationPolicyStep(input: {id: %q, delayMinutes: 2, actions: []})}`, h.UUID("step-a1")),
		} {
			response := stepOrganizationPost(t, h, map[string]any{"query": query}, h.GraphQLToken(h.UUID(principal)), false)
			require.NotEmpty(t, response.Errors)
			require.Contains(t, response.Errors[0].Message, "normal Organization scoped authority is required")
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
	}
}

func TestGraphQLEscalationPolicyStepParentOrganizationLockScope(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	ctx, cancel := context.WithTimeout(permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleUser), 10*time.Second)
	defer cancel()
	tx, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	organizationID := uuid.MustParse(harness.SmokeOrganizationID)
	step, err := h.App().EscalationStore.FindOneStepForUpdateTx(ctx, tx, h.UUID("step-a1"), &organizationID)
	require.NoError(t, err)
	require.Equal(t, h.UUID("step-a1"), step.ID.String())
	_, err = h.App().EscalationStore.FindOneStepForUpdateTx(ctx, tx, h.UUID("step-b1"), &organizationID)
	require.ErrorIs(t, err, sql.ErrNoRows)

	other, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer other.Rollback()
	// The parent and unrelated/foreign Steps remain independently lockable.
	for _, lock := range []struct{ table, id string }{
		{"escalation_policies", h.UUID("policy-a")},
		{"escalation_policy_steps", h.UUID("step-a2")},
		{"escalation_policy_steps", h.UUID("step-b1")},
	} {
		var id string
		require.NoError(t, other.QueryRowContext(ctx, `SELECT id FROM `+lock.table+` WHERE id = $1 FOR UPDATE NOWAIT`, lock.id).Scan(&id))
		require.Equal(t, lock.id, id)
	}
	var id string
	err = other.QueryRowContext(ctx, `SELECT id FROM escalation_policy_steps WHERE id = $1 FOR UPDATE NOWAIT`, h.UUID("step-a1")).Scan(&id)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "55P03", pgErr.Code, "the authorized Step itself must remain locked")
}
