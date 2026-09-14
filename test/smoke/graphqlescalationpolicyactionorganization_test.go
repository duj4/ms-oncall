package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/test/smoke/harness"
)

const stepActionOrganizationSQL = stepParentOrganizationSQL + `
INSERT INTO user_organization_assignments (
    user_id, effective_organization_id, effective_organization_classification,
    effective_normal_organization_id, organization_role, mapping_outcome,
    authoritative_evaluated_at, source_config_version, matched_count
) VALUES (
    {{uuid "user-other"}}, {{uuid "org-b"}}, 'NORMAL', {{uuid "org-b"}},
    'ORG_MEMBER', 'EXACTLY_ONE', now(), 'step-action-smoke-v1', 1
);
INSERT INTO schedules (id, organization_id, name, description, time_zone)
VALUES
    ({{uuid "schedule-a"}}, {{smokeOrganizationID}}, 'Action Schedule A', '', 'Etc/UTC'),
    ({{uuid "schedule-a2"}}, {{smokeOrganizationID}}, 'Action Schedule A2', '', 'Etc/UTC'),
    ({{uuid "schedule-b"}}, {{uuid "org-b"}}, 'Action Schedule B', '', 'Etc/UTC');
INSERT INTO rotations (id, organization_id, name, description, type, start_time, shift_length, time_zone)
VALUES
    ({{uuid "rotation-a"}}, {{smokeOrganizationID}}, 'Action Rotation A', '', 'daily', now(), 1, 'Etc/UTC'),
    ({{uuid "rotation-a2"}}, {{smokeOrganizationID}}, 'Action Rotation A2', '', 'daily', now(), 1, 'Etc/UTC'),
    ({{uuid "rotation-b"}}, {{uuid "org-b"}}, 'Action Rotation B', '', 'daily', now(), 1, 'Etc/UTC');
`

func stepActionOrganizationTarget(kind, id string) string {
	return fmt.Sprintf(`{type: "builtin-%s", args: {%s_id: %q}}`, kind, kind, id)
}

func stepActionOrganizationCreate(t *testing.T, h *harness.Harness, actions string) *stepOrganizationResponse {
	t.Helper()
	return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
		createEscalationPolicyStep(input: {escalationPolicyID: %q, delayMinutes: 7, actions: [%s]}) {id}
	}`, h.UUID("policy-a"), actions))
}

func stepActionOrganizationUpdate(t *testing.T, h *harness.Harness, actions string, delay int) *stepOrganizationResponse {
	t.Helper()
	if actions != "" {
		actions = "actions: " + actions
	}
	return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
		updateEscalationPolicyStep(input: {id: %q, delayMinutes: %d, %s})
	}`, h.UUID("step-a1"), delay, actions))
}

func stepActionOrganizationRows(t *testing.T, h *harness.Harness, stepID string) []string {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT coalesce(
		'user:' || user_id::text, 'schedule:' || schedule_id::text,
		'rotation:' || rotation_id::text, 'channel:' || channel_id::text
	) FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, stepID)
	require.NoError(t, err)
	defer rows.Close()
	var result []string
	for rows.Next() {
		var target string
		require.NoError(t, rows.Scan(&target))
		result = append(result, target)
	}
	require.NoError(t, rows.Err())
	return result
}

func TestGraphQLEscalationPolicyActionOrganizationCreate(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			own := stepActionOrganizationTarget(kind, h.UUID(kind+"-a"))
			id := stepOrganizationCreateID(t, stepActionOrganizationCreate(t, h, own))
			require.Equal(t, []string{kind + ":" + h.UUID(kind+"-a")}, stepActionOrganizationRows(t, h, id))

			// Include valid User and operational actions ahead of the rejected
			// target to detect partial Step/action persistence in a mixed list.
			for _, prefix := range []string{"", stepActionOrganizationTarget("user", h.UUID("user-other")) + ", " + own + ", "} {
				before := stepOrganizationSnapshot(t, h)
				var foreign *stepOrganizationResponse
				for _, target := range []string{kind + "-b", kind + "-missing"} {
					response := stepActionOrganizationCreate(t, h, prefix+stepActionOrganizationTarget(kind, h.UUID(target)))
					field := "Actions[0].ID"
					if prefix != "" {
						field = "Actions[2].ID"
					}
					stepOrganizationUnavailable(t, response, "createEscalationPolicyStep", field)
					if foreign == nil {
						foreign = response
					} else {
						require.Equal(t, foreign, response, "foreign and missing targets must be indistinguishable")
					}
					require.Equal(t, before, stepOrganizationSnapshot(t, h), "rejected CREATE must leave no durable artifact")
				}
			}
		})
	}

	t.Run("source authorization precedes target validation", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, parent := range []string{"policy-b", "policy-missing"} {
			for _, kind := range []string{"schedule", "rotation"} {
				response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
					createEscalationPolicyStep(input: {escalationPolicyID: %q, delayMinutes: 7, actions: [%s]}) {id}
				}`, h.UUID(parent), stepActionOrganizationTarget(kind, "invalid")))
				stepOrganizationUnavailable(t, response, "createEscalationPolicyStep", "EscalationPolicyID")
				require.Equal(t, before, stepOrganizationSnapshot(t, h))
			}
		}
	})

	t.Run("nested policy failure rolls back earlier nested resources", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, kind := range []string{"schedule", "rotation"} {
			response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
				createEscalationPolicy(input: {name: "Rejected Action Policy", steps: [
					{delayMinutes: 2, newSchedule: {name: "Rolled Back Action Schedule", timeZone: "Etc/UTC", favorite: true}},
					{delayMinutes: 3, actions: [%s]}
				]}) {id}
			}`, stepActionOrganizationTarget(kind, h.UUID(kind+"-b"))))
			stepOrganizationUnavailable(t, response, "createEscalationPolicy", "Steps[1].Actions[0].ID")
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
	})
}

func TestGraphQLEscalationPolicyActionOrganizationUpdate(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			user := stepActionOrganizationTarget("user", h.UUID("user-other"))
			own := stepActionOrganizationTarget(kind, h.UUID(kind+"-a"))
			final := "[" + user + ", " + own + "]"
			require.Empty(t, stepActionOrganizationUpdate(t, h, final, 7).Errors)
			require.ElementsMatch(t, []string{"user:" + h.UUID("user-other"), kind + ":" + h.UUID(kind+"-a")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
			before := stepOrganizationSnapshot(t, h)
			require.Empty(t, stepActionOrganizationUpdate(t, h, final, 7).Errors)
			require.Equal(t, before, stepOrganizationSnapshot(t, h), "retained own actions must keep their durable rows")

			for _, prefix := range []string{"", user + ", " + own + ", "} {
				var foreign *stepOrganizationResponse
				for _, target := range []string{kind + "-b", kind + "-missing"} {
					response := stepActionOrganizationUpdate(t, h, "["+prefix+stepActionOrganizationTarget(kind, h.UUID(target))+"]", 19)
					stepOrganizationUnavailable(t, response, "updateEscalationPolicyStep", "ID")
					if foreign == nil {
						foreign = response
					} else {
						require.Equal(t, foreign, response)
					}
					require.Equal(t, before, stepOrganizationSnapshot(t, h), "rejected UPDATE must preserve delay and every action row")
				}
			}
			// Replace an existing own operational target with another own target.
			require.Empty(t, stepActionOrganizationUpdate(t, h, "["+stepActionOrganizationTarget(kind, h.UUID(kind+"-a2"))+"]", 8).Errors)
			require.Equal(t, []string{kind + ":" + h.UUID(kind+"-a2")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
		})
	}

	t.Run("foreign source rejects before malformed target", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, step := range []string{"step-b1", "step-missing"} {
			response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
				updateEscalationPolicyStep(input: {id: %q, delayMinutes: 19, actions: [%s]})
			}`, h.UUID(step), stepActionOrganizationTarget("rotation", "invalid")))
			stepOrganizationUnavailable(t, response, "updateEscalationPolicyStep", "EscalationPolicyStepID")
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
	})
}

func TestGraphQLEscalationPolicyActionOrganizationHistoricalRemoval(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	for _, kind := range []string{"schedule", "rotation"} {
		for _, retained := range []string{"empty", "user", "user and own target"} {
			t.Run(kind+"/"+retained, func(t *testing.T) {
				// Historical foreign references are seeded directly, never through
				// the ordinary-human application mutation being tested.
				_, err := h.App().DB().Exec(`DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id = $1`, h.UUID("step-a1"))
				require.NoError(t, err)
				_, err = h.App().DB().Exec(`INSERT INTO escalation_policy_actions (escalation_policy_step_id, `+kind+`_id) VALUES ($1, $2)`, h.UUID("step-a1"), h.UUID(kind+"-b"))
				require.NoError(t, err)
				_, err = h.App().DB().Exec(`INSERT INTO escalation_policy_actions (escalation_policy_step_id, user_id) VALUES ($1, $2)`, h.UUID("step-a1"), h.UUID("user-other"))
				require.NoError(t, err)
				before := stepOrganizationSnapshot(t, h)
				require.Empty(t, stepActionOrganizationUpdate(t, h, "", 9).Errors, "Actions == nil must retain base-compatible delay-only behavior")
				afterDelay := stepOrganizationSnapshot(t, h)
				for table, rows := range before {
					if table != "escalation_policy_steps" {
						require.Equal(t, rows, afterDelay[table], table)
					}
				}
				var delay int
				require.NoError(t, h.App().DB().QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id = $1`, h.UUID("step-a1")).Scan(&delay))
				require.Equal(t, 9, delay)

				foreign := stepActionOrganizationTarget(kind, h.UUID(kind+"-b"))
				user := stepActionOrganizationTarget("user", h.UUID("user-other"))
				response := stepActionOrganizationUpdate(t, h, "["+user+", "+foreign+"]", 19)
				stepOrganizationUnavailable(t, response, "updateEscalationPolicyStep", "ID")
				require.Equal(t, afterDelay, stepOrganizationSnapshot(t, h), "retaining an existing foreign target must reject")

				final := "[]"
				var want []string
				if retained != "empty" {
					final = "[" + user + "]"
					want = []string{"user:" + h.UUID("user-other")}
				}
				if retained == "user and own target" {
					final = "[" + user + ", " + stepActionOrganizationTarget(kind, h.UUID(kind+"-a")) + "]"
					want = append(want, kind+":"+h.UUID(kind+"-a"))
				}
				require.Empty(t, stepActionOrganizationUpdate(t, h, final, 10).Errors)
				require.ElementsMatch(t, want, stepActionOrganizationRows(t, h, h.UUID("step-a1")), "pure removal must not authorize the removed target")
			})
		}
	}
}

func TestGraphQLEscalationPolicyActionOrganizationValidationPrecedence(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	// Captured from exact base b80dc99ad before the repair: duplicate errors
	// have no extensions; malformed IDs and delay errors retain field names.
	const malformedMessage = "must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	for _, kind := range []string{"schedule", "rotation"} {
		own := stepActionOrganizationTarget(kind, h.UUID(kind+"-a"))
		for _, malformedKind := range []string{"schedule", "rotation"} {
			malformed := stepActionOrganizationTarget(malformedKind, "invalid")
			for _, tc := range []struct {
				name       string
				create     bool
				retained   bool
				actions    string
				delay      int
				message    string
				extensions map[string]any
			}{
				{
					name: "CREATE malformed User before malformed target", create: true,
					actions: stepActionOrganizationTarget("user", "invalid") + ", " + malformed,
					message: malformedMessage, extensions: map[string]any{"fieldName": "Actions[0].ID", "isFieldError": true},
				},
				{
					name: "CREATE duplicate before malformed target", create: true,
					actions: own + ", " + own + ", " + malformed,
					message: "same " + kind + " cannot be assigned twice to the same step",
				},
				{
					name: "UPDATE delay before malformed target", delay: 0,
					actions: malformed, message: "must not be below 1",
					extensions: map[string]any{"fieldName": "DelayMinutes", "isFieldError": true},
				},
				{
					name: "UPDATE new duplicate before malformed target", delay: 19,
					actions: own + ", " + own + ", " + malformed,
					message: "same " + kind + " cannot be assigned twice to the same step",
				},
				{
					name: "UPDATE retained duplicate before malformed target", retained: true, delay: 19,
					actions: own + ", " + own + ", " + malformed,
					message: malformedMessage, extensions: map[string]any{"fieldName": "ID", "isFieldError": true},
				},
			} {
				t.Run(kind+"/later "+malformedKind+"/"+tc.name, func(t *testing.T) {
					// Reset through valid application requests so each case also
					// exercises rollback of the original actions and Step delay.
					initial := "[" + stepActionOrganizationTarget("user", h.UUID("user-other")) + "]"
					if tc.retained {
						initial = "[" + own + ", " + own + "]"
						require.Empty(t, stepActionOrganizationUpdate(t, h, "["+own+"]", 7).Errors)
					}
					require.Empty(t, stepActionOrganizationUpdate(t, h, initial, 7).Errors)
					if tc.retained {
						require.Equal(t, []string{kind + ":" + h.UUID(kind+"-a")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")), "retained duplicates must keep the existing row")
					}
					before := stepOrganizationSnapshot(t, h)
					mutation := "updateEscalationPolicyStep"
					var response *stepOrganizationResponse
					if tc.create {
						mutation = "createEscalationPolicyStep"
						response = stepActionOrganizationCreate(t, h, tc.actions)
					} else {
						response = stepActionOrganizationUpdate(t, h, "["+tc.actions+"]", tc.delay)
					}
					require.Len(t, response.Errors, 1)
					require.Equal(t, tc.message, response.Errors[0].Message)
					require.Equal(t, harness.QLPath(mutation), response.Errors[0].Path)
					require.Equal(t, tc.extensions, response.Errors[0].Extensions)
					require.Equal(t, before, stepOrganizationSnapshot(t, h), "rejected request must roll back every durable row")
				})
			}
		}
	}
}

func TestGraphQLEscalationPolicyActionOrganizationCompatibility(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)

	t.Run("malformed UUID errors retain existing fields and messages", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, kind := range []string{"schedule", "rotation", "user"} {
			action := stepActionOrganizationTarget(kind, "invalid")
			for _, tc := range []struct {
				response *stepOrganizationResponse
				mutation string
				field    string
			}{
				{stepActionOrganizationCreate(t, h, action), "createEscalationPolicyStep", "Actions[0].ID"},
				{stepActionOrganizationUpdate(t, h, "["+action+"]", 19), "updateEscalationPolicyStep", "ID"},
			} {
				require.Len(t, tc.response.Errors, 1)
				require.Equal(t, "must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", tc.response.Errors[0].Message)
				require.Equal(t, harness.QLPath(tc.mutation), tc.response.Errors[0].Path)
				require.Equal(t, map[string]any{"fieldName": tc.field, "isFieldError": true}, tc.response.Errors[0].Extensions)
				require.Equal(t, before, stepOrganizationSnapshot(t, h))
			}
		}
	})

	t.Run("global User current user and channel actions", func(t *testing.T) {
		user := stepActionOrganizationTarget("user", h.UUID("user-other"))
		channel := `{type: "builtin-webhook", args: {webhook_url: "https://example.invalid/action-organization-smoke"}}`
		id := stepOrganizationCreateID(t, stepActionOrganizationCreate(t, h, strings.Join([]string{
			user, stepActionOrganizationTarget("user", "__current_user"), channel,
		}, ", ")))
		var channelID string
		require.NoError(t, h.App().DB().QueryRow(`SELECT a.channel_id FROM escalation_policy_actions a
			JOIN notification_channels c ON c.id = a.channel_id WHERE a.escalation_policy_step_id = $1`, id).Scan(&channelID))
		require.ElementsMatch(t, []string{"user:" + h.UUID("user-other"), "user:" + h.UUID("user-a"), "channel:" + channelID}, stepActionOrganizationRows(t, h, id))
		require.Empty(t, stepActionOrganizationUpdate(t, h, "["+user+", "+channel+"]", 8).Errors)
		require.ElementsMatch(t, []string{"user:" + h.UUID("user-other"), "channel:" + channelID}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
		before := stepOrganizationSnapshot(t, h)
		require.Empty(t, stepActionOrganizationUpdate(t, h, "["+user+", "+channel+"]", 8).Errors)
		require.Equal(t, before, stepOrganizationSnapshot(t, h))
		require.Empty(t, stepActionOrganizationUpdate(t, h, "["+user+"]", 8).Errors)
		require.Equal(t, []string{"user:" + h.UUID("user-other")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
	})

	t.Run("duplicate actions and action limit retain existing behavior", func(t *testing.T) {
		before := stepOrganizationSnapshot(t, h)
		for _, kind := range []string{"schedule", "rotation", "user"} {
			action := stepActionOrganizationTarget(kind, h.UUID(kind+"-a"))
			response := stepActionOrganizationCreate(t, h, action+", "+action)
			require.Len(t, response.Errors, 1)
			require.Equal(t, "same "+kind+" cannot be assigned twice to the same step", response.Errors[0].Message)
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
		var oldLimit int
		require.NoError(t, h.App().DB().QueryRow(`SELECT max FROM config_limits WHERE id = 'ep_actions_per_step'`).Scan(&oldLimit))
		_, err := h.App().DB().Exec(`UPDATE config_limits SET max = 2 WHERE id = 'ep_actions_per_step'`)
		require.NoError(t, err)
		defer func() {
			_, err := h.App().DB().Exec(`UPDATE config_limits SET max = $1 WHERE id = 'ep_actions_per_step'`, oldLimit)
			require.NoError(t, err)
		}()
		actions := strings.Join([]string{
			stepActionOrganizationTarget("user", h.UUID("user-other")),
			stepActionOrganizationTarget("schedule", h.UUID("schedule-a")),
			stepActionOrganizationTarget("rotation", h.UUID("rotation-a")),
		}, ", ")
		for _, response := range []*stepOrganizationResponse{
			stepActionOrganizationCreate(t, h, actions),
			stepActionOrganizationUpdate(t, h, "["+actions+"]", 19),
		} {
			require.NotEmpty(t, response.Errors)
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
		// Replacing the old actions at the limit must still delete before add.
		final := strings.Join([]string{
			stepActionOrganizationTarget("schedule", h.UUID("schedule-a")),
			stepActionOrganizationTarget("rotation", h.UUID("rotation-a")),
		}, ", ")
		require.Empty(t, stepActionOrganizationUpdate(t, h, "["+final+"]", 8).Errors)
		require.ElementsMatch(t, []string{"schedule:" + h.UUID("schedule-a"), "rotation:" + h.UUID("rotation-a")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
	})

	t.Run("nested policy schedule and rotation creation", func(t *testing.T) {
		response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {
			createEscalationPolicy(input: {name: "Nested Action Compatibility", steps: [
				{delayMinutes: 2, newSchedule: {name: "Nested Action Schedule", timeZone: "Etc/UTC"}},
				{delayMinutes: 3, newRotation: {name: "Nested Action Rotation", timeZone: "Etc/UTC", start: %q, type: daily, userIDs: [%q]}},
				{delayMinutes: 4, actions: [%s, %s]}
			]}) {id}
		}`, h.Now().Format(time.RFC3339), h.UUID("user-other"), stepActionOrganizationTarget("schedule", h.UUID("schedule-a")), stepActionOrganizationTarget("rotation", h.UUID("rotation-a"))))
		require.Empty(t, response.Errors)
		var result struct{ CreateEscalationPolicy struct{ ID string } }
		require.NoError(t, json.Unmarshal(response.Data, &result))
		var steps, actions, ownTargets int
		require.NoError(t, h.App().DB().QueryRow(`SELECT
			(SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id = $1),
			count(*), count(*) FILTER (WHERE coalesce(sc.organization_id, r.organization_id) = p.organization_id)
			FROM escalation_policies p JOIN escalation_policy_steps s ON s.escalation_policy_id = p.id
			JOIN escalation_policy_actions a ON a.escalation_policy_step_id = s.id
			LEFT JOIN schedules sc ON sc.id = a.schedule_id LEFT JOIN rotations r ON r.id = a.rotation_id
			WHERE p.id = $1
		`, result.CreateEscalationPolicy.ID).Scan(&steps, &actions, &ownTargets))
		require.Equal(t, []int{3, 4, 4}, []int{steps, actions, ownTargets})
	})
}

func TestGraphQLEscalationPolicyActionOrganizationAPIKeyCompatibility(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	const document = `mutation ActionCompatibility($policy: ID!, $step: ID!, $schedule: String!, $rotation: String!) {
		created: createEscalationPolicyStep(input: {escalationPolicyID: $policy, delayMinutes: 6, actions: [
			{type: "builtin-schedule", args: {schedule_id: $schedule}},
			{type: "builtin-rotation", args: {rotation_id: $rotation}}
		]}) {id}
		updated: updateEscalationPolicyStep(input: {id: $step, delayMinutes: 8, actions: [
			{type: "builtin-schedule", args: {schedule_id: $schedule}},
			{type: "builtin-rotation", args: {rotation_id: $rotation}}
		]})
	}`
	created := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
		mutation CreateActionCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
			createGQLAPIKey(input: {name: "step-action-compatibility", description: "Action compatibility smoke",
				expiresAt: $expires, role: admin, query: $query}) {token}
		}
	`, "CreateActionCompatibilityKey", map[string]any{
		"expires": time.Now().Add(time.Hour).Format(time.RFC3339), "query": document,
	})
	require.Empty(t, created.Errors)
	var key struct{ CreateGQLAPIKey struct{ Token string } }
	require.NoError(t, json.Unmarshal(created.Data, &key))
	require.NotEmpty(t, key.CreateGQLAPIKey.Token)
	response := stepOrganizationPost(t, h, map[string]any{
		"operationName": "ActionCompatibility",
		"variables": map[string]string{
			"policy": h.UUID("policy-a"), "step": h.UUID("step-a1"),
			"schedule": h.UUID("schedule-b"), "rotation": h.UUID("rotation-b"),
		},
	}, key.CreateGQLAPIKey.Token, true)
	require.Empty(t, response.Errors)
	var result struct {
		Created struct{ ID string }
		Updated bool
	}
	require.NoError(t, json.Unmarshal(response.Data, &result))
	require.True(t, result.Updated)
	for _, step := range []string{result.Created.ID, h.UUID("step-a1")} {
		require.ElementsMatch(t, []string{"schedule:" + h.UUID("schedule-b"), "rotation:" + h.UUID("rotation-b")}, stepActionOrganizationRows(t, h, step))
	}
}

func TestGraphQLEscalationPolicyActionOrganizationNonLockingTargets(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepActionOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	actions := strings.Join([]string{
		stepActionOrganizationTarget("schedule", h.UUID("schedule-a")),
		stepActionOrganizationTarget("rotation", h.UUID("rotation-a")),
	}, ", ")
	require.Empty(t, stepActionOrganizationUpdate(t, h, "["+actions+"]", 7).Errors)
	token := h.GraphQLToken(h.UUID("user-a"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer gate.Rollback()
	request := func(query string) *stepOrganizationResponse {
		t.Helper()
		body, err := json.Marshal(map[string]string{"query": query})
		require.NoError(t, err)
		reqCtx, reqCancel := context.WithTimeout(ctx, 3*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err, "relationship authorization must complete while target mutation locks are held")
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result stepOrganizationResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		return &result
	}

	for _, strength := range []string{"NO KEY UPDATE", "UPDATE"} {
		for _, kind := range []string{"schedule", "rotation"} {
			var id string
			require.NoError(t, gate.QueryRowContext(ctx, `SELECT id FROM `+kind+`s WHERE id = $1 FOR `+strength+` NOWAIT`, h.UUID(kind+"-a")).Scan(&id))
		}
		if strength == "NO KEY UPDATE" {
			// Existing FK KEY SHARE checks are compatible with these locks;
			// a newly introduced target FOR UPDATE would block CREATE.
			id := stepOrganizationCreateID(t, request(fmt.Sprintf(`mutation {
				createEscalationPolicyStep(input: {escalationPolicyID: %q, delayMinutes: 7, actions: [%s]}) {id}
			}`, h.UUID("policy-a"), actions)))
			require.Len(t, stepActionOrganizationRows(t, h, id), 2)
		} else {
			// Retaining the final action set requires no new FK checks or
			// target locks, even while both roots are exclusively row-locked.
			before := stepOrganizationSnapshot(t, h)
			response := request(fmt.Sprintf(`mutation {
				updateEscalationPolicyStep(input: {id: %q, delayMinutes: 7, actions: [%s]})
			}`, h.UUID("step-a1"), actions))
			require.Empty(t, response.Errors)
			require.Equal(t, before, stepOrganizationSnapshot(t, h))
		}
	}
}
