package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/test/smoke/harness"
)

const scheduleRotationOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Schedule Rotation Organization B', 'schedule-rotation.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'schedule-rotation:organization-b', 'Etc/UTC');

INSERT INTO users (id, name, email, role)
VALUES
    ({{uuid "user-a"}}, 'Schedule Rotation Organization A User', '', 'user'),
    ({{uuid "user-b"}}, 'Schedule Rotation Organization B User', '', 'user');
INSERT INTO user_organization_assignments (
    user_id, effective_organization_id, effective_organization_classification,
    effective_normal_organization_id, organization_role, mapping_outcome,
    authoritative_evaluated_at, source_config_version, matched_count
) VALUES (
    {{uuid "user-b"}}, {{uuid "org-b"}}, 'NORMAL',
    {{uuid "org-b"}}, 'ORG_MEMBER', 'EXACTLY_ONE', now(), 'schedule-rotation-smoke-v1', 1
);

INSERT INTO schedules (id, organization_id, name, description, time_zone)
VALUES
    ({{uuid "schedule-a"}}, {{smokeOrganizationID}}, 'Schedule Rotation A', '', 'Etc/UTC'),
    ({{uuid "schedule-b"}}, {{uuid "org-b"}}, 'Schedule Rotation B', '', 'Etc/UTC');

INSERT INTO rotations (id, organization_id, name, description, type, start_time, shift_length, time_zone)
VALUES
    ({{uuid "rotation-a"}}, {{smokeOrganizationID}}, 'Schedule Target Rotation A', '', 'daily', now(), 1, 'Etc/UTC'),
    ({{uuid "rotation-b"}}, {{uuid "org-b"}}, 'Schedule Target Rotation B', '', 'daily', now(), 1, 'Etc/UTC');
`

func TestGraphQLScheduleRotationSameOrganization(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, scheduleRotationOrganizationSQL, "")
	defer h.Close()

	type response struct {
		Data   json.RawMessage
		Errors []struct {
			Message    string
			Path       harness.QLPath
			Extensions map[string]any
		}
	}
	// The harness supplies real Normal Organization A and assigns user-a to it.
	// Decode all error extensions to check field names and existence hiding.
	update := func(t *testing.T, scheduleID, targetType, targetID, rules string) *response {
		t.Helper()
		document := fmt.Sprintf(`mutation {
			updateScheduleTarget(input: {scheduleID: %q, target: {type: %s, id: %q}, rules: %s})
		}`, scheduleID, targetType, targetID, rules)
		body, err := json.Marshal(map[string]string{"query": document})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(h.UUID("user-a"))})
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result response
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		return &result
	}
	success := func(t *testing.T, response *response) {
		t.Helper()
		require.Empty(t, response.Errors)
		require.JSONEq(t, `{"updateScheduleTarget": true}`, string(response.Data))
	}
	// Compare complete durable rule rows, including IDs, filters, and times.
	snapshot := func(t *testing.T) string {
		t.Helper()
		var result string
		err := h.App().DB().QueryRow(`
			SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id), '[]'::jsonb)::text
			FROM schedule_rules r
		`).Scan(&result)
		require.NoError(t, err)
		return result
	}
	rotationRuleCount := func(t *testing.T, rotationID string) int {
		t.Helper()
		var count int
		err := h.App().DB().QueryRow(`
			SELECT count(*) FROM schedule_rules WHERE schedule_id = $1 AND tgt_rotation_id = $2
		`, h.UUID("schedule-a"), rotationID).Scan(&count)
		require.NoError(t, err)
		return count
	}

	t.Run("same organization create and update", func(t *testing.T) {
		for _, rules := range []string{`[{}]`, `[{start: "08:00", end: "12:00"}, {start: "13:00", end: "17:00"}]`} {
			success(t, update(t, h.UUID("schedule-a"), "rotation", h.UUID("rotation-a"), rules))
		}
		require.Equal(t, 2, rotationRuleCount(t, h.UUID("rotation-a")))
		var scheduleOrgID, rotationOrgID string
		err := h.App().DB().QueryRow(`
			SELECT DISTINCT s.organization_id, r.organization_id
			FROM schedule_rules sr
			JOIN schedules s ON s.id = sr.schedule_id
			JOIN rotations r ON r.id = sr.tgt_rotation_id
			WHERE s.id = $1
		`, h.UUID("schedule-a")).Scan(&scheduleOrgID, &rotationOrgID)
		require.NoError(t, err)
		require.Equal(t, harness.SmokeOrganizationID, scheduleOrgID)
		require.Equal(t, scheduleOrgID, rotationOrgID)
	})

	t.Run("foreign and missing rotations reject without changing existing rules", func(t *testing.T) {
		before := snapshot(t)
		var foreignResponse *response
		for _, target := range []string{"rotation-b", "rotation-missing"} {
			response := update(t, h.UUID("schedule-a"), "rotation", h.UUID(target), `[{}, {}]`)
			// The mutation returns only a Boolean, so a nested resolver cannot
			// disguise a persisted cross-Organization reference as a rejection.
			require.Len(t, response.Errors, 1)
			require.Equal(t, "does not exist", response.Errors[0].Message)
			require.Equal(t, harness.QLPath("updateScheduleTarget"), response.Errors[0].Path)
			require.Equal(t, map[string]any{"fieldName": "TargetID", "isFieldError": true}, response.Errors[0].Extensions)
			if foreignResponse == nil {
				foreignResponse = response
			} else {
				require.Equal(t, foreignResponse.Errors, response.Errors)
				require.JSONEq(t, string(foreignResponse.Data), string(response.Data))
			}
			require.Equal(t, 0, rotationRuleCount(t, h.UUID(target)))
			require.Equal(t, before, snapshot(t))
		}
	})

	t.Run("schedule authorization precedes target validation and resolution", func(t *testing.T) {
		before := snapshot(t)
		var unavailableResponse *response
		for _, schedule := range []string{"schedule-b", "schedule-missing"} {
			for _, targetID := range []string{h.UUID("rotation-a"), h.UUID("rotation-b"), h.UUID("rotation-missing"), "invalid-uuid"} {
				for _, rules := range []string{`[{}]`, `[]`} {
					response := update(t, h.UUID(schedule), "rotation", targetID, rules)
					require.Len(t, response.Errors, 1)
					require.Equal(t, "schedule not found", response.Errors[0].Message)
					require.Equal(t, map[string]any{"fieldName": "scheduleID", "isFieldError": true}, response.Errors[0].Extensions)
					if unavailableResponse == nil {
						unavailableResponse = response
					} else {
						require.Equal(t, unavailableResponse.Errors, response.Errors)
					}
				}
			}
		}
		require.Equal(t, before, snapshot(t))
	})

	t.Run("existing target type and UUID validation", func(t *testing.T) {
		before := snapshot(t)
		for _, rules := range []string{`[{}]`, `[]`} {
			response := update(t, h.UUID("schedule-a"), "rotation", "invalid-uuid", rules)
			require.Len(t, response.Errors, 1)
			require.Equal(t, "must be valid UUID: format must be xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", response.Errors[0].Message)
			require.Equal(t, map[string]any{"fieldName": "TargetID", "isFieldError": true}, response.Errors[0].Extensions)
			response = update(t, h.UUID("schedule-a"), "schedule", h.UUID("schedule-b"), rules)
			require.Len(t, response.Errors, 1)
			require.Equal(t, "must be one of: TargetTypeUser, TargetTypeRotation", response.Errors[0].Message)
			require.Equal(t, map[string]any{"fieldName": "TargetType", "isFieldError": true}, response.Errors[0].Extensions)
		}
		require.Equal(t, before, snapshot(t))
	})

	t.Run("user targets retain global and current user compatibility", func(t *testing.T) {
		for _, targetID := range []string{h.UUID("user-b"), "__current_user"} {
			success(t, update(t, h.UUID("schedule-a"), "user", targetID, `[{}]`))
		}
		for _, user := range []string{"user-a", "user-b"} {
			var count int
			err := h.App().DB().QueryRow(`
				SELECT count(*) FROM schedule_rules WHERE schedule_id = $1 AND tgt_user_id = $2
			`, h.UUID("schedule-a"), h.UUID(user)).Scan(&count)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		}
	})

	t.Run("API key compatibility and human removal of an unavailable relationship", func(t *testing.T) {
		// Create the cross-Organization relationship through the supported
		// non-human mutation path, then prove that a human can remove it.
		const document = `mutation ScheduleRotationCompatibility($scheduleID: ID!, $rotationID: ID!) {
			updateScheduleTarget(input: {scheduleID: $scheduleID, target: {type: rotation, id: $rotationID}, rules: [{}, {}]})
		}`
		createdResponse := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
			mutation CreateScheduleRotationCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
				createGQLAPIKey(input: {
					name: "schedule-rotation-compatibility"
					description: "schedule rotation compatibility smoke"
					expiresAt: $expires
					role: admin
					query: $query
				}) { token }
			}
		`, "CreateScheduleRotationCompatibilityKey", map[string]any{
			"expires": time.Now().Add(time.Hour).Format(time.RFC3339),
			"query":   document,
		})
		require.Empty(t, createdResponse.Errors)
		var created struct{ CreateGQLAPIKey struct{ Token string } }
		require.NoError(t, json.Unmarshal(createdResponse.Data, &created))
		require.NotEmpty(t, created.CreateGQLAPIKey.Token)
		body, err := json.Marshal(map[string]any{
			"operationName": "ScheduleRotationCompatibility",
			"variables": map[string]string{
				"scheduleID": h.UUID("schedule-a"),
				"rotationID": h.UUID("rotation-b"),
			},
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+created.CreateGQLAPIKey.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result response
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		success(t, &result)
		require.Equal(t, 2, rotationRuleCount(t, h.UUID("rotation-b")))

		before := snapshot(t)
		rejected := update(t, h.UUID("schedule-a"), "rotation", h.UUID("rotation-b"), `[{}]`)
		require.Len(t, rejected.Errors, 1)
		require.Equal(t, "does not exist", rejected.Errors[0].Message)
		require.Equal(t, before, snapshot(t), "retaining even one foreign rule must fail without partial update or deletion")

		success(t, update(t, h.UUID("schedule-a"), "rotation", h.UUID("rotation-b"), `[]`))
		require.Equal(t, 0, rotationRuleCount(t, h.UUID("rotation-b")))
		require.Equal(t, 2, rotationRuleCount(t, h.UUID("rotation-a")))
	})

	t.Run("empty rules remove own target and allow unavailable targets", func(t *testing.T) {
		success(t, update(t, h.UUID("schedule-a"), "rotation", h.UUID("rotation-a"), `[]`))
		require.Equal(t, 0, rotationRuleCount(t, h.UUID("rotation-a")))
		before := snapshot(t)
		for _, target := range []string{"rotation-a", "rotation-b", "rotation-missing"} {
			success(t, update(t, h.UUID("schedule-a"), "rotation", h.UUID(target), `[]`))
		}
		require.Equal(t, before, snapshot(t))
	})
}
