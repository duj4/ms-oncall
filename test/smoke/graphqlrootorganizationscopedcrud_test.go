package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

const scopedRootCRUDSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "scoped-org-b"}}, 'NORMAL', 'Scoped Organization B', 'scoped.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "scoped-org-b"}}, 'NORMAL', 'scoped:organization-b', 'Etc/UTC');

INSERT INTO users (id, name, email, role)
VALUES ({{uuid "scoped-user-b"}}, 'Scoped Organization B User', '', 'admin');
INSERT INTO user_organization_assignments (
    user_id, effective_organization_id, effective_organization_classification,
    effective_normal_organization_id, organization_role, mapping_outcome,
    authoritative_evaluated_at, source_config_version, matched_count
) VALUES (
    {{uuid "scoped-user-b"}}, {{uuid "scoped-org-b"}}, 'NORMAL',
    {{uuid "scoped-org-b"}}, 'ORG_ADMIN', 'EXACTLY_ONE', now(), 'scoped-smoke-v1', 1
);

INSERT INTO escalation_policies (id, organization_id, name, description, repeat)
VALUES
    ({{uuid "policy-a1"}}, {{smokeOrganizationID}}, 'Human Scoped Policy 01', 'policy a1', 1),
    ({{uuid "policy-b1"}}, {{uuid "scoped-org-b"}}, 'Human Scoped Policy 02', 'policy b1', 1),
    ({{uuid "policy-a2"}}, {{smokeOrganizationID}}, 'Human Scoped Policy 03', 'policy a2', 1),
    ({{uuid "policy-delete-a"}}, {{smokeOrganizationID}}, 'Policy Delete Own', '', 1),
    ({{uuid "policy-delete-b"}}, {{uuid "scoped-org-b"}}, 'Policy Delete Cross', '', 1),
    ({{uuid "policy-mixed-a"}}, {{smokeOrganizationID}}, 'Policy Mixed Own', '', 1),
    ({{uuid "policy-mixed-b"}}, {{uuid "scoped-org-b"}}, 'Policy Mixed Cross', '', 1);

INSERT INTO services (id, organization_id, name, description, escalation_policy_id)
VALUES
    ({{uuid "service-a1"}}, {{smokeOrganizationID}}, 'Human Scoped Service 01', 'service a1', {{uuid "policy-a1"}}),
    ({{uuid "service-b1"}}, {{uuid "scoped-org-b"}}, 'Human Scoped Service 02', 'service b1', {{uuid "policy-b1"}}),
    ({{uuid "service-a2"}}, {{smokeOrganizationID}}, 'Human Scoped Service 03', 'service a2', {{uuid "policy-b1"}}),
    ({{uuid "service-delete-a"}}, {{smokeOrganizationID}}, 'Service Delete Own', '', {{uuid "policy-a1"}}),
    ({{uuid "service-delete-b"}}, {{uuid "scoped-org-b"}}, 'Service Delete Cross', '', {{uuid "policy-b1"}}),
    ({{uuid "service-mixed-a"}}, {{smokeOrganizationID}}, 'Service Mixed Own', '', {{uuid "policy-a1"}}),
    ({{uuid "service-mixed-b"}}, {{uuid "scoped-org-b"}}, 'Service Mixed Cross', '', {{uuid "policy-b1"}});

INSERT INTO schedules (id, organization_id, name, description, time_zone)
VALUES
    ({{uuid "schedule-a1"}}, {{smokeOrganizationID}}, 'Human Scoped Schedule 01', 'schedule a1', 'Etc/UTC'),
    ({{uuid "schedule-b1"}}, {{uuid "scoped-org-b"}}, 'Human Scoped Schedule 02', 'schedule b1', 'Etc/UTC'),
    ({{uuid "schedule-a2"}}, {{smokeOrganizationID}}, 'Human Scoped Schedule 03', 'schedule a2', 'Etc/UTC'),
    ({{uuid "schedule-delete-a"}}, {{smokeOrganizationID}}, 'Schedule Delete Own', '', 'Etc/UTC'),
    ({{uuid "schedule-delete-b"}}, {{uuid "scoped-org-b"}}, 'Schedule Delete Cross', '', 'Etc/UTC'),
    ({{uuid "schedule-mixed-a"}}, {{smokeOrganizationID}}, 'Schedule Mixed Own', '', 'Etc/UTC'),
    ({{uuid "schedule-mixed-b"}}, {{uuid "scoped-org-b"}}, 'Schedule Mixed Cross', '', 'Etc/UTC');

INSERT INTO rotations (id, organization_id, name, description, type, start_time, shift_length, time_zone)
VALUES
    ({{uuid "rotation-a1"}}, {{smokeOrganizationID}}, 'Human Scoped Rotation 01', 'rotation a1', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-b1"}}, {{uuid "scoped-org-b"}}, 'Human Scoped Rotation 02', 'rotation b1', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-a2"}}, {{smokeOrganizationID}}, 'Human Scoped Rotation 03', 'rotation a2', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-delete-a"}}, {{smokeOrganizationID}}, 'Rotation Delete Own', '', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-delete-b"}}, {{uuid "scoped-org-b"}}, 'Rotation Delete Cross', '', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-mixed-a"}}, {{smokeOrganizationID}}, 'Rotation Mixed Own', '', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC'),
    ({{uuid "rotation-mixed-b"}}, {{uuid "scoped-org-b"}}, 'Rotation Mixed Cross', '', 'daily', '2026-09-10T00:00:00Z', 1, 'Etc/UTC');

INSERT INTO schedule_rules (schedule_id, tgt_rotation_id)
VALUES ({{uuid "schedule-a1"}}, {{uuid "rotation-a1"}});

INSERT INTO escalation_policy_steps (id, escalation_policy_id, delay)
VALUES ({{uuid "policy-a1-step"}}, {{uuid "policy-a1"}}, 0);
INSERT INTO escalation_policy_actions (escalation_policy_step_id, schedule_id, rotation_id)
VALUES
    ({{uuid "policy-a1-step"}}, {{uuid "schedule-a1"}}, NULL),
    ({{uuid "policy-a1-step"}}, NULL, {{uuid "rotation-a1"}});
`

type scopedSmokeRootConnection struct {
	Nodes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"nodes"`
	PageInfo struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
}

func scopedSmokeConnection(t *testing.T, h *harness.Harness, field, input string) scopedSmokeRootConnection {
	t.Helper()
	response := h.GraphQLQueryT(t, fmt.Sprintf(`query { result: %s(input: {%s}) { nodes { id name } pageInfo { hasNextPage endCursor } } }`, field, input))
	require.Empty(t, response.Errors)
	var envelope struct {
		Result scopedSmokeRootConnection `json:"result"`
	}
	require.NoError(t, json.Unmarshal(response.Data, &envelope))
	return envelope.Result
}

func requireScopedSmokeIDs(t *testing.T, connection scopedSmokeRootConnection, want ...string) {
	t.Helper()
	got := make([]string, 0, len(connection.Nodes))
	for _, node := range connection.Nodes {
		got = append(got, node.ID)
	}
	sort.Strings(got)
	sort.Strings(want)
	require.Equal(t, want, got)
}

func scopedSmokeQueryExpectNoRows(t *testing.T, h *harness.Harness, query string) *harness.QLResponse {
	t.Helper()
	wait := h.ExpectBackendError("sql: no rows in result set")
	response := h.GraphQLQueryT(t, query)
	wait()
	return response
}

func TestGraphQLRootOrganizationScopedHumanCRUD(t *testing.T) {
	h := harness.NewHarness(t, scopedRootCRUDSQL, "")
	defer h.Close()

	// Ensure the canonical Org A human exists before adding global-user schedule
	// assignments that deliberately span both root Organizations.
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	_, err := h.App().DB().Exec(`
		INSERT INTO schedule_rules (schedule_id, tgt_user_id)
		VALUES ($1, $2), ($3, $2)
	`, h.UUID("schedule-a1"), harness.DefaultGraphQLAdminUserID, h.UUID("schedule-b1"))
	require.NoError(t, err)

	t.Run("direct batch and alternate materialization", func(t *testing.T) {
		response := h.GraphQLQueryT(t, fmt.Sprintf(`
			query {
				serviceOwn: service(id: %q) { id name escalationPolicy { id name } }
				serviceCross: service(id: %q) { id name }
				serviceNestedCross: service(id: %q) { id escalationPolicy { id name } }
				scheduleOwn: schedule(id: %q) {
					id name
					targets { target { id type name } }
					assignedTo { id type name }
				}
				scheduleCross: schedule(id: %q) { id name }
				rotationOwn: rotation(id: %q) { id name }
				rotationCross: rotation(id: %q) { id name }
				policyOwn: escalationPolicy(id: %q) {
					id name
					assignedTo { id type name }
					steps {
						actions {
							displayInfo {
								__typename
								... on DestinationDisplayInfo { text }
							}
						}
					}
				}
				policyCross: escalationPolicy(id: %q) { id name }
				user { assignedSchedules { id name } }
			}
		`,
			h.UUID("service-a1"), h.UUID("service-b1"), h.UUID("service-a2"),
			h.UUID("schedule-a1"), h.UUID("schedule-b1"),
			h.UUID("rotation-a1"), h.UUID("rotation-b1"),
			h.UUID("policy-a1"), h.UUID("policy-b1"),
		))
		require.Empty(t, response.Errors)

		var result struct {
			ServiceOwn *struct {
				ID               string
				EscalationPolicy *struct{ ID, Name string }
			}
			ServiceCross       *struct{ ID string }
			ServiceNestedCross *struct {
				ID               string
				EscalationPolicy *struct{ ID string }
			}
			ScheduleOwn *struct {
				ID      string
				Targets []struct {
					Target struct{ ID, Type, Name string }
				}
				AssignedTo []struct{ ID, Type, Name string }
			}
			ScheduleCross *struct{ ID string }
			RotationOwn   *struct{ ID string }
			RotationCross *struct{ ID string }
			PolicyOwn     *struct {
				ID         string
				AssignedTo []struct{ ID, Type, Name string }
				Steps      []struct {
					Actions []struct {
						DisplayInfo struct {
							TypeName string `json:"__typename"`
							Text     string `json:"text"`
						} `json:"displayInfo"`
					}
				}
			}
			PolicyCross *struct{ ID string }
			User        *struct {
				AssignedSchedules []struct{ ID, Name string }
			}
		}
		require.NoError(t, json.Unmarshal(response.Data, &result))
		require.Equal(t, h.UUID("service-a1"), result.ServiceOwn.ID)
		require.Equal(t, h.UUID("policy-a1"), result.ServiceOwn.EscalationPolicy.ID)
		require.Nil(t, result.ServiceCross)
		require.Equal(t, h.UUID("service-a2"), result.ServiceNestedCross.ID)
		require.Nil(t, result.ServiceNestedCross.EscalationPolicy)
		require.Equal(t, h.UUID("schedule-a1"), result.ScheduleOwn.ID)
		require.Nil(t, result.ScheduleCross)
		require.Equal(t, h.UUID("rotation-a1"), result.RotationOwn.ID)
		require.Nil(t, result.RotationCross)
		require.Equal(t, h.UUID("policy-a1"), result.PolicyOwn.ID)
		require.Nil(t, result.PolicyCross)

		var rotationTargetFound bool
		for _, target := range result.ScheduleOwn.Targets {
			if target.Target.ID == h.UUID("rotation-a1") {
				rotationTargetFound = true
				require.Equal(t, "Human Scoped Rotation 01", target.Target.Name)
			}
		}
		require.True(t, rotationTargetFound, "Schedule Target.Name did not materialize the own-Organization rotation")
		require.Contains(t, result.ScheduleOwn.AssignedTo, struct{ ID, Type, Name string }{ID: h.UUID("policy-a1"), Type: "escalationPolicy", Name: "Human Scoped Policy 01"})

		assignedIDs := make([]string, 0, len(result.User.AssignedSchedules))
		for _, sched := range result.User.AssignedSchedules {
			assignedIDs = append(assignedIDs, sched.ID)
		}
		require.Equal(t, []string{h.UUID("schedule-a1")}, assignedIDs)

		var actionTexts []string
		for _, step := range result.PolicyOwn.Steps {
			for _, action := range step.Actions {
				actionTexts = append(actionTexts, action.DisplayInfo.Text)
			}
		}
		sort.Strings(actionTexts)
		require.Equal(t, []string{"Human Scoped Rotation 01", "Human Scoped Schedule 01"}, actionTexts)
	})

	roots := []struct {
		name, field, targetType, prefix string
		ownFirst, crossMiddle, ownLast  string
	}{
		{name: "service", field: "services", targetType: "service", prefix: "Human Scoped Service", ownFirst: h.UUID("service-a1"), crossMiddle: h.UUID("service-b1"), ownLast: h.UUID("service-a2")},
		{name: "schedule", field: "schedules", targetType: "schedule", prefix: "Human Scoped Schedule", ownFirst: h.UUID("schedule-a1"), crossMiddle: h.UUID("schedule-b1"), ownLast: h.UUID("schedule-a2")},
		{name: "rotation", field: "rotations", targetType: "rotation", prefix: "Human Scoped Rotation", ownFirst: h.UUID("rotation-a1"), crossMiddle: h.UUID("rotation-b1"), ownLast: h.UUID("rotation-a2")},
		{name: "policy", field: "escalationPolicies", targetType: "escalationPolicy", prefix: "Human Scoped Policy", ownFirst: h.UUID("policy-a1"), crossMiddle: h.UUID("policy-b1"), ownLast: h.UUID("policy-a2")},
	}

	t.Run("search pagination only omit and favorites", func(t *testing.T) {
		for _, root := range roots {
			t.Run(root.name, func(t *testing.T) {
				favoriteResponse := h.GraphQLQueryT(t, fmt.Sprintf(`mutation {
					own: setFavorite(input: {target: {id: %q, type: %s}, favorite: true})
					cross: setFavorite(input: {target: {id: %q, type: %s}, favorite: true})
				}`, root.ownLast, root.targetType, root.crossMiddle, root.targetType))
				require.Empty(t, favoriteResponse.Errors)

				all := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 10", root.prefix))
				requireScopedSmokeIDs(t, all, root.ownFirst, root.ownLast)

				pageOne := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 1", root.prefix))
				requireScopedSmokeIDs(t, pageOne, root.ownFirst)
				require.True(t, pageOne.PageInfo.HasNextPage)
				require.NotEmpty(t, pageOne.PageInfo.EndCursor)
				pageTwo := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 1, after: %s", root.prefix, strconv.Quote(pageOne.PageInfo.EndCursor)))
				requireScopedSmokeIDs(t, pageTwo, root.ownLast)

				omit := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 10, omit: [%q, %q]", root.prefix, root.ownFirst, root.crossMiddle))
				requireScopedSmokeIDs(t, omit, root.ownLast)

				favorites := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 10, favoritesOnly: true, favoritesFirst: true", root.prefix))
				requireScopedSmokeIDs(t, favorites, root.ownLast)

				if root.name == "service" {
					only := scopedSmokeConnection(t, h, root.field, fmt.Sprintf("search: %q, first: 10, only: [%q, %q]", root.prefix, root.ownLast, root.crossMiddle))
					requireScopedSmokeIDs(t, only, root.ownLast)
				}
			})
		}
	})

	t.Run("update scopes lock and final write", func(t *testing.T) {
		updates := []struct {
			name, mutation, table, ownID, crossID, ownName, crossName string
			expectNoRowsLog                                           bool
		}{
			{name: "service", mutation: "updateService", table: "services", ownID: h.UUID("service-a1"), crossID: h.UUID("service-b1"), ownName: "Human Scoped Service 01 Updated", crossName: "Human Scoped Service 02", expectNoRowsLog: true},
			{name: "schedule", mutation: "updateSchedule", table: "schedules", ownID: h.UUID("schedule-a1"), crossID: h.UUID("schedule-b1"), ownName: "Human Scoped Schedule 01 Updated", crossName: "Human Scoped Schedule 02"},
			{name: "rotation", mutation: "updateRotation", table: "rotations", ownID: h.UUID("rotation-a1"), crossID: h.UUID("rotation-b1"), ownName: "Human Scoped Rotation 01 Updated", crossName: "Human Scoped Rotation 02"},
			{name: "policy", mutation: "updateEscalationPolicy", table: "escalation_policies", ownID: h.UUID("policy-a1"), crossID: h.UUID("policy-b1"), ownName: "Human Scoped Policy 01 Updated", crossName: "Human Scoped Policy 02", expectNoRowsLog: true},
		}
		for _, update := range updates {
			t.Run(update.name, func(t *testing.T) {
				ownResponse := h.GraphQLQueryT(t, fmt.Sprintf(`mutation { result: %s(input: {id: %q, name: %q}) }`, update.mutation, update.ownID, update.ownName))
				require.Empty(t, ownResponse.Errors)
				crossQuery := fmt.Sprintf(`mutation { result: %s(input: {id: %q, name: %q}) }`, update.mutation, update.crossID, update.crossName+" Mutated")
				var crossResponse *harness.QLResponse
				if update.expectNoRowsLog {
					crossResponse = scopedSmokeQueryExpectNoRows(t, h, crossQuery)
				} else {
					crossResponse = h.GraphQLQueryT(t, crossQuery)
				}
				require.NotEmpty(t, crossResponse.Errors)

				for _, check := range []struct {
					id, name, organizationID string
				}{
					{id: update.ownID, name: update.ownName, organizationID: harness.SmokeOrganizationID},
					{id: update.crossID, name: update.crossName, organizationID: h.UUID("scoped-org-b")},
				} {
					var name string
					var organizationID uuid.UUID
					err := h.App().DB().QueryRow("SELECT name, organization_id FROM "+update.table+" WHERE id = $1", check.id).Scan(&name, &organizationID)
					require.NoError(t, err)
					require.Equal(t, check.name, name)
					require.Equal(t, uuid.MustParse(check.organizationID), organizationID)
				}
			})
		}
	})

	t.Run("delete is scoped and mixed batches are atomic", func(t *testing.T) {
		deletes := []struct {
			name, targetType, table, ownID, crossID, mixedOwnID, mixedCrossID string
		}{
			{name: "service", targetType: "service", table: "services", ownID: h.UUID("service-delete-a"), crossID: h.UUID("service-delete-b"), mixedOwnID: h.UUID("service-mixed-a"), mixedCrossID: h.UUID("service-mixed-b")},
			{name: "schedule", targetType: "schedule", table: "schedules", ownID: h.UUID("schedule-delete-a"), crossID: h.UUID("schedule-delete-b"), mixedOwnID: h.UUID("schedule-mixed-a"), mixedCrossID: h.UUID("schedule-mixed-b")},
			{name: "rotation", targetType: "rotation", table: "rotations", ownID: h.UUID("rotation-delete-a"), crossID: h.UUID("rotation-delete-b"), mixedOwnID: h.UUID("rotation-mixed-a"), mixedCrossID: h.UUID("rotation-mixed-b")},
			{name: "policy", targetType: "escalationPolicy", table: "escalation_policies", ownID: h.UUID("policy-delete-a"), crossID: h.UUID("policy-delete-b"), mixedOwnID: h.UUID("policy-mixed-a"), mixedCrossID: h.UUID("policy-mixed-b")},
		}
		for _, deletion := range deletes {
			t.Run(deletion.name, func(t *testing.T) {
				crossResponse := scopedSmokeQueryExpectNoRows(t, h, fmt.Sprintf(`mutation { deleteAll(input: [{id: %q, type: %s}]) }`, deletion.crossID, deletion.targetType))
				require.NotEmpty(t, crossResponse.Errors)
				require.Equal(t, 1, scopedSmokeRowCount(t, h, deletion.table, deletion.crossID))

				mixedResponse := scopedSmokeQueryExpectNoRows(t, h, fmt.Sprintf(`mutation { deleteAll(input: [{id: %q, type: %s}, {id: %q, type: %s}]) }`, deletion.mixedOwnID, deletion.targetType, deletion.mixedCrossID, deletion.targetType))
				require.NotEmpty(t, mixedResponse.Errors)
				require.Equal(t, 1, scopedSmokeRowCount(t, h, deletion.table, deletion.mixedOwnID))
				require.Equal(t, 1, scopedSmokeRowCount(t, h, deletion.table, deletion.mixedCrossID))

				ownResponse := h.GraphQLQueryT(t, fmt.Sprintf(`mutation { deleteAll(input: [{id: %q, type: %s}]) }`, deletion.ownID, deletion.targetType))
				require.Empty(t, ownResponse.Errors)
				require.Zero(t, scopedSmokeRowCount(t, h, deletion.table, deletion.ownID))
			})
		}
	})

	t.Run("GraphQL-local schedule and rotation destination adapter", func(t *testing.T) {
		response := h.GraphQLQueryT(t, fmt.Sprintf(`query {
			scheduleSearch: destinationFieldSearch(input: {destType: "builtin-schedule", fieldID: "schedule_id", search: "Human Scoped Schedule", first: 10}) { nodes { value label } }
			rotationSearch: destinationFieldSearch(input: {destType: "builtin-rotation", fieldID: "rotation_id", search: "Human Scoped Rotation", first: 10}) { nodes { value label } }
			scheduleName: destinationFieldValueName(input: {destType: "builtin-schedule", fieldID: "schedule_id", value: %q})
			rotationName: destinationFieldValueName(input: {destType: "builtin-rotation", fieldID: "rotation_id", value: %q})
			scheduleDisplay: destinationDisplayInfo(input: {type: "builtin-schedule", args: {schedule_id: %q}}) { text }
			rotationDisplay: destinationDisplayInfo(input: {type: "builtin-rotation", args: {rotation_id: %q}}) { text }
		}`, h.UUID("schedule-a1"), h.UUID("rotation-a1"), h.UUID("schedule-a1"), h.UUID("rotation-a1")))
		require.Empty(t, response.Errors)
		var result struct {
			ScheduleSearch struct {
				Nodes []struct{ Value, Label string }
			}
			RotationSearch struct {
				Nodes []struct{ Value, Label string }
			}
			ScheduleName    string
			RotationName    string
			ScheduleDisplay struct{ Text string }
			RotationDisplay struct{ Text string }
		}
		require.NoError(t, json.Unmarshal(response.Data, &result))
		require.Equal(t, "Human Scoped Schedule 01 Updated", result.ScheduleName)
		require.Equal(t, result.ScheduleName, result.ScheduleDisplay.Text)
		require.Equal(t, "Human Scoped Rotation 01 Updated", result.RotationName)
		require.Equal(t, result.RotationName, result.RotationDisplay.Text)
		for _, node := range result.ScheduleSearch.Nodes {
			require.NotEqual(t, h.UUID("schedule-b1"), node.Value)
		}
		for _, node := range result.RotationSearch.Nodes {
			require.NotEqual(t, h.UUID("rotation-b1"), node.Value)
		}
		require.Len(t, result.ScheduleSearch.Nodes, 2)
		require.Len(t, result.RotationSearch.Nodes, 2)

		for _, crossQuery := range []struct {
			name            string
			query           string
			expectNoRowsLog bool
		}{
			{name: "schedule field value", query: fmt.Sprintf(`query { destinationFieldValueName(input: {destType: "builtin-schedule", fieldID: "schedule_id", value: %q}) }`, h.UUID("schedule-b1")), expectNoRowsLog: true},
			{name: "schedule display info", query: fmt.Sprintf(`query { destinationDisplayInfo(input: {type: "builtin-schedule", args: {schedule_id: %q}}) { text } }`, h.UUID("schedule-b1"))},
			{name: "rotation field value", query: fmt.Sprintf(`query { destinationFieldValueName(input: {destType: "builtin-rotation", fieldID: "rotation_id", value: %q}) }`, h.UUID("rotation-b1")), expectNoRowsLog: true},
			{name: "rotation display info", query: fmt.Sprintf(`query { destinationDisplayInfo(input: {type: "builtin-rotation", args: {rotation_id: %q}}) { text } }`, h.UUID("rotation-b1"))},
		} {
			t.Run(crossQuery.name, func(t *testing.T) {
				var crossResponse *harness.QLResponse
				if crossQuery.expectNoRowsLog {
					crossResponse = scopedSmokeQueryExpectNoRows(t, h, crossQuery.query)
				} else {
					crossResponse = h.GraphQLQueryT(t, crossQuery.query)
				}
				require.NotEmpty(t, crossResponse.Errors)
			})
		}
	})

	t.Run("GQL API key retains unscoped compatibility", func(t *testing.T) {
		const queryDocument = `
			query RootCompatibility($serviceID: ID!, $scheduleID: ID!, $rotationID: ID!, $policyID: ID!) {
				serviceValue: service(id: $serviceID) { id }
				scheduleValue: schedule(id: $scheduleID) { id }
				rotationValue: rotation(id: $rotationID) { id }
				policyValue: escalationPolicy(id: $policyID) { id }
			}
		`
		createResponse := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
			mutation CreateCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
				createGQLAPIKey(input: {
					name: "root-scope-compatibility"
					description: "root scope compatibility smoke"
					expiresAt: $expires
					role: admin
					query: $query
				}) { token }
			}
		`, "CreateCompatibilityKey", map[string]any{
			"expires": time.Now().Add(time.Hour).Format(time.RFC3339),
			"query":   queryDocument,
		})
		require.Empty(t, createResponse.Errors)
		var created struct {
			CreateGQLAPIKey struct{ Token string }
		}
		require.NoError(t, json.Unmarshal(createResponse.Data, &created))
		require.NotEmpty(t, created.CreateGQLAPIKey.Token)

		requestBody, err := json.Marshal(map[string]any{
			"operationName": "RootCompatibility",
			"variables": map[string]string{
				"serviceID":  h.UUID("service-b1"),
				"scheduleID": h.UUID("schedule-b1"),
				"rotationID": h.UUID("rotation-b1"),
				"policyID":   h.UUID("policy-b1"),
			},
		})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(requestBody))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+created.CreateGQLAPIKey.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Data struct {
				ServiceValue  *struct{ ID string }
				ScheduleValue *struct{ ID string }
				RotationValue *struct{ ID string }
				PolicyValue   *struct{ ID string }
			}
			Errors []struct{ Message string }
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		require.Empty(t, result.Errors)
		require.Equal(t, h.UUID("service-b1"), result.Data.ServiceValue.ID)
		require.Equal(t, h.UUID("schedule-b1"), result.Data.ScheduleValue.ID)
		require.Equal(t, h.UUID("rotation-b1"), result.Data.RotationValue.ID)
		require.Equal(t, h.UUID("policy-b1"), result.Data.PolicyValue.ID)
	})
}

type scopedSmokeOnCallOverview struct {
	ServiceCount       int `json:"serviceCount"`
	ServiceAssignments []struct {
		StepNumber           int    `json:"stepNumber"`
		EscalationPolicyID   string `json:"escalationPolicyID"`
		EscalationPolicyName string `json:"escalationPolicyName"`
		ServiceID            string `json:"serviceID"`
		ServiceName          string `json:"serviceName"`
	} `json:"serviceAssignments"`
}

func TestGraphQLUserOnCallOverviewOrganizationScoped(t *testing.T) {
	h := harness.NewHarness(t, scopedRootCRUDSQL, "")
	defer h.Close()

	// Materialize the canonical Org A human before using it in a direct-user
	// escalation action. Direct-user actions are stable source data from which
	// the Escalation Manager derives the current on-call table.
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	_, err := h.App().DB().Exec(`
		INSERT INTO escalation_policy_steps (id, escalation_policy_id, delay)
		VALUES ($1, $2, 0)
	`, h.UUID("policy-b1-step"), h.UUID("policy-b1"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`
		INSERT INTO escalation_policy_actions (escalation_policy_step_id, user_id)
		VALUES ($1, $2), ($3, $4)
	`, h.UUID("policy-a1-step"), harness.DefaultGraphQLAdminUserID, h.UUID("policy-b1-step"), h.UUID("scoped-user-b"))
	require.NoError(t, err)

	assertCurrentOnCall := func() {
		t.Helper()
		var orgACount, orgBCount int
		err := h.App().DB().QueryRow(`
			SELECT
				count(*) FILTER (WHERE ep_step_id = $1 AND user_id = $2),
				count(*) FILTER (WHERE ep_step_id = $3 AND user_id = $4)
			FROM ep_step_on_call_users
			WHERE end_time IS NULL
		`, h.UUID("policy-a1-step"), harness.DefaultGraphQLAdminUserID, h.UUID("policy-b1-step"), h.UUID("scoped-user-b")).Scan(&orgACount, &orgBCount)
		require.NoError(t, err)
		require.Equal(t, 1, orgACount, "Org A source assignment must remain active")
		require.Equal(t, 1, orgBCount, "Org B source assignment must remain active")
	}
	h.Trigger()
	assertCurrentOnCall()

	humanResponse := h.GraphQLQueryT(t, fmt.Sprintf(`
		query {
			sameUser: user(id: %q) {
				onCallOverview {
					serviceCount
					serviceAssignments { stepNumber escalationPolicyID escalationPolicyName serviceID serviceName }
				}
			}
			crossUser: user(id: %q) {
				onCallOverview {
					serviceCount
					serviceAssignments { stepNumber escalationPolicyID escalationPolicyName serviceID serviceName }
				}
			}
			ownService: service(id: %q) { id name }
			ownPolicy: escalationPolicy(id: %q) { id name }
			crossService: service(id: %q) { id name }
			crossPolicy: escalationPolicy(id: %q) { id name }
		}
	`, harness.DefaultGraphQLAdminUserID, h.UUID("scoped-user-b"), h.UUID("service-a1"), h.UUID("policy-a1"), h.UUID("service-b1"), h.UUID("policy-b1")))
	require.Empty(t, humanResponse.Errors)
	var humanResult struct {
		SameUser struct {
			OnCallOverview scopedSmokeOnCallOverview `json:"onCallOverview"`
		} `json:"sameUser"`
		CrossUser struct {
			OnCallOverview scopedSmokeOnCallOverview `json:"onCallOverview"`
		} `json:"crossUser"`
		OwnService   *struct{ ID, Name string } `json:"ownService"`
		OwnPolicy    *struct{ ID, Name string } `json:"ownPolicy"`
		CrossService *struct{ ID, Name string } `json:"crossService"`
		CrossPolicy  *struct{ ID, Name string } `json:"crossPolicy"`
	}
	require.NoError(t, json.Unmarshal(humanResponse.Data, &humanResult))
	require.NotNil(t, humanResult.OwnService)
	require.Equal(t, h.UUID("service-a1"), humanResult.OwnService.ID)
	require.NotNil(t, humanResult.OwnPolicy)
	require.Equal(t, h.UUID("policy-a1"), humanResult.OwnPolicy.ID)
	require.Nil(t, humanResult.CrossService)
	require.Nil(t, humanResult.CrossPolicy)

	require.Equal(t, 3, humanResult.SameUser.OnCallOverview.ServiceCount)
	sameOrgServiceIDs := make([]string, 0, len(humanResult.SameUser.OnCallOverview.ServiceAssignments))
	for _, assignment := range humanResult.SameUser.OnCallOverview.ServiceAssignments {
		sameOrgServiceIDs = append(sameOrgServiceIDs, assignment.ServiceID)
		require.Equal(t, h.UUID("policy-a1"), assignment.EscalationPolicyID)
		require.Equal(t, "Human Scoped Policy 01", assignment.EscalationPolicyName)
	}
	require.ElementsMatch(t, []string{h.UUID("service-a1"), h.UUID("service-delete-a"), h.UUID("service-mixed-a")}, sameOrgServiceIDs)
	require.Zero(t, humanResult.CrossUser.OnCallOverview.ServiceCount)
	require.Empty(t, humanResult.CrossUser.OnCallOverview.ServiceAssignments)
	assertCurrentOnCall()

	const queryDocument = `
		query OnCallCompatibility($userID: ID!) {
			user(id: $userID) {
				onCallOverview {
					serviceCount
					serviceAssignments { stepNumber escalationPolicyID escalationPolicyName serviceID serviceName }
				}
			}
		}
	`
	createResponse := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
		mutation CreateOnCallCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
			createGQLAPIKey(input: {
				name: "on-call-overview-scope-compatibility"
				description: "on-call overview scope compatibility smoke"
				expiresAt: $expires
				role: admin
				query: $query
			}) { token }
		}
	`, "CreateOnCallCompatibilityKey", map[string]any{
		"expires": time.Now().Add(time.Hour).Format(time.RFC3339),
		"query":   queryDocument,
	})
	require.Empty(t, createResponse.Errors)
	var created struct {
		CreateGQLAPIKey struct{ Token string }
	}
	require.NoError(t, json.Unmarshal(createResponse.Data, &created))
	require.NotEmpty(t, created.CreateGQLAPIKey.Token)

	requestBody, err := json.Marshal(map[string]any{
		"operationName": "OnCallCompatibility",
		"variables":     map[string]string{"userID": h.UUID("scoped-user-b")},
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(requestBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+created.CreateGQLAPIKey.Token)
	req.Header.Set("Content-Type", "application/json")
	h.Trigger()
	assertCurrentOnCall()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var compatibilityResult struct {
		Data struct {
			User struct {
				OnCallOverview scopedSmokeOnCallOverview `json:"onCallOverview"`
			} `json:"user"`
		} `json:"data"`
		Errors []struct{ Message string } `json:"errors"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&compatibilityResult))
	require.Empty(t, compatibilityResult.Errors)
	require.Equal(t, 4, compatibilityResult.Data.User.OnCallOverview.ServiceCount)
	nonHumanServiceIDs := make([]string, 0, len(compatibilityResult.Data.User.OnCallOverview.ServiceAssignments))
	for _, assignment := range compatibilityResult.Data.User.OnCallOverview.ServiceAssignments {
		nonHumanServiceIDs = append(nonHumanServiceIDs, assignment.ServiceID)
		require.Equal(t, h.UUID("policy-b1"), assignment.EscalationPolicyID)
	}
	require.ElementsMatch(t, []string{
		h.UUID("service-a2"),
		h.UUID("service-b1"),
		h.UUID("service-delete-b"),
		h.UUID("service-mixed-b"),
	}, nonHumanServiceIDs)
	assertCurrentOnCall()
}

type scopedSmokeMessageLogNode struct {
	ID          string  `json:"id"`
	ServiceID   *string `json:"serviceID"`
	ServiceName *string `json:"serviceName"`
}

type scopedSmokeMessageLogConnection struct {
	Nodes    []scopedSmokeMessageLogNode `json:"nodes"`
	PageInfo struct {
		HasNextPage bool `json:"hasNextPage"`
	} `json:"pageInfo"`
	Stats struct {
		TimeSeries []struct {
			Value float64 `json:"value"`
		} `json:"timeSeries"`
	} `json:"stats"`
}

func requireScopedSmokeMessageLogIDs(t *testing.T, nodes []scopedSmokeMessageLogNode, want ...string) {
	t.Helper()
	got := make([]string, 0, len(nodes))
	for _, node := range nodes {
		got = append(got, node.ID)
	}
	require.Equal(t, want, got)
}

func requireScopedSmokeMessageLogNodes(t *testing.T, nodes []scopedSmokeMessageLogNode, h *harness.Harness, crossServiceVisible bool) {
	t.Helper()

	byID := make(map[string]scopedSmokeMessageLogNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}
	require.Len(t, byID, 3)

	own := byID[h.UUID("message-log-own")]
	require.NotNil(t, own.ServiceID)
	require.Equal(t, h.UUID("service-a1"), *own.ServiceID)
	require.NotNil(t, own.ServiceName)
	require.Equal(t, "Human Scoped Service 01", *own.ServiceName)

	cross := byID[h.UUID("message-log-cross")]
	if crossServiceVisible {
		require.NotNil(t, cross.ServiceID)
		require.Equal(t, h.UUID("service-b1"), *cross.ServiceID)
		require.NotNil(t, cross.ServiceName)
		require.Equal(t, "Human Scoped Service 02", *cross.ServiceName)
	} else {
		require.Nil(t, cross.ServiceID)
		require.Nil(t, cross.ServiceName)
	}

	withoutService := byID[h.UUID("message-log-without-service")]
	require.Nil(t, withoutService.ServiceID)
	require.Nil(t, withoutService.ServiceName)
}

func TestGraphQLMessageLogsOrganizationScoped(t *testing.T) {
	h := harness.NewHarness(t, scopedRootCRUDSQL, "")
	defer h.Close()

	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	_, err := h.App().DB().Exec(`
		INSERT INTO user_contact_methods (id, user_id, name, type, value, disabled)
		VALUES
			($1, $2, 'Scoped service message-log destination', 'EMAIL', 'scoped-service-message-log@example.invalid', false),
			($3, $2, 'No-Service message-log destination', 'EMAIL', 'no-service-message-log@example.invalid', false)
	`, h.UUID("message-log-contact-method"), harness.DefaultGraphQLAdminUserID, h.UUID("message-log-no-service-contact-method"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`
		INSERT INTO outgoing_messages (
			id, message_type, created_at, sent_at, contact_method_id, last_status, user_id, service_id
		) VALUES
			($1, 'test_notification', '2026-09-10 00:01:00Z', '2026-09-10 00:01:01Z', $2, 'delivered', $3, $4),
			($5, 'test_notification', '2026-09-10 00:02:00Z', '2026-09-10 00:02:01Z', $2, 'delivered', $3, $6),
			($7, 'test_notification', '2026-09-10 00:03:00Z', '2026-09-10 00:03:01Z', $8, 'delivered', $3, NULL)
	`,
		h.UUID("message-log-own"), h.UUID("message-log-contact-method"),
		harness.DefaultGraphQLAdminUserID, h.UUID("service-a1"),
		h.UUID("message-log-cross"), h.UUID("service-b1"),
		h.UUID("message-log-without-service"), h.UUID("message-log-no-service-contact-method"),
	)
	require.NoError(t, err)

	humanResponse := h.GraphQLQueryT(t, fmt.Sprintf(`
		query {
			ownService: service(id: %q) { id name }
			crossService: service(id: %q) { id name }
			messageLogs(input: {first: 10}) {
				nodes { id serviceID serviceName }
				pageInfo { hasNextPage }
			}
			crossServiceSearch: messageLogs(input: {
				first: 10
				search: "Human Scoped Service 02"
				createdAfter: "2026-09-10T00:00:00Z"
				createdBefore: "2026-09-10T01:00:00Z"
			}) {
				nodes { id serviceID serviceName }
				pageInfo { hasNextPage }
				stats {
					timeSeries(input: {
						bucketDuration: "PT1H"
						bucketOrigin: "2026-09-10T00:00:00Z"
					}) { value }
				}
			}
			sameServiceSearch: messageLogs(input: {first: 10, search: "Human Scoped Service 01"}) {
				nodes { id serviceID serviceName }
				pageInfo { hasNextPage }
			}
			noServiceSearch: messageLogs(input: {first: 10, search: "no-service-message-log@example.invalid"}) {
				nodes { id serviceID serviceName }
				pageInfo { hasNextPage }
			}
			debugMessages(input: {first: 10}) { id serviceID serviceName }
		}
	`, h.UUID("service-a1"), h.UUID("service-b1")))
	require.Empty(t, humanResponse.Errors)
	var humanResult struct {
		OwnService         *struct{ ID, Name string }      `json:"ownService"`
		CrossService       *struct{ ID, Name string }      `json:"crossService"`
		MessageLogs        scopedSmokeMessageLogConnection `json:"messageLogs"`
		CrossServiceSearch scopedSmokeMessageLogConnection `json:"crossServiceSearch"`
		SameServiceSearch  scopedSmokeMessageLogConnection `json:"sameServiceSearch"`
		NoServiceSearch    scopedSmokeMessageLogConnection `json:"noServiceSearch"`
		DebugMessages      []scopedSmokeMessageLogNode     `json:"debugMessages"`
	}
	require.NoError(t, json.Unmarshal(humanResponse.Data, &humanResult))
	require.NotNil(t, humanResult.OwnService)
	require.Equal(t, h.UUID("service-a1"), humanResult.OwnService.ID)
	require.Nil(t, humanResult.CrossService)
	requireScopedSmokeMessageLogNodes(t, humanResult.MessageLogs.Nodes, h, false)
	requireScopedSmokeMessageLogIDs(t, humanResult.MessageLogs.Nodes,
		h.UUID("message-log-without-service"),
		h.UUID("message-log-cross"),
		h.UUID("message-log-own"),
	)
	require.False(t, humanResult.MessageLogs.PageInfo.HasNextPage)

	requireScopedSmokeMessageLogIDs(t, humanResult.CrossServiceSearch.Nodes, h.UUID("message-log-cross"))
	require.Nil(t, humanResult.CrossServiceSearch.Nodes[0].ServiceID)
	require.Nil(t, humanResult.CrossServiceSearch.Nodes[0].ServiceName)
	require.False(t, humanResult.CrossServiceSearch.PageInfo.HasNextPage)
	require.Len(t, humanResult.CrossServiceSearch.Stats.TimeSeries, 1)
	require.Equal(t, float64(1), humanResult.CrossServiceSearch.Stats.TimeSeries[0].Value)

	requireScopedSmokeMessageLogIDs(t, humanResult.SameServiceSearch.Nodes, h.UUID("message-log-own"))
	require.NotNil(t, humanResult.SameServiceSearch.Nodes[0].ServiceID)
	require.Equal(t, h.UUID("service-a1"), *humanResult.SameServiceSearch.Nodes[0].ServiceID)
	require.NotNil(t, humanResult.SameServiceSearch.Nodes[0].ServiceName)
	require.Equal(t, "Human Scoped Service 01", *humanResult.SameServiceSearch.Nodes[0].ServiceName)
	require.False(t, humanResult.SameServiceSearch.PageInfo.HasNextPage)

	requireScopedSmokeMessageLogIDs(t, humanResult.NoServiceSearch.Nodes, h.UUID("message-log-without-service"))
	require.Nil(t, humanResult.NoServiceSearch.Nodes[0].ServiceID)
	require.Nil(t, humanResult.NoServiceSearch.Nodes[0].ServiceName)
	require.False(t, humanResult.NoServiceSearch.PageInfo.HasNextPage)
	requireScopedSmokeMessageLogNodes(t, humanResult.DebugMessages, h, false)
	requireScopedSmokeMessageLogIDs(t, humanResult.DebugMessages,
		h.UUID("message-log-without-service"),
		h.UUID("message-log-cross"),
		h.UUID("message-log-own"),
	)

	const queryDocument = `
		query MessageLogCompatibility {
			messageLogs(input: {first: 10}) { nodes { id serviceID serviceName } }
			crossServiceSearch: messageLogs(input: {first: 10, search: "Human Scoped Service 02"}) {
				nodes { id serviceID serviceName }
				pageInfo { hasNextPage }
			}
			debugMessages(input: {first: 10}) { id serviceID serviceName }
		}
	`
	createResponse := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
		mutation CreateMessageLogCompatibilityKey($expires: ISOTimestamp!, $query: String!) {
			createGQLAPIKey(input: {
				name: "message-log-scope-compatibility"
				description: "message-log scope compatibility smoke"
				expiresAt: $expires
				role: admin
				query: $query
			}) { token }
		}
	`, "CreateMessageLogCompatibilityKey", map[string]any{
		"expires": time.Now().Add(time.Hour).Format(time.RFC3339),
		"query":   queryDocument,
	})
	require.Empty(t, createResponse.Errors)
	var created struct {
		CreateGQLAPIKey struct{ Token string }
	}
	require.NoError(t, json.Unmarshal(createResponse.Data, &created))
	require.NotEmpty(t, created.CreateGQLAPIKey.Token)

	requestBody, err := json.Marshal(map[string]any{"operationName": "MessageLogCompatibility"})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(requestBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+created.CreateGQLAPIKey.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var compatibilityResult struct {
		Data struct {
			MessageLogs        scopedSmokeMessageLogConnection `json:"messageLogs"`
			CrossServiceSearch scopedSmokeMessageLogConnection `json:"crossServiceSearch"`
			DebugMessages      []scopedSmokeMessageLogNode     `json:"debugMessages"`
		} `json:"data"`
		Errors []struct{ Message string } `json:"errors"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&compatibilityResult))
	require.Empty(t, compatibilityResult.Errors)
	requireScopedSmokeMessageLogNodes(t, compatibilityResult.Data.MessageLogs.Nodes, h, true)
	requireScopedSmokeMessageLogIDs(t, compatibilityResult.Data.CrossServiceSearch.Nodes, h.UUID("message-log-cross"))
	require.NotNil(t, compatibilityResult.Data.CrossServiceSearch.Nodes[0].ServiceID)
	require.Equal(t, h.UUID("service-b1"), *compatibilityResult.Data.CrossServiceSearch.Nodes[0].ServiceID)
	require.NotNil(t, compatibilityResult.Data.CrossServiceSearch.Nodes[0].ServiceName)
	require.Equal(t, "Human Scoped Service 02", *compatibilityResult.Data.CrossServiceSearch.Nodes[0].ServiceName)
	require.False(t, compatibilityResult.Data.CrossServiceSearch.PageInfo.HasNextPage)
	requireScopedSmokeMessageLogNodes(t, compatibilityResult.Data.DebugMessages, h, true)
}

func scopedSmokeRowCount(t *testing.T, h *harness.Harness, table, id string) int {
	t.Helper()
	var count int
	err := h.App().DB().QueryRow("SELECT count(*) FROM "+table+" WHERE id = $1", id).Scan(&count)
	require.NoError(t, err)
	return count
}
