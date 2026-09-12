package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

const servicePolicyOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Service Policy Organization B', 'service-policy.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'service-policy:organization-b', 'Etc/UTC');

INSERT INTO users (id, name, email, role)
VALUES ({{uuid "user-a"}}, 'Service Policy Organization A User', '', 'user');

INSERT INTO escalation_policies (id, organization_id, name, description, repeat)
VALUES
    ({{uuid "policy-a1"}}, {{smokeOrganizationID}}, 'Service Policy A One', '', 1),
    ({{uuid "policy-a2"}}, {{smokeOrganizationID}}, 'Service Policy A Two', '', 1),
    ({{uuid "policy-b"}}, {{uuid "org-b"}}, 'Service Policy B', '', 1);

INSERT INTO services (id, organization_id, name, description, escalation_policy_id)
VALUES ({{uuid "service-a"}}, {{smokeOrganizationID}}, 'Service Policy Original', 'original description', {{uuid "policy-a1"}});
`

func TestGraphQLServicePolicySameOrganization(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, servicePolicyOrganizationSQL, "")
	defer h.Close()

	// The harness assigns this ordinary user to its real Normal Organization A.
	query := func(t *testing.T, input string) *harness.QLResponse {
		t.Helper()
		return h.GraphQLQueryUserT(t, h.UUID("user-a"), input)
	}
	counts := func(t *testing.T) map[string]int {
		t.Helper()
		result := make(map[string]int)
		for _, table := range []string{
			"services", "escalation_policies", "escalation_policy_steps", "escalation_policy_actions",
			"user_favorites", "integration_keys", "heartbeat_monitors", "labels",
		} {
			var count int
			require.NoError(t, h.App().DB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
			result[table] = count
		}
		return result
	}
	servicePolicy := func(t *testing.T, serviceID string) string {
		t.Helper()
		var serviceOrgID, policyID, policyOrgID string
		err := h.App().DB().QueryRow(`
			SELECT s.organization_id, s.escalation_policy_id, p.organization_id
			FROM services s JOIN escalation_policies p ON p.id = s.escalation_policy_id
			WHERE s.id = $1
		`, serviceID).Scan(&serviceOrgID, &policyID, &policyOrgID)
		require.NoError(t, err)
		require.Equal(t, harness.SmokeOrganizationID, serviceOrgID)
		require.Equal(t, serviceOrgID, policyOrgID)
		return policyID
	}
	createdServiceID := func(t *testing.T, response *harness.QLResponse) string {
		t.Helper()
		require.Empty(t, response.Errors)
		var result struct{ CreateService struct{ ID string } }
		require.NoError(t, json.Unmarshal(response.Data, &result))
		require.NotEmpty(t, result.CreateService.ID)
		return result.CreateService.ID
	}
	const children = `
		favorite: true
		newIntegrationKeys: [{name: "Service Policy Key", type: generic}]
		newHeartbeatMonitors: [{name: "Service Policy Heartbeat", timeoutMinutes: 15}]
		labels: [{key: "test/team", value: "Service Policy Team"}]
	`

	t.Run("create foreign and missing policies are unavailable without side effects", func(t *testing.T) {
		before := counts(t)
		var foreignResponse *harness.QLResponse
		for _, policy := range []string{"policy-b", "policy-missing"} {
			response := query(t, fmt.Sprintf(`mutation {
				createService(input: {name: "Rejected Service Policy Create", escalationPolicyID: %q, %s}) {id}
			}`, h.UUID(policy), children))
			// Only request the Service ID: the mutation must reject the reference
			// before any nested escalationPolicy resolver could hide a bad write.
			require.Len(t, response.Errors, 1)
			require.Equal(t, "does not exist", response.Errors[0].Message)
			require.Equal(t, before, counts(t), "rejected create persisted a relationship or child")
			if foreignResponse == nil {
				foreignResponse = response
			} else {
				require.Equal(t, foreignResponse.Errors, response.Errors)
			}
		}
	})

	t.Run("create existing same organization policy and children", func(t *testing.T) {
		response := query(t, fmt.Sprintf(`mutation {
			createService(input: {name: "Same Organization Service Policy", escalationPolicyID: %q, %s}) {id}
		}`, h.UUID("policy-a1"), children))
		serviceID := createdServiceID(t, response)
		require.Equal(t, h.UUID("policy-a1"), servicePolicy(t, serviceID))
		for _, child := range []struct{ table, column string }{
			{"user_favorites", "tgt_service_id"},
			{"integration_keys", "service_id"},
			{"heartbeat_monitors", "service_id"},
			{"labels", "tgt_service_id"},
		} {
			var count int
			err := h.App().DB().QueryRow("SELECT count(*) FROM "+child.table+" WHERE "+child.column+" = $1", serviceID).Scan(&count)
			require.NoError(t, err)
			require.Equal(t, 1, count, child.table)
		}
	})

	t.Run("create nested policy in the same transaction and organization", func(t *testing.T) {
		response := query(t, `mutation {
			createService(input: {
				name: "Nested Organization Service Policy"
				escalationPolicyID: ""
				newEscalationPolicy: {
					name: "Nested Organization Policy"
					steps: [{delayMinutes: 1}]
				}
			}) {id}
		}`)
		policyID := servicePolicy(t, createdServiceID(t, response))
		var policyName string
		var stepCount int
		require.NoError(t, h.App().DB().QueryRow("SELECT name FROM escalation_policies WHERE id = $1", policyID).Scan(&policyName))
		require.Equal(t, "Nested Organization Policy", policyName)
		require.NoError(t, h.App().DB().QueryRow("SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id = $1", policyID).Scan(&stepCount))
		require.Equal(t, 1, stepCount)
	})

	t.Run("update foreign and missing policies preserve the original service", func(t *testing.T) {
		var foreignResponse *harness.QLResponse
		for _, policy := range []string{"policy-b", "policy-missing"} {
			response := query(t, fmt.Sprintf(`mutation {
				updateService(input: {
					id: %q, name: "Rejected Service Policy Update", description: "rejected description", escalationPolicyID: %q
				})
			}`, h.UUID("service-a"), h.UUID(policy)))
			require.Len(t, response.Errors, 1)
			require.Equal(t, "does not exist", response.Errors[0].Message)
			if foreignResponse == nil {
				foreignResponse = response
			} else {
				require.Equal(t, foreignResponse.Errors, response.Errors)
			}
			require.Equal(t, h.UUID("policy-a1"), servicePolicy(t, h.UUID("service-a")))
			var name, description string
			require.NoError(t, h.App().DB().QueryRow("SELECT name, description FROM services WHERE id = $1", h.UUID("service-a")).Scan(&name, &description))
			require.Equal(t, "Service Policy Original", name)
			require.Equal(t, "original description", description)
		}
	})

	t.Run("update same organization replacement policy", func(t *testing.T) {
		response := query(t, fmt.Sprintf(`mutation {
			updateService(input: {id: %q, escalationPolicyID: %q})
		}`, h.UUID("service-a"), h.UUID("policy-a2")))
		require.Empty(t, response.Errors)
		require.JSONEq(t, `{"updateService": true}`, string(response.Data))
		require.Equal(t, h.UUID("policy-a2"), servicePolicy(t, h.UUID("service-a")))
	})

	t.Run("service validation precedes existing policy resolution", func(t *testing.T) {
		before := counts(t)
		for _, mutation := range []string{
			fmt.Sprintf(`mutation {createService(input: {name: "x", escalationPolicyID: %q}) {id}}`, h.UUID("policy-b")),
			fmt.Sprintf(`mutation {updateService(input: {id: %q, name: "x", escalationPolicyID: %q})}`, h.UUID("service-a"), h.UUID("policy-b")),
		} {
			response := query(t, mutation)
			require.Len(t, response.Errors, 1)
			require.Equal(t, "must be at least 2 characters", response.Errors[0].Message)
		}
		require.Equal(t, before, counts(t))
		require.Equal(t, h.UUID("policy-a2"), servicePolicy(t, h.UUID("service-a")))
	})

	for _, policy := range []struct{ name, input string }{
		{"existing policy", fmt.Sprintf("escalationPolicyID: %q", h.UUID("policy-a1"))},
		{"nested policy", `newEscalationPolicy: {name: "Rolled Back Nested Policy", favorite: true, steps: [{delayMinutes: 1}]}`},
	} {
		t.Run("child failure rolls back "+policy.name, func(t *testing.T) {
			before := counts(t)
			response := query(t, fmt.Sprintf(`mutation {
				createService(input: {
					name: "Rolled Back Service Policy"
					%s
					favorite: true
					newIntegrationKeys: [{name: "Rolled Back Key", type: generic}]
					newHeartbeatMonitors: [{name: "Rolled Back Heartbeat", timeoutMinutes: 15}]
					labels: [{key: "test/team", value: "x"}]
				}) {id}
			}`, policy.input))
			require.Len(t, response.Errors, 1)
			require.Equal(t, "must be at least 3 characters", response.Errors[0].Message)
			require.Equal(t, before, counts(t), "child failure must roll back the complete nested transaction")
		})
	}
}
