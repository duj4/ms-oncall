package smoke

import (
	"fmt"
	"testing"

	"github.com/target/goalert/test/smoke/harness"
)

// TestSlackAddToEPStep tests that slack channels can be added to an EPStep.
func TestSlackAddToEPStep(t *testing.T) {
	t.Parallel()

	sql := `
	insert into escalation_policies (id, name, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', {{smokeOrganizationID}});
	
	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});
`
	h := harness.NewHarness(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1")
	defer h.Close()

	doQL := func(t *testing.T, query string) {
		g := h.GraphQLQuery2(query)
		for _, err := range g.Errors {
			t.Error("GraphQL Error:", err.Message)
		}
		if len(g.Errors) > 0 {
			t.Fatal("errors returned from GraphQL")
		}

		t.Log("Response:", string(g.Data))
	}

	channel := h.Slack().Channel("test")

	doQL(t, fmt.Sprintf(`
		mutation { 
			createEscalationPolicyStep(input:{
				escalationPolicyID: "%s",
				delayMinutes: 5,
				targets: [{
					id: "%s", 
					type: slackChannel,
				}],
			}){
				id
			}
		}
	`, h.UUID("eid"), channel.ID()))

	h.CreateAlert(h.UUID("sid"), "testing")
	channel.ExpectMessage("testing")
}
