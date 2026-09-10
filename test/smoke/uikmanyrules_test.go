package smoke

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/test/smoke/harness"
)

// TestUIKManyRules validates that a UIK key can be updated with many rules
// without getting rejected during validation.
func TestUIKManyRules(t *testing.T) {
	t.Parallel()

	// Insert initial one label into db
	const sql = `
	insert into escalation_policies (id, name, organization_id)
	values
		({{uuid "eid"}}, 'esc policy', {{smokeOrganizationID}});
	insert into services (id, escalation_policy_id, name, organization_id)
	values
		({{uuid "sid"}}, {{uuid "eid"}}, 'service', {{smokeOrganizationID}});
	insert into integration_keys (id, service_id, name, type)
	values
		({{uuid "key"}}, {{uuid "sid"}}, 'key', 'universal');
`

	h := harness.NewHarnessWithFlags(t, sql, "ms-oncall-resource-root-organization-ownership-persistence-v1", expflag.FlagSet{expflag.UnivKeys})
	defer h.Close()
	type dest struct {
		Type string            `json:"type"`
		Args map[string]string `json:"args"`
	}
	type action struct {
		Params map[string]string `json:"params"`
		Dest   dest              `json:"dest"`
	}
	type rule struct {
		Name               string   `json:"name"`
		Desc               string   `json:"description"`
		Cond               string   `json:"conditionExpr"`
		Actions            []action `json:"actions"`
		ContinueAfterMatch bool     `json:"continueAfterMatch"`
	}

	var vars struct {
		Input struct {
			KeyID string `json:"keyID"`
			Rules []rule `json:"rules"`
		} `json:"input"`
	}
	vars.Input.KeyID = h.UUID("key")

	for i := 0; i < 80; i++ {
		vars.Input.Rules = append(vars.Input.Rules, rule{
			Name: fmt.Sprintf("Rule %d", i),
			Desc: fmt.Sprintf("Description for Rule %d", i),
			Cond: "true",
			Actions: []action{{
				Params: map[string]string{"message": "hello"},
				Dest: dest{
					Type: "builtin-slack-channel",
					Args: map[string]string{"slack_channel_id": h.Slack().Channel("one channel").ID()},
				},
			}},
		})
	}

	resp := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID,
		`
		mutation test($input: UpdateKeyConfigInput!) {
			updateKeyConfig(input: $input)
		}
	`, "test", vars)
	require.Empty(t, resp.Errors)
}
