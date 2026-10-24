package smoke

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// TestGQLAPIKeys verifies retirement of legacy issuance while preserving normal
// Human GraphQL access. Historical-key authentication is covered by the real
// PostgreSQL/HTTP tests in app; no production issuance backdoor is used there.
func TestGQLAPIKeys(t *testing.T) {
	h := harness.NewHarness(t, "", "")
	defer h.Close()

	for _, role := range []string{"admin", "user"} {
		t.Run(role, func(t *testing.T) {
			vars := map[string]string{
				"expires": time.Now().Add(time.Hour).Format(time.RFC3339),
				"query":   `query { user { id } }`,
				"role":    role,
			}
			resp := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
			mutation($expires: ISOTimestamp!, $query: String!, $role: UserRole!){
				createGQLAPIKey(input:{name:"retired",description:"synthetic",expiresAt:$expires,role:$role,query:$query}){id token}
			}`, "", vars)
			require.Len(t, resp.Errors, 1)
			require.Equal(t, "access denied: legacy GraphQL API key issuance is disabled in MS OnCall", resp.Errors[0].Message)
			var result struct{ CreateGQLAPIKey json.RawMessage }
			require.NoError(t, json.Unmarshal(resp.Data, &result))
			require.True(t, len(result.CreateGQLAPIKey) == 0 || string(result.CreateGQLAPIKey) == "null", "denied issuance returned data")
		})
	}
	resp := h.GraphQLQuery2(`query { user { id } gqlAPIKeys { id name } }`)
	require.Empty(t, resp.Errors)
	var result struct {
		User       struct{ ID string }
		GQLAPIKeys []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(resp.Data, &result))
	require.Equal(t, harness.DefaultGraphQLAdminUserID, result.User.ID)
	require.Empty(t, result.GQLAPIKeys, "denied issuance persisted a key")
}
