package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

var ikCredentialTypes = []string{"generic", "grafana", "site24x7", "prometheusAlertmanager", "email"}

func ikSetAuthority(t *testing.T, h *harness.Harness, role string, pa bool) {
	t.Helper()
	globalRole := "user"
	if pa {
		globalRole = "admin"
	}
	_, err := h.App().DB().Exec(`UPDATE users SET role=$2 WHERE id=$1`, h.UUID("user-a"), globalRole)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`UPDATE user_organization_assignments SET organization_role=$2 WHERE user_id=$1`, h.UUID("user-a"), role)
	require.NoError(t, err)
}

func ikAuthorizationHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := integrationKeyOrganizationHarness(t)
	for _, kind := range ikCredentialTypes[1:] {
		for _, suffix := range []string{"a", "b"} {
			_, err := h.App().DB().Exec(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,$3,$4)`, h.UUID(kind+"-"+suffix), h.UUID("service-"+suffix), kind+" "+suffix, kind)
			require.NoError(t, err)
		}
	}
	return h
}

func ikAuthorizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	s := integrationKeyOrganizationSnapshot(t, h)
	var rows string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM user_favorites r`).Scan(&rows))
	s["user_favorites"] = rows
	return s
}

func ikRequireDenied(t *testing.T, h *harness.Harness, query string) {
	t.Helper()
	response := stepOrganizationQuery(t, h, query)
	require.NotEmpty(t, response.Errors)
	require.Contains(t, response.Errors[0].Message, "access denied")
	body, err := json.Marshal(response)
	require.NoError(t, err)
	for _, kind := range append(append([]string{}, ikCredentialTypes...), "universal") {
		for _, suffix := range []string{"a", "b"} {
			require.NotContains(t, string(body), h.UUID(kind+"-"+suffix))
		}
	}
}

func TestGraphQLIntegrationKeyAuthorizationMember(t *testing.T) {
	h := ikAuthorizationHarness(t)
	before := ikAuthorizationSnapshot(t, h)
	for _, kind := range append(append([]string{}, ikCredentialTypes...), "universal") {
		for _, fields := range []string{"id", "href", "name type serviceID", "__typename"} {
			ikRequireDenied(t, h, fmt.Sprintf(`{integrationKey(id:%q){%s}}`, h.UUID(kind+"-a"), fields))
		}
	}
	for _, query := range []string{
		`{integrationKeys{nodes{id href}}}`,
		`{integrationKeys{pageInfo{hasNextPage endCursor}}}`,
		fmt.Sprintf(`{integrationKeys(input:{search:%q,first:1}){pageInfo{hasNextPage}}}`, h.UUID("generic-a")[:8]),
		`{integrationKeys(input:{after:"invalid"}){nodes{name}}}`,
		fmt.Sprintf(`{service(id:%q){name integrationKeys{id href}}}`, h.UUID("service-a")),
		`{services{nodes{name integrationKeys{id}}}}`,
		fmt.Sprintf(`{alias:integrationKey(id:%q){...Secret}} fragment Secret on IntegrationKey{secret:id href}`, h.UUID("generic-a")),
		fmt.Sprintf(`{integrationKey(id:%q){... on IntegrationKey{name}}}`, h.UUID("generic-a")),
	} {
		ikRequireDenied(t, h, query)
	}
	for _, kind := range ikCredentialTypes {
		for _, fields := range []string{"id href", "name", "__typename"} {
			ikRequireDenied(t, h, fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"Denied",type:%s}){%s}}`, h.UUID("service-a"), kind, fields))
		}
	}
	ikRequireDenied(t, h, `mutation{createService(input:{name:"Denied nested",favorite:true,newEscalationPolicy:{name:"Denied EP"},newIntegrationKeys:[{name:"Denied",type:generic}]}){__typename}}`)
	require.Equal(t, before, ikAuthorizationSnapshot(t, h), "no Key or composite business mutation persisted")
	ordinary := stepOrganizationQuery(t, h, fmt.Sprintf(`{service(id:%q){name description}}`, h.UUID("service-a")))
	require.Empty(t, ordinary.Errors)
	// No credential intent leaves the existing Service behavior intact.
	ordinary = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createService(input:{name:"No credential intent",escalationPolicyID:%q,newIntegrationKeys:[]}){id}}`, h.UUID("policy-a")))
	require.Empty(t, ordinary.Errors)
}

func TestGraphQLIntegrationKeyAuthorizationOrgAdmin(t *testing.T) {
	h := ikAuthorizationHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, kind := range ikCredentialTypes {
		own := stepOrganizationQuery(t, h, fmt.Sprintf(`{integrationKey(id:%q){id href}}`, h.UUID(kind+"-a")))
		require.Empty(t, own.Errors)
		require.Contains(t, string(own.Data), h.UUID(kind+"-a"))
		ikRequireDenied(t, h, fmt.Sprintf(`{integrationKey(id:%q){id href}}`, h.UUID(kind+"-b")))
		before := ikAuthorizationSnapshot(t, h)
		ikRequireDenied(t, h, fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"Foreign",type:%s}){name}}`, h.UUID("service-b"), kind))
		require.Equal(t, before, ikAuthorizationSnapshot(t, h))
		created := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:%q,type:%s}){id href serviceID}}`, h.UUID("service-a"), "Own "+kind, kind))
		require.Empty(t, created.Errors)
		require.Contains(t, string(created.Data), h.UUID("service-a"))
	}
	nested := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createService(input:{name:"Same transaction",escalationPolicyID:%q,newIntegrationKeys:[{name:"Nested",type:generic}]}){integrationKeys{id href}}}`, h.UUID("policy-a")))
	require.Empty(t, nested.Errors)
	before := ikAuthorizationSnapshot(t, h)
	rejected := stepOrganizationQuery(t, h, `mutation{createService(input:{name:"Rollback",favorite:true,newEscalationPolicy:{name:"Rollback EP"},newIntegrationKeys:[{name:"First",type:generic},{name:"",type:generic}]}){id}}`)
	require.NotEmpty(t, rejected.Errors)
	require.Equal(t, before, ikAuthorizationSnapshot(t, h))
	// A previously signed Session must observe current PG role on a new request.
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	ikRequireDenied(t, h, fmt.Sprintf(`{integrationKey(id:%q){id}}`, h.UUID("generic-a")))
}

func TestGraphQLIntegrationKeyAuthorizationPlatformAdmin(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			h := ikAuthorizationHarness(t)
			ikSetAuthority(t, h, role, true)
			// Equal names across Orgs exercise the server-owned cursor tie-breaker.
			for _, suffix := range []string{"a", "b"} {
				_, err := h.App().DB().Exec(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'Same','generic')`, h.UUID("tie-"+suffix), h.UUID("service-"+suffix))
				require.NoError(t, err)
			}
			seen := make(map[string]bool)
			cursor := ""
			for page := 0; page < 30; page++ {
				response := stepOrganizationQuery(t, h, fmt.Sprintf(`{integrationKeys(input:{first:1,after:%q}){nodes{id name} pageInfo{hasNextPage endCursor}}}`, cursor))
				require.Empty(t, response.Errors)
				var data struct {
					IntegrationKeys struct {
						Nodes    []struct{ ID string }
						PageInfo struct {
							HasNextPage bool
							EndCursor   string
						}
					}
				}
				require.NoError(t, json.Unmarshal(response.Data, &data))
				for _, key := range data.IntegrationKeys.Nodes {
					require.False(t, seen[key.ID])
					seen[key.ID] = true
				}
				if !data.IntegrationKeys.PageInfo.HasNextPage {
					break
				}
				cursor = data.IntegrationKeys.PageInfo.EndCursor
			}
			require.Len(t, seen, 13)
			require.False(t, seen[h.UUID("universal-b")])
			require.True(t, seen[h.UUID("universal-a")])
			for _, kind := range ikCredentialTypes {
				read := stepOrganizationQuery(t, h, fmt.Sprintf(`{integrationKey(id:%q){id href}}`, h.UUID(kind+"-b")))
				require.Empty(t, read.Errors)
				created := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:%q,type:%s}){id href serviceID}}`, h.UUID("service-b"), "PA foreign "+kind, kind))
				require.Empty(t, created.Errors)
				require.Contains(t, string(created.Data), h.UUID("service-b"))
			}
			ikRequireDenied(t, h, fmt.Sprintf(`{integrationKey(id:%q){name}}`, h.UUID("universal-b")))
			ikRequireDenied(t, h, fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"Invalid target",type:generic}){__typename}}`, h.UUID("service-missing")))
			// Raw-parent checks supplement, rather than replace, signed HTTP above.
			session := uuid.NewString()
			ctx := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
			r, err := auth.NewRequester(h.UUID("user-a"), session)
			require.NoError(t, err)
			ctx = auth.WithRequester(ctx, r)
			constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(h.App().DB()))
			require.NoError(t, err)
			ec, err := constructor.Construct(ctx)
			require.NoError(t, err)
			ctx = executioncontext.WithExecutionContext(ctx, ec)
			app := integrationKeyOrganizationApp(h)
			_, err = h.App().DB().Exec(`UPDATE integration_keys SET external_system_name='synthetic-managed' WHERE id=$1`, h.UUID("generic-b"))
			require.NoError(t, err)
			keys, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: h.UUID("service-b")})
			require.NoError(t, err)
			for _, key := range keys {
				require.NotEqual(t, integrationkey.TypeUniversal, key.Type)
				if key.ID == h.UUID("generic-b") {
					require.Equal(t, "synthetic-managed", key.ExternalSystemName)
				}
			}
			id, err := app.IntegrationKey().ID(ctx, &integrationkey.IntegrationKey{ID: h.UUID("generic-b"), Type: integrationkey.TypeUniversal, ServiceID: h.UUID("service-a")})
			require.NoError(t, err)
			require.Equal(t, h.UUID("generic-b"), id)
			// Removing real PA status must take effect on the next signed request.
			ikSetAuthority(t, h, role, false)
			ikRequireDenied(t, h, fmt.Sprintf(`{integrationKey(id:%q){id}}`, h.UUID("generic-b")))
		})
	}
}

func TestGraphQLIntegrationKeyAuthorizationUIKDefaultOff(t *testing.T) {
	h := harness.NewHarness(t, integrationKeyOrganizationSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, query := range []string{
		fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"UIK",type:universal}){id}}`, h.UUID("service-a")),
		fmt.Sprintf(`mutation{generateKeyToken(id:%q)}`, h.UUID("universal-a")),
		fmt.Sprintf(`{integrationKey(id:%q){config{rules{id}} tokenInfo{primaryHint}}}`, h.UUID("universal-a")),
	} {
		response := stepOrganizationQuery(t, h, query)
		require.NotEmpty(t, response.Errors)
	}
}
