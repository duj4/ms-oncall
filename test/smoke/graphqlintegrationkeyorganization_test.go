package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

const integrationKeyOrganizationSQL = `
INSERT INTO organizations (id, classification, display_name, canonical_name)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'Integration Key Organization B', 'integration-key.organization-b');
INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
VALUES ({{uuid "org-b"}}, 'NORMAL', 'integration-key:organization-b', 'Etc/UTC');
INSERT INTO users (id, name, email, role)
VALUES ({{uuid "user-a"}}, 'Integration Key Organization A User', '', 'user');
INSERT INTO escalation_policies (id, organization_id, name)
VALUES ({{uuid "policy-a"}}, {{smokeOrganizationID}}, 'Integration Key Policy A'),
       ({{uuid "policy-b"}}, {{uuid "org-b"}}, 'Integration Key Policy B');
INSERT INTO services (id, organization_id, escalation_policy_id, name)
VALUES ({{uuid "service-a"}}, {{smokeOrganizationID}}, {{uuid "policy-a"}}, 'Integration Key Service A'),
       ({{uuid "service-b"}}, {{uuid "org-b"}}, {{uuid "policy-b"}}, 'Integration Key Service B');
INSERT INTO integration_keys (id, service_id, name, type)
VALUES ({{uuid "generic-a"}}, {{uuid "service-a"}}, 'Generic A', 'generic'),
       ({{uuid "universal-a"}}, {{uuid "service-a"}}, 'Universal A', 'universal'),
       ({{uuid "generic-b"}}, {{uuid "service-b"}}, 'Generic B', 'generic'),
       ({{uuid "universal-b"}}, {{uuid "service-b"}}, 'Universal B', 'universal');
INSERT INTO uik_config (id, config, primary_token, primary_token_hint, secondary_token, secondary_token_hint)
VALUES ({{uuid "universal-a"}}, '{"Version":1,"V1":{"Rules":[],"DefaultActions":[]}}',
        {{uuid "primary-a"}}, 'synthetic-primary-a', {{uuid "secondary-a"}}, 'synthetic-secondary-a'),
       ({{uuid "universal-b"}}, '{"Version":1,"V1":{"Rules":[],"DefaultActions":[]}}',
        {{uuid "primary-b"}}, 'synthetic-primary-b', {{uuid "secondary-b"}}, 'synthetic-secondary-b');
`

func integrationKeyOrganizationHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarnessWithFlags(t, integrationKeyOrganizationSQL, "", expflag.FlagSet{expflag.UnivKeys})
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func integrationKeyOrganizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{"integration_keys", "uik_config", "notification_channels", "services", "escalation_policies"} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text FROM `+table+` r`).Scan(&rows))
		result[table] = rows
	}
	return result
}

func integrationKeyOrganizationContext(t *testing.T, h *harness.Harness) context.Context {
	t.Helper()
	sessionID := uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID})
	requester, err := auth.NewRequester(h.UUID("user-a"), sessionID)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(h.App().DB()))
	require.NoError(t, err)
	authority, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return expflag.Context(executioncontext.WithExecutionContext(ctx, authority), expflag.FlagSet{expflag.UnivKeys})
}

func integrationKeyOrganizationApp(h *harness.Harness) *graphqlapp.App {
	return &graphqlapp.App{DB: h.App().DB(), IntKeyStore: h.App().IntegrationKeyStore}
}

func TestGraphQLIntegrationKeyOrganizationMaterialization(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	for _, kind := range []string{"generic", "universal"} {
		fields := "id serviceID href type"
		if kind == "universal" {
			fields += " tokenInfo {primaryHint secondaryHint} config {rules {id name} defaultActions {dest {type}}}"
		}
		query := func(id string) *stepOrganizationResponse {
			return stepOrganizationQuery(t, h, fmt.Sprintf(`query {integrationKey(id: %q) {%s}}`, id, fields))
		}
		own := query(h.UUID(kind + "-a"))
		require.Empty(t, own.Errors)
		require.Contains(t, string(own.Data), h.UUID(kind+"-a"))
		foreign := query(h.UUID(kind + "-b"))
		missing := query(h.UUID("missing"))
		require.Equal(t, missing, foreign)
		require.JSONEq(t, `{"integrationKey":null}`, string(foreign.Data))
	}
	// Every object-producing list boundary must prevent legacy Href exposure.
	for _, query := range []string{
		`query {integrationKeys {nodes {id serviceID href}}}`,
		fmt.Sprintf(`query {service(id:%q) {integrationKeys {id serviceID href}}}`, h.UUID("service-a")),
		`query {services {nodes {id integrationKeys {id serviceID href}}}}`,
	} {
		response := stepOrganizationQuery(t, h, query)
		require.Empty(t, response.Errors)
		require.Contains(t, string(response.Data), h.UUID("generic-a"))
		require.NotContains(t, string(response.Data), h.UUID("generic-b"))
		require.NotContains(t, string(response.Data), h.UUID("universal-b"))
	}
	for _, forged := range []map[string]any{
		{"OrganizationID": h.UUID("org-b"), "organization_id": h.UUID("org-b"), "organizationID": h.UUID("org-b")},
		{"OrganizationID": nil, "organization_id": nil},
		{"OrganizationID": "00000000-0000-0000-0000-000000000000"},
		{"OrganizationID": h.UUID("org-b"), "s": h.UUID("generic-b")},
	} {
		cursor, err := search.Cursor(forged)
		require.NoError(t, err)
		response := stepOrganizationQuery(t, h, fmt.Sprintf(`query {integrationKeys(input:{after:%q}) {nodes {id href}}}`, cursor))
		require.Empty(t, response.Errors)
		require.NotContains(t, string(response.Data), h.UUID("generic-b"))
		require.NotContains(t, string(response.Data), h.UUID("universal-b"))
		if forged["s"] == nil {
			require.Contains(t, string(response.Data), h.UUID("generic-a"))
		}
	}
	// A raw Service parent is deliberately supplied without scoped materialization.
	app := integrationKeyOrganizationApp(h)
	ctx := integrationKeyOrganizationContext(t, h)
	own, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: h.UUID("service-a")})
	require.NoError(t, err)
	require.Len(t, own, 2)
	foreign, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: h.UUID("service-b")})
	require.NoError(t, err)
	require.Empty(t, foreign)
	// Even a raw IntegrationKey cannot expose configuration or token hints.
	for _, id := range []string{h.UUID("universal-b"), h.UUID("missing")} {
		info, err := app.IntegrationKey().TokenInfo(ctx, &integrationkey.IntegrationKey{ID: id})
		require.ErrorIs(t, err, sql.ErrNoRows)
		require.Nil(t, info)
		cfg, err := app.IntegrationKey().Config(ctx, &integrationkey.IntegrationKey{ID: id})
		require.ErrorIs(t, err, sql.ErrNoRows)
		require.Nil(t, cfg)
	}
	info, err := app.IntegrationKey().TokenInfo(ctx, &integrationkey.IntegrationKey{ID: h.UUID("universal-a")})
	require.NoError(t, err)
	require.Equal(t, "synthetic-primary-a", info.PrimaryHint)
	cfg, err := app.IntegrationKey().Config(ctx, &integrationkey.IntegrationKey{ID: h.UUID("universal-a")})
	require.NoError(t, err)
	require.Empty(t, cfg.Rules)
}

func TestGraphQLIntegrationKeyOrganizationCreate(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	create := func(serviceID, name string) *stepOrganizationResponse {
		return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createIntegrationKey(input:{serviceID:%q, name:%q, type:generic}) {id serviceID href}}`, serviceID, name))
	}
	before := integrationKeyOrganizationSnapshot(t, h)
	foreign := create(h.UUID("service-b"), "New")
	missing := create(h.UUID("service-missing"), "New")
	require.NotEmpty(t, foreign.Errors)
	require.Equal(t, missing, foreign)
	require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	ownInvalid := create(h.UUID("service-a"), "")
	for _, target := range []string{"service-b", "service-missing"} {
		require.Equal(t, ownInvalid, create(h.UUID(target), ""), "Name validation precedes ownership lookup")
	}
	own := create(h.UUID("service-a"), "New")
	require.Empty(t, own.Errors)
	require.Contains(t, string(own.Data), h.UUID("service-a"))
	// Nested CreateService shares its transaction, so ownership lookup must see
	// the newly inserted Service. The returned child must remain scoped as well.
	nested := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createService(input:{name:"Nested key service", escalationPolicyID:%q, newIntegrationKeys:[{name:"Nested key",type:generic}]}) {id integrationKeys {id href}}}`, h.UUID("policy-a")))
	require.Empty(t, nested.Errors)
	require.Contains(t, string(nested.Data), "integrationKeys")
	before = integrationKeyOrganizationSnapshot(t, h)
	rejected := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {createService(input:{name:"Rejected nested key service", escalationPolicyID:%q, newIntegrationKeys:[{name:"",type:generic}]}) {id}}`, h.UUID("policy-a")))
	require.NotEmpty(t, rejected.Errors)
	require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
}

func TestGraphQLIntegrationKeyOrganizationTokenConfigMutation(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	for _, operation := range []string{"generateKeyToken", "promoteSecondaryToken", "deleteSecondaryToken", "updateKeyConfig"} {
		t.Run(operation, func(t *testing.T) {
			request := func(id string) *stepOrganizationResponse {
				wait := h.ExpectBackendError("sql: no rows in result set")
				defer wait()
				if operation == "updateKeyConfig" {
					return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {updateKeyConfig(input:{keyID:%q, setRuleActions:{id:%q,actions:[]}})}`, id, h.UUID("rule-missing")))
				}
				return stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {%s(id:%q)}`, operation, id))
			}
			before := integrationKeyOrganizationSnapshot(t, h)
			missing := request(h.UUID("missing"))
			require.NotEmpty(t, missing.Errors)
			for _, key := range []string{"universal-b", "generic-b"} {
				require.Equal(t, missing, request(h.UUID(key)), "foreign type and token/config state must remain hidden")
				require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
			}
		})
	}
	// A foreign key with available token slots must not reach token generation.
	for _, setup := range []string{
		`UPDATE uik_config SET secondary_token=NULL,secondary_token_hint=NULL WHERE id=$1`,
		`UPDATE uik_config SET primary_token=NULL,primary_token_hint=NULL WHERE id=$1`,
	} {
		_, err := h.App().DB().Exec(setup, h.UUID("universal-b"))
		require.NoError(t, err)
		before := integrationKeyOrganizationSnapshot(t, h)
		wait := h.ExpectBackendError("sql: no rows in result set")
		response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {generateKeyToken(id:%q)}`, h.UUID("universal-b")))
		wait()
		require.NotEmpty(t, response.Errors)
		require.Equal(t, "null", string(response.Data))
		require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	}
	for _, query := range []string{
		fmt.Sprintf(`mutation {generateKeyToken(id:%q)}`, h.UUID("generic-a")),
		fmt.Sprintf(`mutation {generateKeyToken(id:%q)}`, h.UUID("universal-a")),
		fmt.Sprintf(`mutation {updateKeyConfig(input:{keyID:%q,setRuleActions:{id:%q,actions:[]}})}`, h.UUID("universal-a"), h.UUID("rule-missing")),
		fmt.Sprintf(`mutation {updateKeyConfig(input:{keyID:%q,defaultActions:[{dest:{type:"not-a-destination"},params:{}}]})}`, h.UUID("universal-a")),
	} {
		before := integrationKeyOrganizationSnapshot(t, h)
		response := stepOrganizationQuery(t, h, query)
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	}
	require.Empty(t, stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {promoteSecondaryToken(id:%q)}`, h.UUID("universal-a"))).Errors)
	var primary, secondary sql.NullString
	require.NoError(t, h.App().DB().QueryRow(`SELECT primary_token_hint,secondary_token_hint FROM uik_config WHERE id=$1`, h.UUID("universal-a")).Scan(&primary, &secondary))
	require.Equal(t, "synthetic-secondary-a", primary.String)
	require.False(t, secondary.Valid)
	noSecondary := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {promoteSecondaryToken(id:%q)}`, h.UUID("universal-a")))
	require.Len(t, noSecondary.Errors, 1)
	require.Equal(t, "no secondary token to promote", noSecondary.Errors[0].Message)
	require.Empty(t, stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {deleteSecondaryToken(id:%q)}`, h.UUID("universal-a"))).Errors)
	generated := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {generateKeyToken(id:%q)}`, h.UUID("universal-a")))
	require.Empty(t, generated.Errors)
	var token struct{ GenerateKeyToken string }
	require.NoError(t, json.Unmarshal(generated.Data, &token))
	require.True(t, len(token.GenerateKeyToken) > 0, "own token generated")
	require.Empty(t, stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {updateKeyConfig(input:{keyID:%q, rules:[], defaultActions:[{dest:{type:"builtin-webhook",args:{webhook_url:"https://example.invalid/integration-key-org"}},params:{body:"'test'"}}]})}`, h.UUID("universal-a"))).Errors)
}

func TestGraphQLIntegrationKeyOrganizationDeleteAll(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	request := func(ids ...string) *stepOrganizationResponse {
		targets := make([]string, len(ids))
		for i, id := range ids {
			targets[i] = fmt.Sprintf(`{type:integrationKey,id:%q}`, id)
		}
		return stepOrganizationQuery(t, h, `mutation {deleteAll(input:[`+strings.Join(targets, ",")+`])}`)
	}
	before := integrationKeyOrganizationSnapshot(t, h)
	for _, prefix := range [][]string{nil, {h.UUID("generic-a")}} {
		wait := h.ExpectBackendError("sql: no rows in result set")
		foreign := request(append(append([]string{}, prefix...), h.UUID("generic-b"))...)
		wait()
		wait = h.ExpectBackendError("sql: no rows in result set")
		missing := request(append(append([]string{}, prefix...), h.UUID("missing"))...)
		wait()
		require.NotEmpty(t, foreign.Errors)
		require.Equal(t, missing, foreign)
		require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	}
	// Schedule deletion runs before IntegrationKey deletion; a rejected key must
	// also roll back that earlier group without changing DeleteAll ordering.
	_, err := h.App().DB().Exec(`INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'Rollback schedule','Etc/UTC')`, h.UUID("rollback-schedule"), harness.SmokeOrganizationID)
	require.NoError(t, err)
	wait := h.ExpectBackendError("sql: no rows in result set")
	rolledBack := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {deleteAll(input:[{type:schedule,id:%q},{type:integrationKey,id:%q}])}`, h.UUID("rollback-schedule"), h.UUID("generic-b")))
	wait()
	require.NotEmpty(t, rolledBack.Errors)
	var remaining int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedules WHERE id=$1`, h.UUID("rollback-schedule")).Scan(&remaining))
	require.Equal(t, 1, remaining)
	require.Empty(t, request(h.UUID("generic-a"), h.UUID("generic-a")).Errors)
	var exists bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT EXISTS(SELECT 1 FROM integration_keys WHERE id=$1)`, h.UUID("generic-a")).Scan(&exists))
	require.False(t, exists)
	require.NoError(t, h.App().DB().QueryRow(`SELECT EXISTS(SELECT 1 FROM integration_keys WHERE id=$1)`, h.UUID("generic-b")).Scan(&exists))
	require.True(t, exists)
}

func TestIntegrationKeyOrganizationStore(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	ctx := integrationKeyOrganizationContext(t, h)
	store := h.App().IntegrationKeyStore
	org := uuid.MustParse(harness.SmokeOrganizationID)
	db := h.App().DB()
	for _, scope := range []*uuid.UUID{&org, nil} {
		own, err := store.FindOne(ctx, h.UUID("generic-a"), scope)
		require.NoError(t, err)
		require.NotNil(t, own)
		foreign, err := store.FindOne(ctx, h.UUID("generic-b"), scope)
		require.NoError(t, err)
		all, err := store.Search(ctx, nil, scope)
		require.NoError(t, err)
		children, err := store.FindAllByService(ctx, h.UUID("service-b"), scope)
		require.NoError(t, err)
		if scope == nil {
			require.NotNil(t, foreign)
			require.Len(t, all, 4)
			require.Len(t, children, 2)
		} else {
			require.Nil(t, foreign)
			require.Len(t, all, 2)
			require.Empty(t, children)
		}
	}
	before := integrationKeyOrganizationSnapshot(t, h)
	for _, target := range []string{"service-b", "service-missing"} {
		key, err := store.Create(ctx, db, &integrationkey.IntegrationKey{ServiceID: h.UUID(target), Name: "Scoped", Type: integrationkey.TypeGeneric}, &org)
		require.Error(t, err)
		require.Nil(t, key)
	}
	require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	// Every local validation case precedes both foreign and missing Service lookup.
	for _, invalid := range []integrationkey.IntegrationKey{
		{Name: "", Type: integrationkey.TypeGeneric},
		{Name: "Invalid type", Type: integrationkey.Type("invalid")},
		{Name: "Invalid external", Type: integrationkey.TypeGeneric, ExternalSystemName: "\u2603"},
	} {
		var firstError string
		for _, target := range []string{"service-a", "service-b", "service-missing"} {
			invalid.ServiceID = h.UUID(target)
			_, err := store.Create(ctx, db, &invalid, &org)
			require.Error(t, err)
			if firstError == "" {
				firstError = err.Error()
			} else {
				require.Equal(t, firstError, err.Error())
			}
		}
	}
	for _, other := range []string{"generic-b", "missing"} {
		require.ErrorIs(t, store.DeleteMany(ctx, db, []string{h.UUID("generic-a"), h.UUID(other)}, &org), sql.ErrNoRows)
		require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h), "Store autocommit deletion is all-or-nothing")
	}
	zero := uuid.Nil
	_, err := store.FindOne(ctx, h.UUID("generic-a"), &zero)
	require.Error(t, err)
	// A nil scope keeps the explicit existing Store behavior, including missing
	// deletes and foreign-Service creation for bounded non-human callers.
	compatibility := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})
	_, err = store.Create(compatibility, db, &integrationkey.IntegrationKey{ServiceID: h.UUID("service-b"), Name: "Compatibility", Type: integrationkey.TypeGeneric}, nil)
	require.NoError(t, err)
	require.NoError(t, store.DeleteMany(compatibility, db, []string{h.UUID("missing")}, nil))
	// Ingress uses its existing Service identity without a human Requester.
	for _, suffix := range []string{"a", "b"} {
		keyID := uuid.MustParse(h.UUID("generic-" + suffix))
		authorized, err := store.Authorize(context.Background(), authtoken.Token{ID: keyID}, integrationkey.TypeGeneric)
		require.NoError(t, err)
		require.Equal(t, h.UUID("service-"+suffix), permission.ServiceID(authorized))
		sid, err := store.GetServiceID(compatibility, keyID.String(), integrationkey.TypeGeneric)
		require.NoError(t, err)
		require.Equal(t, h.UUID("service-"+suffix), sid)
	}
	tokCtx := expflag.Context(compatibility, expflag.FlagSet{expflag.UnivKeys})
	require.NoError(t, store.DeleteSecondaryToken(tokCtx, db, uuid.MustParse(h.UUID("universal-b"))))
	token, err := store.GenerateToken(tokCtx, db, uuid.MustParse(h.UUID("universal-b")))
	require.NoError(t, err)
	authorized, err := store.AuthorizeUIK(expflag.Context(context.Background(), expflag.FlagSet{expflag.UnivKeys}), token)
	require.NoError(t, err)
	require.Equal(t, h.UUID("service-b"), permission.ServiceID(authorized))
	cfg, err := store.Config(authorized, db, uuid.MustParse(h.UUID("universal-b")))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	_, err = store.AuthorizeUIK(expflag.Context(context.Background(), expflag.FlagSet{expflag.UnivKeys}), token+"invalid")
	require.Error(t, err)
}

func TestIntegrationKeyOrganizationNonLockingAndCascade(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	ctx, cancel := context.WithTimeout(integrationKeyOrganizationContext(t, h), 5*time.Second)
	defer cancel()
	db := h.App().DB()
	store := h.App().IntegrationKeyStore
	org := uuid.MustParse(harness.SmokeOrganizationID)
	gate, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer gate.Rollback()
	var id string
	require.NoError(t, gate.QueryRowContext(ctx, `SELECT id FROM services WHERE id=$1 FOR NO KEY UPDATE`, h.UUID("service-a")).Scan(&id))
	created, err := store.Create(ctx, db, &integrationkey.IntegrationKey{ServiceID: id, Name: "Non locking", Type: integrationkey.TypeGeneric}, &org)
	require.NoError(t, err, "ownership must not acquire a Service mutation lock")
	require.NoError(t, gate.QueryRowContext(ctx, `SELECT id FROM services WHERE id=$1 FOR UPDATE`, id).Scan(&id))
	require.NoError(t, store.CheckOrganization(ctx, db, uuid.MustParse(created.ID), &org))
	require.NoError(t, gate.Rollback())
	_, err = db.ExecContext(ctx, `DELETE FROM services WHERE id=$1`, id)
	require.NoError(t, err)
	key, err := store.FindOne(ctx, created.ID, nil)
	require.NoError(t, err)
	require.Nil(t, key, "Service deletion cascades to the key")
	_, err = store.Create(ctx, db, &integrationkey.IntegrationKey{ServiceID: id, Name: "Deleted parent", Type: integrationkey.TypeGeneric}, &org)
	require.Error(t, err, "deleted Service cannot leave an orphan")
}

func TestGraphQLIntegrationKeyOrganizationBoundaryCompatibility(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	app := integrationKeyOrganizationApp(h)
	ctx := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	before := integrationKeyOrganizationSnapshot(t, h)
	_, err := app.Mutation().UpdateKeyConfig(ctx, graphql2.UpdateKeyConfigInput{KeyID: h.UUID("universal-a")})
	require.True(t, permission.IsPermissionError(err))
	require.Equal(t, before, integrationKeyOrganizationSnapshot(t, h))
	// Heartbeat is deliberately still its existing independent compatibility path.
	_, err = h.App().DB().Exec(`INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'Compatibility heartbeat','1 hour')`, h.UUID("heartbeat-b"), h.UUID("service-b"))
	require.NoError(t, err)
	response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation {deleteAll(input:[{type:heartbeatMonitor,id:%q}])}`, h.UUID("heartbeat-b")))
	require.Empty(t, response.Errors)
	var remaining int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM heartbeat_monitors WHERE id=$1`, h.UUID("heartbeat-b")).Scan(&remaining))
	require.Zero(t, remaining)
}
