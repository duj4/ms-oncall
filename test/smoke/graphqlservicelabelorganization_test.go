package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/label"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

func serviceLabelID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("service-label-organization-test:"+name)).String()
}

func serviceLabelHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := h.App().DB().ExecContext(t.Context(), query, args...)
		require.NoError(t, err)
	}
	exec(`INSERT INTO organizations(id, classification, display_name, canonical_name)
	 VALUES ($1, 'NORMAL', 'Service Labels B', 'service-labels.b')`, serviceLabelID("org-b"))
	exec(`INSERT INTO normal_organizations(organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
	 VALUES ($1, 'NORMAL', 'service-labels:b', 'Etc/UTC')`, serviceLabelID("org-b"))
	for _, name := range []string{"user-a", "admin-a", "user-b", "missing", "default"} {
		role := "user"
		if name == "admin-a" {
			role = "admin"
		}
		exec(`INSERT INTO users(id, name, email, role) VALUES ($1, $2, '', $3)`, serviceLabelID(name), name, role)
		if name == "missing" {
			continue
		}
		if name == "default" {
			exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
			 effective_organization_classification, effective_normal_organization_id, organization_role,
			 mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
			 VALUES ($1, $2, 'DEFAULT', NULL, 'NONE', 'ZERO', now(), 'service-label-test', 0)`,
				serviceLabelID(name), organization.DefaultOrganizationID)
			continue
		}
		org := harness.SmokeOrganizationID
		if name == "user-b" {
			org = serviceLabelID("org-b")
		}
		exec(`INSERT INTO user_organization_assignments(user_id, effective_organization_id,
		 effective_organization_classification, effective_normal_organization_id, organization_role,
		 mapping_outcome, authoritative_evaluated_at, source_config_version, matched_count)
		 VALUES ($1, $2, 'NORMAL', $2, 'ORG_MEMBER', 'EXACTLY_ONE', now(), 'service-label-test', 1)`, serviceLabelID(name), org)
	}
	for _, side := range []string{"a", "a2", "b"} {
		org := harness.SmokeOrganizationID
		if side == "b" {
			org = serviceLabelID("org-b")
		}
		exec(`INSERT INTO escalation_policies(id, organization_id, name) VALUES ($1, $2, $3)`, serviceLabelID("policy-"+side), org, "policy-"+side)
		exec(`INSERT INTO services(id, organization_id, name, escalation_policy_id) VALUES ($1, $2, $3, $4)`,
			serviceLabelID(side), org, "service-"+side, serviceLabelID("policy-"+side))
	}
	for _, row := range [][3]string{
		{"a", "aaa/own", "own-value"}, {"a", "org/shared", "Alpha"},
		{"a", "mix/Alpha", "Zulu"}, {"a", "test/escape", "100%_value"},
		{"a2", "org/shared", "own-shared"}, {"a2", "mix/omega", "omega"},
		{"b", "bbb/foreign", "foreign-value"}, {"b", "org/shared", "alpha"},
		{"b", "mix/alpha", "foreign-case"},
	} {
		exec(`INSERT INTO labels(tgt_service_id, key, value) VALUES ($1, $2, $3)`, serviceLabelID(row[0]), row[1], row[2])
	}
	return h
}

func serviceLabelHuman(t *testing.T, h *harness.Harness, name string) context.Context {
	t.Helper()
	session := uuid.NewString()
	role := permission.RoleUser
	if name == "admin-a" {
		role = permission.RoleAdmin
	}
	ctx := permission.UserSourceContext(h.Config().Context(t.Context()), serviceLabelID(name), role,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(serviceLabelID(name), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(h.App().OrganizationStore)
	require.NoError(t, err)
	authority, err := c.Construct(ctx)
	if name == "missing" || name == "default" {
		require.Error(t, err)
		return ctx
	}
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, authority)
}

func serviceLabelApp(h *harness.Harness) *graphqlapp.App {
	return &graphqlapp.App{DB: h.App().DB(), LabelStore: h.App().LabelStore}
}

func serviceLabelRecord(t *testing.T, outcome any, err error) {
	t.Helper()
	message := ""
	if err != nil {
		message = err.Error()
	}
	data, marshalErr := json.Marshal(struct {
		Case    string `json:"case"`
		Outcome any    `json:"outcome"`
		Error   string `json:"error"`
	}{t.Name(), outcome, message})
	require.NoError(t, marshalErr)
	t.Log("SERVICE_LABEL_CASE " + string(data))
}

func serviceLabelInput(target, key, value string) graphql2.SetLabelInput {
	return graphql2.SetLabelInput{Target: &assignment.RawTarget{Type: assignment.TargetTypeService, ID: serviceLabelID(target)}, Key: key, Value: value}
}

func serviceLabelVariables(target, key, value string) map[string]any {
	return map[string]any{"input": map[string]any{
		"target": map[string]string{"type": "service", "id": serviceLabelID(target)},
		"key":    key, "value": value,
	}}
}

func serviceLabelSnapshot(t *testing.T, h *harness.Harness, target string) string {
	t.Helper()
	var result string
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT coalesce(jsonb_agg(to_jsonb(l) ORDER BY key), '[]'::jsonb)::text FROM labels l WHERE tgt_service_id=$1`, serviceLabelID(target)).Scan(&result))
	return result
}

func serviceLabelHTTP(t *testing.T, h *harness.Harness, principal, query string, variables any) *stepOrganizationResponse {
	t.Helper()
	data, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL()+"/v1/graphql2", bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(serviceLabelID(principal))})
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	var result stepOrganizationResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
	serviceLabelRecord(t, result, nil)
	require.Equal(t, http.StatusOK, response.StatusCode)
	return &result
}

func TestGraphQLServiceLabelOrganizationReads(t *testing.T) {
	h := serviceLabelHarness(t)
	app := serviceLabelApp(h)
	ownKeys := []string{"aaa/own", "mix/Alpha", "mix/omega", "org/shared", "test/escape"}
	for _, principal := range []string{"user-a", "admin-a"} {
		t.Run(principal, func(t *testing.T) {
			ctx := serviceLabelHuman(t, h, principal)
			keys, err := app.Query().LabelKeys(ctx, nil)
			require.NoError(t, err)
			require.Equal(t, ownKeys, keys.Nodes) // Shared key appears only once.
			labels, err := app.Query().Labels(ctx, nil)
			require.NoError(t, err)
			var got []string
			for _, l := range labels.Nodes {
				got = append(got, l.Key)
			}
			require.Equal(t, ownKeys, got)
			values, err := app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "org/shared"})
			require.NoError(t, err)
			require.Equal(t, []string{"Alpha", "own-shared"}, values.Nodes)
			foreign, err := app.Service().Labels(ctx, &service.Service{ID: serviceLabelID("b")})
			require.NoError(t, err)
			require.Empty(t, foreign) // Direct nested invocation must also enforce scope.
			own, err := app.Service().Labels(ctx, &service.Service{ID: serviceLabelID("a")})
			require.NoError(t, err)
			require.Len(t, own, 4)
			response := serviceLabelHTTP(t, h, principal, fmt.Sprintf(`query {
			 labelKeys { nodes } labelValues(input:{key:"org/shared"}) { nodes }
			 labels { nodes { key } }
			 own: service(id:%q) { labels { key value } }
			 foreign: service(id:%q) { id labels { key value } }
			}`, serviceLabelID("a"), serviceLabelID("b")), nil)
			require.Empty(t, response.Errors)
			var result struct {
				LabelKeys, LabelValues struct{ Nodes []string }
				Labels                 struct{ Nodes []label.Label }
				Own                    struct{ Labels []label.Label }
				Foreign                any
			}
			require.NoError(t, json.Unmarshal(response.Data, &result))
			require.Equal(t, ownKeys, result.LabelKeys.Nodes)
			require.Equal(t, []string{"Alpha", "own-shared"}, result.LabelValues.Nodes)
			require.Len(t, result.Labels.Nodes, len(ownKeys))
			require.Len(t, result.Own.Labels, 4)
			require.Nil(t, result.Foreign)
		})
	}
	ctx := serviceLabelHuman(t, h, "user-a")
	one := 1
	var cursor *string
	var paged []string
	for range 10 {
		conn, err := app.Query().LabelKeys(ctx, &graphql2.LabelKeySearchOptions{First: &one, After: cursor})
		require.NoError(t, err)
		paged = append(paged, conn.Nodes...)
		if !conn.PageInfo.HasNextPage {
			break
		}
		require.NotNil(t, conn.PageInfo.EndCursor)
		cursor = conn.PageInfo.EndCursor
	}
	require.Equal(t, ownKeys, paged)
	filter := "mix/"
	keys, err := app.Query().LabelKeys(ctx, &graphql2.LabelKeySearchOptions{Search: &filter, Omit: []string{"mix/omega"}})
	require.NoError(t, err)
	require.Equal(t, []string{"mix/Alpha"}, keys.Nodes)
	for _, tc := range []struct {
		key, filter string
		omit        []string
		want        []string
	}{
		{"org/shared", "own", nil, []string{"own-shared"}},
		{"org/shared", "", []string{"org/shared"}, []string{"Alpha", "own-shared"}},
		{"bbb/foreign", "", nil, nil},
		{"test/escape", "%_", nil, []string{"100%_value"}},
	} {
		t.Run("values/"+tc.key+"/"+tc.filter, func(t *testing.T) {
			conn, err := app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: tc.key, Search: &tc.filter, Omit: tc.omit})
			require.NoError(t, err)
			require.Equal(t, tc.want, conn.Nodes)
		})
	}
	values, err := app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "org/shared", First: &one})
	require.NoError(t, err)
	require.Equal(t, []string{"Alpha"}, values.Nodes)
	require.True(t, values.PageInfo.HasNextPage)
	values, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{After: values.PageInfo.EndCursor, First: &one})
	require.NoError(t, err)
	require.Equal(t, []string{"own-shared"}, values.Nodes)
	require.False(t, values.PageInfo.HasNextPage)

	// Exercise both sides of the legacy case-sensitive cursor OR expression.
	// Supplying each case avoids depending on the database's text collation.
	for _, after := range []string{"mix/Alpha", "mix/alpha"} {
		c, err := search.Cursor(label.KeySearchOptions{After: after, Search: "no-match", Omit: []string{"mix/Alpha", "mix/alpha"}})
		require.NoError(t, err)
		for _, principal := range []string{"user-a", "user-b"} {
			conn, err := app.Query().LabelKeys(serviceLabelHuman(t, h, principal), &graphql2.LabelKeySearchOptions{After: &c})
			require.NoError(t, err)
			foreign := "mix/alpha"
			if principal == "user-b" {
				foreign = "mix/Alpha"
			}
			require.NotContains(t, conn.Nodes, foreign)
		}
	}
	for _, after := range []string{"Alpha", "alpha"} {
		c, err := search.Cursor(label.ValueSearchOptions{Key: "unrelated/key", KeySearchOptions: label.KeySearchOptions{After: after, Search: "no-match"}})
		require.NoError(t, err)
		for _, principal := range []string{"user-a", "user-b"} {
			conn, err := app.Query().LabelValues(serviceLabelHuman(t, h, principal), &graphql2.LabelValueSearchOptions{After: &c})
			require.NoError(t, err)
			foreign := "alpha"
			if principal == "user-b" {
				foreign = "Alpha"
			}
			require.NotContains(t, conn.Nodes, foreign)
		}
	}
	_, err = h.App().DB().Exec(`INSERT INTO labels(tgt_service_id,key,value) VALUES
	 ($1,'omit/test','val/own'), ($2,'omit/test','val/other'), ($3,'omit/test','val/foreign')`,
		serviceLabelID("a"), serviceLabelID("a2"), serviceLabelID("b"))
	require.NoError(t, err)
	values, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "omit/test", Omit: []string{"val/other"}, First: &one})
	require.NoError(t, err)
	require.Equal(t, []string{"val/own"}, values.Nodes)
	require.False(t, values.PageInfo.HasNextPage)
	// A cursor is pagination state, never a source of Organization authority.
	forged, err := search.Cursor(map[string]any{"OrganizationID": serviceLabelID("org-b"), "organizationID": serviceLabelID("org-b")})
	require.NoError(t, err)
	keys, err = app.Query().LabelKeys(ctx, &graphql2.LabelKeySearchOptions{After: &forged})
	require.NoError(t, err)
	require.NotContains(t, keys.Nodes, "bbb/foreign")
}

func TestGraphQLServiceLabelOrganizationWrites(t *testing.T) {
	h := serviceLabelHarness(t)
	app := serviceLabelApp(h)
	const mutation = `mutation($input:SetLabelInput!) { setLabel(input:$input) }`
	for _, principal := range []string{"user-a", "admin-a"} {
		for _, tc := range []struct{ key, value string }{{"new/label", "created"}, {"new/label", "updated"}, {"new/label", ""}} {
			t.Run(principal+"/own/"+tc.value, func(t *testing.T) {
				response := serviceLabelHTTP(t, h, principal, mutation, serviceLabelVariables("a", tc.key, tc.value))
				require.Empty(t, response.Errors)
				require.JSONEq(t, `{"setLabel":true}`, string(response.Data))
				var value string
				err := h.App().DB().QueryRow(`SELECT value FROM labels WHERE tgt_service_id=$1 AND key=$2`, serviceLabelID("a"), tc.key).Scan(&value)
				if tc.value == "" {
					require.ErrorIs(t, err, sql.ErrNoRows)
				} else {
					require.NoError(t, err)
					require.Equal(t, tc.value, value)
				}
			})
		}
		for _, tc := range []struct{ key, value string }{{"new/label", "created"}, {"org/shared", "updated"}, {"org/shared", ""}} {
			t.Run(principal+"/foreign/"+tc.value, func(t *testing.T) {
				before := serviceLabelSnapshot(t, h, "b")
				wait := h.ExpectBackendError("sql: no rows in result set")
				response := serviceLabelHTTP(t, h, principal, mutation, serviceLabelVariables("b", tc.key, tc.value))
				wait()
				require.NotEmpty(t, response.Errors)
				require.Equal(t, before, serviceLabelSnapshot(t, h, "b"))
			})
		}
	}
	ctx := serviceLabelHuman(t, h, "user-a")
	ok, err := app.Mutation().SetLabel(ctx, serviceLabelInput("absent", "aaa/own", ""))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = app.Mutation().SetLabel(ctx, serviceLabelInput("absent", "aaa/own", "value"))
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.False(t, ok)

	// Legacy nil/System/API-key compatibility does not acquire human scope.
	for _, ctx := range []context.Context{
		permission.SystemContext(h.Config().Context(t.Context()), "Smoketest"),
		permission.UserSourceContext(h.Config().Context(t.Context()), serviceLabelID("user-a"), permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: serviceLabelID("api")}),
	} {
		conn, err := app.Query().LabelKeys(ctx, nil)
		require.NoError(t, err)
		require.Contains(t, conn.Nodes, "bbb/foreign")
		for _, value := range []string{"created", "updated", ""} {
			ok, err := app.Mutation().SetLabel(ctx, serviceLabelInput("b", "new/compatibility", value))
			require.NoError(t, err)
			require.True(t, ok)
		}
	}
}
