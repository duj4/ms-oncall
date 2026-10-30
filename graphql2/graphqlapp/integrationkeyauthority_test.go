package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/config"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
)

// These SQL-driver fixtures test application decisions and DB-owned target
// projections, not PostgreSQL query semantics or signed Session admission.
type ikAuthorityFixture struct {
	user, home, session, targetOrg uuid.UUID
	role                           organization.OrganizationRole
	platformAdmin                  bool
	targetType                     integrationkey.Type
	missing                        bool
	queries, begins                int
}

type ikAuthorityConnector struct{ f *ikAuthorityFixture }

func (c ikAuthorityConnector) Connect(context.Context) (driver.Conn, error) {
	return ikAuthorityConn{c.f}, nil
}
func (c ikAuthorityConnector) Driver() driver.Driver { return ikAuthorityDriver{} }

type ikAuthorityDriver struct{}

func (ikAuthorityDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type ikAuthorityConn struct{ f *ikAuthorityFixture }

func (ikAuthorityConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (ikAuthorityConn) Close() error { return nil }
func (c ikAuthorityConn) Begin() (driver.Tx, error) {
	c.f.begins++
	return nil, errors.New("unexpected transaction")
}

type ikAuthorityRows struct{ values []driver.Value }

func (r *ikAuthorityRows) Columns() []string {
	if len(r.values) == 4 {
		return []string{"user", "global_role", "org", "org_role"}
	}
	if len(r.values) == 1 {
		return []string{"org"}
	}
	return []string{"org", "type"}
}
func (*ikAuthorityRows) Close() error { return nil }
func (r *ikAuthorityRows) Next(dest []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(dest, r.values)
	r.values = nil
	return nil
}
func (c ikAuthorityConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	f.queries++
	if strings.Contains(query, "FROM public.users AS u") {
		role := "user"
		if f.platformAdmin {
			role = "admin"
		}
		return &ikAuthorityRows{[]driver.Value{f.user.String(), role, f.home.String(), string(f.role)}}, nil
	}
	if f.missing {
		return &ikAuthorityRows{}, nil
	}
	if strings.Contains(query, "FROM integration_keys k") {
		return &ikAuthorityRows{[]driver.Value{f.targetOrg.String(), string(f.targetType)}}, nil
	}
	if strings.Contains(query, "FROM services s") {
		return &ikAuthorityRows{[]driver.Value{f.targetOrg.String()}}, nil
	}
	return nil, errors.New("unexpected SQL in authority fixture")
}

func ikAuthorityContext(t *testing.T, role organization.OrganizationRole, pa bool) (context.Context, *sql.DB, *ikAuthorityFixture) {
	t.Helper()
	f := &ikAuthorityFixture{user: uuid.New(), home: uuid.New(), session: uuid.New(), role: role, platformAdmin: pa, targetType: integrationkey.TypeGeneric}
	f.targetOrg = f.home
	db := sql.OpenDB(ikAuthorityConnector{f})
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	legacy := permission.RoleUser
	if pa {
		legacy = permission.RoleAdmin
	}
	ctx := permission.UserSourceContext(context.Background(), f.user.String(), legacy, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()})
	r, err := auth.NewRequester(f.user.String(), f.session.String())
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
	require.NoError(t, err)
	ec, err := c.Construct(ctx)
	require.NoError(t, err)
	return (config.Config{}).Context(executioncontext.WithExecutionContext(ctx, ec)), db, f
}

func TestIntegrationKeyAuthorityMemberBoundaries(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	app := new(App) // A denial must happen before any DB/Store/UUID work.
	id := uuid.NewString()
	badCursor := "not-a-cursor"
	checks := map[string]func() error{
		"direct": func() error { _, e := app.Query().IntegrationKey(ctx, id); return e },
		"pageInfo search before cursor parsing": func() error {
			_, e := app.Query().IntegrationKeys(ctx, &graphql2.IntegrationKeySearchOptions{After: &badCursor})
			return e
		},
		"nested": func() error { _, e := app.Service().IntegrationKeys(ctx, &service.Service{ID: id}); return e },
		"raw ID": func() error {
			_, e := app.IntegrationKey().ID(ctx, &integrationkey.IntegrationKey{ID: id, Type: integrationkey.TypeUniversal})
			return e
		},
		"raw href": func() error { _, e := app.IntegrationKey().Href(ctx, &integrationkey.IntegrationKey{ID: id}); return e },
		"create": func() error {
			_, e := app.Mutation().CreateIntegrationKey(ctx, graphql2.CreateIntegrationKeyInput{Name: "key", Type: graphql2.IntegrationKeyTypeGeneric, ServiceID: &id})
			return e
		},
		"nested create": func() error {
			_, e := app.Mutation().CreateService(ctx, graphql2.CreateServiceInput{Name: "service", NewIntegrationKeys: []graphql2.CreateIntegrationKeyInput{{Name: "key", Type: graphql2.IntegrationKeyTypeGeneric}}})
			return e
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			err := check()
			require.True(t, permission.IsPermissionError(err))
			require.NotContains(t, err.Error(), id)
		})
	}
	require.Equal(t, 1, f.queries, "only canonical admission read")
	require.Zero(t, f.begins)
}

func TestIntegrationKeyAuthorityIdentityConflicts(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	contexts := map[string]context.Context{
		"missing":                          context.Background(),
		"bare admin":                       permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin),
		"missing EC":                       auth.WithRequester(permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}), *auth.RequesterFromContext(ctx)),
		"conflicting requester":            auth.WithRequester(ctx, other),
		"conflicting session":              permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"PA disagreement":                  permission.UserContext(ctx, f.user.String(), permission.RoleUser),
		"zero EC cannot install authority": executioncontext.WithExecutionContext(auth.WithRequester(permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}), *auth.RequesterFromContext(ctx)), executioncontext.ExecutionContext{}),
		"sudo Human":                       permission.SystemContext(ctx, "Test"),
		"machine":                          permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"integration":                      permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
	}
	for name, c := range contexts {
		t.Run(name, func(t *testing.T) {
			a, e := integrationKeyManagementAuthority(c)
			require.Nil(t, a)
			require.True(t, permission.IsPermissionError(e))
		})
	}
	a, err := integrationKeyManagementAuthority(permission.SystemContext(context.Background(), "Engine"))
	require.NoError(t, err)
	require.Nil(t, a.home)
	require.False(t, a.platformAdmin)
	require.True(t, a.system)
}

func TestIntegrationKeyAuthorityInvalidTargets(t *testing.T) {
	ctx, db, f := ikAuthorityContext(t, organization.OrganizationRoleMember, true)
	a, err := integrationKeyManagementAuthority(ctx)
	require.NoError(t, err)
	for _, org := range []uuid.UUID{uuid.Nil, uuid.MustParse(organization.DefaultOrganizationID)} {
		f.targetOrg = org
		_, _, err := a.keyTarget(ctx, db, uuid.NewString())
		require.True(t, permission.IsPermissionError(err))
		_, err = a.serviceTarget(ctx, db, uuid.NewString(), integrationkey.TypeGeneric)
		require.True(t, permission.IsPermissionError(err))
	}
	f.targetOrg = uuid.New()
	f.targetType = "unknown"
	_, _, err = a.keyTarget(ctx, db, uuid.NewString())
	require.True(t, permission.IsPermissionError(err))
	scope, err := a.serviceTarget(ctx, db, uuid.NewString(), integrationkey.TypeGeneric)
	require.NoError(t, err)
	require.Equal(t, f.targetOrg, *scope)
	_, err = a.serviceTarget(ctx, db, uuid.NewString(), integrationkey.TypeUniversal)
	require.True(t, permission.IsPermissionError(err))
	// Nil alone is never authority, even with a stray PA bit.
	_, err = (&integrationKeyAuthority{platformAdmin: true}).targetOrganization(f.targetOrg, integrationkey.TypeGeneric)
	require.True(t, permission.IsPermissionError(err))
}

func TestIntegrationKeyAuthorityTargetsAndRawSinks(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleMember, organization.OrganizationRoleAdmin} {
		for _, pa := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/PA=%t", role, pa), func(t *testing.T) {
				ctx, db, f := ikAuthorityContext(t, role, pa)
				app := &App{DB: db}
				id := uuid.NewString()
				for _, kind := range []integrationkey.Type{integrationkey.TypeGeneric, integrationkey.TypeGrafana, integrationkey.TypeSite24x7, integrationkey.TypePrometheusAlertmanager, integrationkey.TypeEmail, integrationkey.TypeUniversal} {
					for _, foreign := range []bool{false, true} {
						f.targetOrg = f.home
						if foreign {
							f.targetOrg = uuid.New()
						}
						f.targetType = kind
						raw := &integrationkey.IntegrationKey{ID: id, Type: integrationkey.TypeUniversal, ServiceID: uuid.NewString()}
						got, err := app.IntegrationKey().ID(ctx, raw)
						allow := (pa || role == organization.OrganizationRoleAdmin) && (!foreign || (pa && kind != integrationkey.TypeUniversal))
						if allow {
							require.NoError(t, err)
							require.Equal(t, id, got)
						} else {
							require.Empty(t, got)
							require.True(t, permission.IsPermissionError(err))
						}
						href, err := app.IntegrationKey().Href(ctx, raw)
						if allow {
							require.NoError(t, err)
							if kind != integrationkey.TypeUniversal && kind != integrationkey.TypeEmail {
								require.Contains(t, href, id)
								require.NotContains(t, href, "/uik")
							}
						} else {
							require.Empty(t, href)
							require.True(t, permission.IsPermissionError(err))
						}
					}
				}
				f.missing = true
				_, err := app.IntegrationKey().ID(ctx, &integrationkey.IntegrationKey{ID: id})
				require.True(t, permission.IsPermissionError(err))
			})
		}
	}
}

func TestIntegrationKeyAuthorityGraphQLSelections(t *testing.T) {
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	id := uuid.NewString()
	app := new(App)
	handler := app.Handler()
	queries := []string{
		fmt.Sprintf(`{integrationKey(id:%q){id href}}`, id),
		fmt.Sprintf(`{k:integrationKey(id:%q){...F}} fragment F on IntegrationKey{x:id href}`, id),
		fmt.Sprintf(`{integrationKey(id:%q){... on IntegrationKey{name type serviceID}}}`, id),
		`{integrationKeys{pageInfo{hasNextPage endCursor}}}`,
		`{integrationKeys(input:{after:"invalid"}){nodes{name}}}`,
		fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"key",type:generic}){__typename}}`, id),
		fmt.Sprintf(`mutation{createIntegrationKey(input:{serviceID:%q,name:"key",type:generic}){name}}`, id),
		`mutation{createService(input:{name:"nested",newIntegrationKeys:[{name:"key",type:generic}]}){__typename}}`,
	}
	for i, q := range queries {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"query": q})
			require.NoError(t, err)
			req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			var result struct {
				Data   json.RawMessage
				Errors []struct{ Message string }
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
			require.NotEmpty(t, result.Errors)
			require.NotContains(t, rec.Body.String(), id)
			require.NotContains(t, rec.Body.String(), "invalid cursor")
			require.Contains(t, result.Errors[0].Message, "access denied")
		})
	}
}
