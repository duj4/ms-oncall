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
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
)

// A controlled SQL driver exercises the real stores, authority, generated
// executable and HTTP handler. It does not prove PostgreSQL execution, database
// constraints, signed Session admission or production runtime behavior.
type ikIdentityRecord struct {
	id, serviceID string
	audit         driver.Value
	kind          integrationkey.Type
	external      string
}
type ikIdentityFixture struct {
	keys                []ikIdentityRecord
	services            map[string]uuid.UUID
	brokenJoin          bool
	queryError          error
	projectedID         driver.Value
	auditReads, queries atomic.Int64
}
type ikIdentityConnector struct{ f *ikIdentityFixture }

func (c ikIdentityConnector) Connect(context.Context) (driver.Conn, error) {
	return ikIdentityConn(c), nil
}
func (ikIdentityConnector) Driver() driver.Driver { return ikAuthorityDriver{} }

type ikIdentityConn struct{ f *ikIdentityFixture }

func (c ikIdentityConn) Prepare(q string) (driver.Stmt, error) { return &ikIdentityStmt{c, q}, nil }
func (ikIdentityConn) Close() error                            { return nil }
func (ikIdentityConn) Begin() (driver.Tx, error) {
	return nil, errors.New("identity reads must not begin a transaction")
}

type ikIdentityStmt struct {
	c     ikIdentityConn
	query string
}

func (*ikIdentityStmt) Close() error  { return nil }
func (*ikIdentityStmt) NumInput() int { return -1 }
func (*ikIdentityStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("identity reads must not mutate")
}
func (s *ikIdentityStmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return s.c.QueryContext(context.Background(), s.query, named)
}

type ikIdentityRows struct {
	cols []string
	rows [][]driver.Value
}

func (r *ikIdentityRows) Columns() []string { return r.cols }
func (*ikIdentityRows) Close() error        { return nil }
func (r *ikIdentityRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}
func (c ikIdentityConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	f.queries.Add(1)
	q := strings.Join(strings.Fields(query), " ")
	arg := func(i int) string { return fmt.Sprint(args[i].Value) }
	rows := func(cols ...string) *ikIdentityRows { return &ikIdentityRows{cols: cols} }
	if strings.HasPrefix(q, "SELECT k.id, k.audit_resource_id,") {
		f.auditReads.Add(1)
		// Check bounded predicates, ownership joins, and parameterization separately
		// from the fixture's record lookup. Never select a fixture by name/order.
		if !strings.Contains(q, "JOIN services s ON s.id = k.service_id") ||
			!strings.Contains(q, "JOIN organizations o ON o.id = s.organization_id AND o.classification = 'NORMAL'") ||
			!strings.Contains(q, "JOIN normal_organizations n ON n.organization_id = o.id AND n.organization_classification = o.classification") ||
			!strings.Contains(q, "WHERE k.id = $1 AND s.organization_id <> $2") ||
			len(args) != 2 || arg(1) != organization.DefaultOrganizationID {
			return nil, errors.New("identity query must retain its ownership predicates")
		}
		if f.queryError != nil {
			return nil, f.queryError
		}
		r := rows("id", "audit_resource_id", "service_id", "organization_id", "type")
		for _, k := range f.keys {
			org, exists := f.services[k.serviceID]
			if k.id == arg(0) && exists && !f.brokenJoin && org.String() != organization.DefaultOrganizationID {
				var id driver.Value = k.id
				if f.projectedID != nil {
					id = f.projectedID
				}
				r.rows = append(r.rows, []driver.Value{id, k.audit, k.serviceID, org.String(), string(k.kind)})
			}
		}
		return r, nil
	}
	if strings.HasPrefix(q, "SELECT s.organization_id, k.type FROM integration_keys k") || strings.HasPrefix(q, "SELECT type FROM integration_keys WHERE") {
		r := rows("organization_id", "type")
		for _, k := range f.keys {
			if k.id == arg(0) {
				if org, ok := f.services[k.serviceID]; ok && !f.brokenJoin {
					if len(args) == 1 {
						r.cols = []string{"type"}
						r.rows = append(r.rows, []driver.Value{string(k.kind)})
					} else {
						r.rows = append(r.rows, []driver.Value{org.String(), string(k.kind)})
					}
				}
			}
		}
		return r, nil
	}
	if strings.HasPrefix(q, "SELECT s.organization_id FROM services s") || strings.HasPrefix(q, "SELECT r.organization_id FROM services r") {
		r := rows("organization_id")
		if org, ok := f.services[arg(0)]; ok && !f.brokenJoin && org.String() != organization.DefaultOrganizationID {
			r.rows = append(r.rows, []driver.Value{org.String()})
		}
		return r, nil
	}
	if strings.Contains(q, "-- name: IntKeyFindOne") || strings.Contains(q, "-- name: IntKeyFindByService") || strings.HasPrefix(q, "SELECT k.id, k.name, k.type, k.service_id, k.external_system_name") {
		r := rows("id", "name", "type", "service_id", "external_system_name")
		one := strings.Contains(q, "-- name: IntKeyFindOne")
		foreignList := strings.HasPrefix(q, "SELECT k.id,")
		for _, k := range f.keys {
			match := k.serviceID == arg(0)
			if one {
				match = k.id == arg(0)
			}
			org, ok := f.services[k.serviceID]
			if !match || !ok || len(args) < 2 || org.String() != arg(1) || (foreignList && k.kind == integrationkey.TypeUniversal) {
				continue
			}
			var ext driver.Value
			if k.external != "" {
				ext = k.external
			}
			r.rows = append(r.rows, []driver.Value{k.id, "same synthetic name", string(k.kind), k.serviceID, ext})
		}
		return r, nil
	}
	if strings.HasPrefix(q, "SELECT s.id, s.organization_id, s.name,") {
		r := rows("id", "org", "name", "description", "ep", "ep_name", "favorite", "maintenance")
		for id, org := range f.services {
			if strings.Contains(arg(0), id) && (len(args) < 3 || arg(2) == org.String()) {
				r.rows = append(r.rows, []driver.Value{id, org.String(), "Synthetic service", "", uuid.NewString(), "Synthetic EP", false, nil})
			}
		}
		return r, nil
	}
	return nil, errors.New("unexpected identity fixture query")
}
func ikIdentityHarness(t *testing.T, role organization.OrganizationRole, pa bool) (context.Context, *App, *ikIdentityFixture, *ikAuthorityFixture) {
	t.Helper()
	ctx, _, admission := ikAuthorityContext(t, role, pa)
	sid := uuid.NewString()
	f := &ikIdentityFixture{services: map[string]uuid.UUID{sid: admission.home}, keys: []ikIdentityRecord{{id: uuid.NewString(), serviceID: sid, audit: uuid.NewString(), kind: integrationkey.TypeGeneric}}}
	db := sql.OpenDB(ikIdentityConnector{f})
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	store, err := service.NewStore(ctx, db)
	require.NoError(t, err)
	return ctx, &App{DB: db, IntKeyStore: integrationkey.NewStore(ctx, db, nil, nil, nil), ServiceStore: store}, f, admission
}
func (k ikIdentityRecord) parent() *integrationkey.IntegrationKey {
	return &integrationkey.IntegrationKey{ID: k.id, ServiceID: k.serviceID, Type: k.kind}
}
func ikIdentityDenied(t *testing.T, got string, err error, private ...string) {
	t.Helper()
	require.Empty(t, got)
	require.True(t, permission.IsPermissionError(err), "expected a safe permission error")
	require.Equal(t, integrationKeyAccessDenied().Error(), err.Error())
	for _, v := range private {
		if v != "" {
			require.NotContains(t, err.Error(), v)
		}
	}
}
func TestIntegrationKeyAuditResourceIDAuthority(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleMember, organization.OrganizationRoleAdmin} {
		for _, pa := range []bool{false, true} {
			for _, kind := range []integrationkey.Type{integrationkey.TypeGeneric, integrationkey.TypeGrafana, integrationkey.TypeSite24x7, integrationkey.TypePrometheusAlertmanager, integrationkey.TypeEmail, integrationkey.TypeUniversal} {
				for _, foreign := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/PA=%t/%s/foreign=%t", role, pa, kind, foreign), func(t *testing.T) {
						ctx, app, f, _ := ikIdentityHarness(t, role, pa)
						f.keys[0].kind = kind
						if foreign {
							f.services[f.keys[0].serviceID] = uuid.New()
						}
						got, err := app.IntegrationKey().AuditResourceID(ctx, f.keys[0].parent())
						allow := (pa || role == organization.OrganizationRoleAdmin) && (!foreign || (pa && kind != integrationkey.TypeUniversal))
						if allow {
							require.NoError(t, err)
							require.Equal(t, f.keys[0].audit, got)
							require.NotEqual(t, f.keys[0].id, got)
						} else {
							ikIdentityDenied(t, got, err, f.keys[0].id)
						}
						if !pa && role == organization.OrganizationRoleMember {
							require.Zero(t, f.queries.Load())
						}
					})
				}
			}
		}
	}
}
func TestIntegrationKeyAuditResourceIDIdentityConflicts(t *testing.T) {
	ctx, app, f, a := ikIdentityHarness(t, organization.OrganizationRoleAdmin, true)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	bare := permission.UserSourceContext(context.Background(), a.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: a.session.String()})
	contexts := map[string]context.Context{
		"missing":                   context.Background(),
		"bare admin":                permission.UserContext(context.Background(), a.user.String(), permission.RoleAdmin),
		"missing execution context": auth.WithRequester(bare, *auth.RequesterFromContext(ctx)),
		"zero execution context":    executioncontext.WithExecutionContext(auth.WithRequester(bare, *auth.RequesterFromContext(ctx)), executioncontext.ExecutionContext{}),
		"missing requester":         executioncontext.WithExecutionContext(bare, *executioncontext.ExecutionContextFromContext(ctx)),
		"conflicting requester":     auth.WithRequester(ctx, other),
		"conflicting session":       permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"PA disagreement":           permission.UserContext(ctx, a.user.String(), permission.RoleUser),
		"sudo human":                permission.SystemContext(ctx, "Test"),
		"machine":                   permission.UserSourceContext(context.Background(), a.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"integration":               permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
	}
	for name, c := range contexts {
		t.Run(name, func(t *testing.T) {
			got, err := app.IntegrationKey().AuditResourceID(c, f.keys[0].parent())
			ikIdentityDenied(t, got, err)
		})
	}
	require.Zero(t, f.queries.Load())
	// Only the existing explicit, source-less System compatibility path is valid.
	got, err := app.IntegrationKey().AuditResourceID(permission.SystemContext(context.Background(), "Engine"), f.keys[0].parent())
	require.NoError(t, err)
	require.Equal(t, f.keys[0].audit, got)
}
func TestIntegrationKeyAuditResourceIDRawParents(t *testing.T) {
	tests := map[string]func(*integrationkey.IntegrationKey, *ikIdentityFixture) *integrationkey.IntegrationKey{
		"nil": func(_ *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			return nil
		},
		"empty": func(_ *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			return &integrationkey.IntegrationKey{}
		},
		"invalid legacy": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ID = "invalid-credential"
			return p
		},
		"zero legacy": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ID = uuid.Nil.String()
			return p
		},
		"missing key": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ID = uuid.NewString()
			return p
		},
		"audit as selector": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ID = f.keys[0].audit.(string)
			return p
		},
		"invalid service": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ServiceID = "invalid-service"
			return p
		},
		"empty service": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ServiceID = ""
			return p
		},
		"zero service": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ServiceID = uuid.Nil.String()
			return p
		},
		"forged service": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.ServiceID = uuid.NewString()
			return p
		},
		"forged type": func(p *integrationkey.IntegrationKey, _ *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.Type = integrationkey.TypeUniversal
			return p
		},
		"missing audit": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.keys[0].audit = nil
			return p
		},
		"invalid audit": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.keys[0].audit = "invalid-private-audit"
			return p
		},
		"zero audit": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.keys[0].audit = uuid.Nil.String()
			return p
		},
		"equal audit and legacy": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.keys[0].audit = p.ID
			return p
		},
		"missing service": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			delete(f.services, p.ServiceID)
			return p
		},
		"broken normal organization join": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.brokenJoin = true
			return p
		},
		"default organization": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.services[p.ServiceID] = uuid.MustParse(organization.DefaultOrganizationID)
			return p
		},
		"zero organization": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.services[p.ServiceID] = uuid.Nil
			return p
		},
		"unknown type": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			p.Type = "unknown"
			f.keys[0].kind = p.Type
			return p
		},
		"query error": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.queryError = errors.New("private SQL parameter synthetic-routing-token")
			return p
		},
		"query timeout": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.queryError = context.DeadlineExceeded
			return p
		},
		"query canceled": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.queryError = context.Canceled
			return p
		},
		"mismatched record": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.projectedID = uuid.NewString()
			return p
		},
		"invalid stored legacy": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.projectedID = "invalid-private-legacy"
			return p
		},
		"zero stored legacy": func(p *integrationkey.IntegrationKey, f *ikIdentityFixture) *integrationkey.IntegrationKey {
			f.projectedID = uuid.Nil.String()
			return p
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, true)
			raw := edit(f.keys[0].parent(), f)
			got, err := app.IntegrationKey().AuditResourceID(ctx, raw)
			ikIdentityDenied(t, got, err, f.keys[0].id, "invalid-private-audit", "synthetic-routing-token")
		})
	}
	t.Run("forged audit JSON has no trusted model field", func(t *testing.T) {
		ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, false)
		p := f.keys[0].parent()
		forged := uuid.NewString()
		require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"auditResourceID":%q,"audit_resource_id":%q}`, forged, forged)), p))
		got, err := app.IntegrationKey().AuditResourceID(ctx, p)
		require.NoError(t, err)
		require.Equal(t, f.keys[0].audit, got)
		require.NotEqual(t, forged, got)
		encoded, err := json.Marshal(p)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), got)
	})
}

func TestIntegrationKeyAuditResourceIDDefaultHome(t *testing.T) {
	for _, pa := range []bool{false, true} {
		t.Run(fmt.Sprintf("PA=%t", pa), func(t *testing.T) {
			ctx, app, f, admission := ikIdentityHarness(t, organization.OrganizationRoleAdmin, pa)
			// Reconstruct canonical admission with a Default Home, retaining
			// the real Normal target rather than trusting any parent Org value.
			admission.home = uuid.MustParse(organization.DefaultOrganizationID)
			admission.role = organization.OrganizationRoleNone
			db := sql.OpenDB(ikAuthorityConnector{admission})
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
			require.NoError(t, err)
			ec, err := constructor.Construct(ctx)
			require.NoError(t, err)
			ctx = executioncontext.WithExecutionContext(ctx, ec)
			got, err := app.IntegrationKey().AuditResourceID(ctx, f.keys[0].parent())
			if pa {
				require.NoError(t, err)
				require.Equal(t, f.keys[0].audit, got)
			} else {
				ikIdentityDenied(t, got, err)
			}
			f.services[f.keys[0].serviceID] = admission.home
			got, err = app.IntegrationKey().AuditResourceID(ctx, f.keys[0].parent())
			ikIdentityDenied(t, got, err)
			got, err = app.IntegrationKey().AuditResourceID(permission.SystemContext(context.Background(), "Engine"), f.keys[0].parent())
			ikIdentityDenied(t, got, err)
		})
	}
}

func TestIntegrationKeyAuditResourceIDServiceLists(t *testing.T) {
	for _, mode := range []string{"one", "many", "reversed", "empty", "externally managed", "universal", "foreign PA"} {
		t.Run(mode, func(t *testing.T) {
			ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, mode == "foreign PA")
			sid := f.keys[0].serviceID
			if mode == "many" || mode == "reversed" || mode == "foreign PA" {
				f.keys = append(f.keys, ikIdentityRecord{id: uuid.NewString(), serviceID: sid, audit: uuid.NewString(), kind: integrationkey.TypeUniversal})
			}
			if mode == "reversed" {
				f.keys[0], f.keys[1] = f.keys[1], f.keys[0]
			}
			if mode == "externally managed" {
				f.keys[0].external = "synthetic-provisioner"
			}
			if mode == "universal" {
				f.keys[0].kind = integrationkey.TypeUniversal
			}
			if mode == "foreign PA" {
				f.services[sid] = uuid.New()
			}
			if mode == "empty" {
				f.keys = nil
			}
			parents, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: sid})
			require.NoError(t, err)
			expected := len(f.keys)
			if mode == "foreign PA" {
				expected--
			}
			require.Len(t, parents, expected)
			seen := map[string]bool{}
			for _, p := range parents {
				got, err := app.IntegrationKey().AuditResourceID(ctx, &p)
				require.NoError(t, err)
				for _, k := range f.keys {
					if k.id == p.ID {
						require.Equal(t, k.audit, got)
						require.Equal(t, k.kind, p.Type)
						require.Equal(t, k.external, p.ExternalSystemName)
					}
				}
				require.False(t, seen[got])
				seen[got] = true
				require.NotEqual(t, p.ID, got)
			}
		})
	}
	for _, change := range []string{"organization moved", "service rebound", "key deleted", "partial invalid audit"} {
		t.Run("cached list/"+change, func(t *testing.T) {
			ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, false)
			sid := f.keys[0].serviceID
			f.keys = append(f.keys, ikIdentityRecord{id: uuid.NewString(), serviceID: sid, audit: uuid.NewString(), kind: integrationkey.TypeGeneric})
			parents, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: sid})
			require.NoError(t, err)
			require.Len(t, parents, 2)
			switch change {
			case "organization moved":
				f.services[sid] = uuid.New()
			case "service rebound":
				f.keys[0].serviceID = uuid.NewString()
				f.services[f.keys[0].serviceID] = f.services[sid]
			case "key deleted":
				f.keys = f.keys[1:]
			case "partial invalid audit":
				f.keys[0].audit = uuid.Nil.String()
			}
			got, err := app.IntegrationKey().AuditResourceID(ctx, &parents[0])
			ikIdentityDenied(t, got, err)
			if change != "organization moved" {
				got, err = app.IntegrationKey().AuditResourceID(ctx, &parents[1])
				require.NoError(t, err)
				require.Equal(t, f.keys[len(f.keys)-1].audit, got)
			}
		})
	}
}
func ikIdentityHTTP(t *testing.T, ctx context.Context, app *App, query string) (map[string]any, []string, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/graphql", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	var result struct {
		Data   map[string]any
		Errors []struct{ Message string }
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	var messages []string
	for _, e := range result.Errors {
		messages = append(messages, e.Message)
	}
	return result.Data, messages, rec.Body.String()
}
func TestIntegrationKeyAuditResourceIDGraphQLHTTP(t *testing.T) {
	ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, false)
	schema := graphql2.NewExecutableSchema(graphql2.Config{Resolvers: app}).Schema()
	require.Equal(t, "ID!", schema.Types["IntegrationKey"].Fields.ForName("auditResourceID").Type.String())
	k := f.keys[0]
	for _, query := range []string{
		fmt.Sprintf(`{integrationKey(id:%q){id auditResourceID}}`, k.id),
		fmt.Sprintf(`{alias:integrationKey(id:%q){...Identity}} fragment Identity on IntegrationKey{legacy:id audit:auditResourceID}`, k.id),
		fmt.Sprintf(`{service(id:%q){integrationKeys{id auditResourceID}}}`, k.serviceID),
		fmt.Sprintf(`{s:service(id:%q){keys:integrationKeys{...Identity}}} fragment Identity on IntegrationKey{legacy:id audit:auditResourceID}`, k.serviceID),
	} {
		_, errs, body := ikIdentityHTTP(t, ctx, app, query)
		require.Empty(t, errs)
		require.Contains(t, body, k.id)
		require.Contains(t, body, k.audit.(string))
	}
	before := f.auditReads.Load()
	data, errs, body := ikIdentityHTTP(t, ctx, app, fmt.Sprintf(`{integrationKey(id:%q){id type serviceID name externalSystemName}}`, k.id))
	require.Empty(t, errs)
	require.Equal(t, k.id, data["integrationKey"].(map[string]any)["id"])
	require.NotContains(t, body, "auditResourceID")
	require.NotContains(t, body, k.audit.(string))
	require.Equal(t, before, f.auditReads.Load(), "unselected field must not read the mapping")
	// Multiple same-name records arrive in a different order. Match each pair
	// by its actual legacy selector, including an externally managed Key.
	f.keys = append([]ikIdentityRecord{{id: uuid.NewString(), serviceID: k.serviceID, audit: uuid.NewString(), kind: integrationkey.TypeUniversal, external: "synthetic-provisioner"}}, f.keys...)
	data, errs, _ = ikIdentityHTTP(t, ctx, app, fmt.Sprintf(`{service(id:%q){integrationKeys{id auditResourceID externalSystemName}}}`, k.serviceID))
	require.Empty(t, errs)
	parents := data["service"].(map[string]any)["integrationKeys"].([]any)
	require.Len(t, parents, 2)
	for i, parent := range parents {
		p := parent.(map[string]any)
		require.Equal(t, f.keys[i].id, p["id"])
		require.Equal(t, f.keys[i].audit, p["auditResourceID"])
	}
	for _, id := range []string{"", "invalid-private-selector", uuid.Nil.String(), uuid.NewString(), k.audit.(string)} {
		_, errs, body := ikIdentityHTTP(t, ctx, app, fmt.Sprintf(`{integrationKey(id:%q){auditResourceID}}`, id))
		require.NotEmpty(t, errs)
		require.NotContains(t, body, k.audit.(string))
		require.NotContains(t, body, "invalid-private-selector")
	}
	// A failed non-null field must bubble an error, without publishing the mapping.
	for _, failure := range []string{"invalid audit", "query error", "broken relationship"} {
		t.Run(failure, func(t *testing.T) {
			ctx, app, f, _ := ikIdentityHarness(t, organization.OrganizationRoleAdmin, false)
			k := f.keys[0]
			switch failure {
			case "invalid audit":
				f.keys[0].audit = uuid.Nil.String()
			case "query error":
				f.queryError = errors.New("synthetic-private-sql-token")
			case "broken relationship":
				f.brokenJoin = true
			}
			_, errs, body := ikIdentityHTTP(t, ctx, app, fmt.Sprintf(`{integrationKey(id:%q){a:auditResourceID}}`, k.id))
			require.NotEmpty(t, errs)
			require.Contains(t, errs[0], "access denied")
			require.NotContains(t, body, k.id)
			require.NotContains(t, body, k.audit.(string))
			require.NotContains(t, body, "synthetic-private-sql-token")
		})
	}
}
func TestIntegrationKeyAuditResourceIDGraphQLHTTPAuthority(t *testing.T) {
	for _, mode := range []string{"member", "non PA foreign", "PA foreign normal", "PA foreign universal", "default target"} {
		t.Run(mode, func(t *testing.T) {
			role := organization.OrganizationRoleAdmin
			if mode == "member" {
				role = organization.OrganizationRoleMember
			}
			ctx, app, f, _ := ikIdentityHarness(t, role, strings.HasPrefix(mode, "PA"))
			if strings.Contains(mode, "foreign") {
				f.services[f.keys[0].serviceID] = uuid.New()
			}
			if mode == "PA foreign universal" {
				f.keys[0].kind = integrationkey.TypeUniversal
			}
			if mode == "default target" {
				f.services[f.keys[0].serviceID] = uuid.MustParse(organization.DefaultOrganizationID)
			}
			k := f.keys[0]
			for _, nested := range []bool{false, true} {
				query := fmt.Sprintf(`{x:integrationKey(id:%q){...F}} fragment F on IntegrationKey{a:auditResourceID}`, k.id)
				if nested {
					query = fmt.Sprintf(`{x:service(id:%q){keys:integrationKeys{...F}}} fragment F on IntegrationKey{a:auditResourceID}`, k.serviceID)
				}
				_, errs, body := ikIdentityHTTP(t, ctx, app, query)
				if mode == "PA foreign normal" {
					require.Empty(t, errs)
					require.Contains(t, body, k.audit.(string))
				} else if nested && mode == "PA foreign universal" {
					require.Empty(t, errs)
					require.Contains(t, body, `"keys":[]`)
					require.NotContains(t, body, k.audit.(string))
				} else if nested && (mode == "non PA foreign" || mode == "default target") {
					// Existing scoped Service reads return null for an
					// unavailable parent, before resolving any Key fields.
					require.Empty(t, errs)
					require.Contains(t, body, `"x":null`)
					require.NotContains(t, body, k.audit.(string))
					require.NotContains(t, body, k.id)
				} else {
					require.NotEmpty(t, errs)
					require.NotContains(t, body, k.audit.(string))
					require.NotContains(t, body, k.id)
				}
			}
		})
	}
}
