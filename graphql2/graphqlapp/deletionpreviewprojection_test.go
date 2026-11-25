package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/vektah/gqlparser/v2"
)

// Synthetic SQL-driver fixtures exercise projection and admission, not real
// PostgreSQL semantics, signed authentication or runtime deletion execution.
type previewProjectionFixture struct {
	missing, duplicate ds.ResourceKind
	unexpected         bool
	queries            []string
	org                uuid.UUID
	human              *ikAuthorityFixture
}
type previewProjectionConnector struct{ f *previewProjectionFixture }

func (c previewProjectionConnector) Connect(context.Context) (driver.Conn, error) {
	return previewProjectionConn(c), nil
}
func (previewProjectionConnector) Driver() driver.Driver { return ikAuthorityDriver{} }

type previewProjectionConn struct{ f *previewProjectionFixture }

func (previewProjectionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (previewProjectionConn) Close() error              { return nil }
func (previewProjectionConn) Begin() (driver.Tx, error) { return previewProjectionTx{}, nil }
func (previewProjectionConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if !o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("expected read-only repeatable read")
	}
	return previewProjectionTx{}, nil
}

type previewProjectionTx struct{}

func (previewProjectionTx) Commit() error   { return errors.New("preview must not commit") }
func (previewProjectionTx) Rollback() error { return nil }

type previewProjectionRows struct {
	columns []string
	rows    [][]driver.Value
}

func (r *previewProjectionRows) Columns() []string { return r.columns }
func (*previewProjectionRows) Close() error        { return nil }
func (r *previewProjectionRows) Next(out []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(out, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}
func previewRows(columns []string, rows ...[]driver.Value) driver.Rows {
	return &previewProjectionRows{columns, rows}
}
func (c previewProjectionConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	f.queries = append(f.queries, q)
	for kind, query := range previewNameQueries {
		if q != query {
			continue
		}
		var ids pq.StringArray
		if err := ids.Scan(args[0].Value); err != nil {
			return nil, err
		}
		var rows [][]driver.Value
		for _, id := range ids {
			if kind == f.missing {
				continue
			}
			rows = append(rows, []driver.Value{id, "Safe display name " + id})
		}
		if kind == f.duplicate && len(rows) > 1 {
			rows[1] = rows[0]
		}
		if f.unexpected && len(rows) > 0 {
			rows[0][0] = uuid.NewString()
		}
		return previewRows([]string{"id", "name"}, rows...), nil
	}
	switch {
	case strings.Contains(q, "current_setting('transaction_read_only')"):
		return previewRows([]string{"read_only", "isolation", "observed"}, []driver.Value{"on", "repeatable read", time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}), nil
	case strings.Contains(q, "SELECT organization_id::text,user_role::text,organization_role::text FROM user_org"):
		role := "user"
		if f.human.platformAdmin {
			role = "admin"
		}
		return previewRows([]string{"org", "role", "org_role"}, []driver.Value{f.human.home.String(), role, string(f.human.role)}), nil
	case strings.Contains(q, "SELECT organization_id::text FROM public.services WHERE id="):
		return previewRows([]string{"org"}, []driver.Value{f.org.String()}), nil
	case strings.Contains(q, "SELECT display_name FROM organizations"):
		return previewRows([]string{"name"}, []driver.Value{"Safe organization"}), nil
	default:
		return nil, errors.New("unexpected SQL in projection fixture")
	}
}
func previewProjectionDB(t *testing.T, f *previewProjectionFixture) *sql.DB {
	t.Helper()
	db := sql.OpenDB(previewProjectionConnector{f})
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}
func previewProjectionTransaction(t *testing.T, f *previewProjectionFixture) *sql.Tx {
	t.Helper()
	tx, err := previewProjectionDB(t, f).BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}
func previewObject(kind ds.ResourceKind, name string) ds.Resource {
	return ds.Resource{Kind: kind, ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()}
}
func previewPlanInput(root ds.Resource, deps ...ds.Dependency) ds.PlanInput {
	input := ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: []ds.Resource{root}, ScopeFingerprint: strings.Repeat("a", 64),
		Intent:     []ds.DestructiveChange{{Resource: root, Kind: ds.ChangeDeleted}},
		Collection: ds.Collection{Completeness: ds.DependenciesComplete, Checked: []ds.Resource{root}, Dependencies: deps}}
	for _, d := range deps {
		input.Collection.Checked = append(input.Collection.Checked, d.Target, d.Referencing)
	}
	return input
}
func previewPlan(t *testing.T, input ds.PlanInput) ds.DeletionPlan {
	t.Helper()
	p, err := ds.BuildPlan(input, ds.Budget{})
	require.NoError(t, err)
	return p
}
func previewUserAction(t *testing.T) (ds.DeletionPlan, ds.Dependency) {
	t.Helper()
	d := ds.Dependency{Target: previewObject(ds.ResourceUser, "U"), Referencing: previewObject(ds.ResourceEscalationPolicyAction, "A"),
		Parent: previewObject(ds.ResourceEscalationPolicyStep, "S"), Owner: previewObject(ds.ResourceEscalationPolicy, "P"), Relationship: ds.RelationshipActionTarget}
	return previewPlan(t, previewPlanInput(d.Target, d)), d
}
func previewProject(t *testing.T, p ds.DeletionPlan, page []ds.DeletionImpact, f *previewProjectionFixture) (*graphql2.DeletionPreview, error) {
	t.Helper()
	ctx := permission.SystemContext(context.Background(), "PreviewProjectionTest")
	a, err := newPreviewAuthority(ctx)
	require.NoError(t, err)
	binding := newDeletionPreviewCursor(p.Targets(), strings.Repeat("a", 64), p.ImpactVersion())
	return projectDeletionPreview(ctx, previewProjectionTransaction(t, f), a, p, page, binding, nil, previewTestSigner{})
}
func TestDeletionPreviewProjectionDerivedCausality(t *testing.T) {
	p, d := previewUserAction(t)
	before := p.Impacts()
	require.Len(t, before, 3)
	require.False(t, p.CanProceed())
	require.Equal(t, &ds.DeletionSafetyError{Code: ds.DeletionBlocked}, p.Check(p.ImpactVersion(), true))
	all, err := previewProject(t, p, before, &previewProjectionFixture{})
	require.NoError(t, err)
	var direct string
	for _, impact := range before {
		if !impact.IsDerived {
			direct = impact.EdgeID
		}
	}
	require.NotEmpty(t, direct)
	affected := map[string]bool{}
	for i, impact := range before {
		node := all.Impacts.Edges[i].Node
		require.Equal(t, impact.EdgeID, node.EdgeID)
		require.Equal(t, d.Target.ID, node.Target.ID)
		require.Equal(t, d.Referencing.ID, node.ReferencingResource.ID)
		require.Equal(t, d.Parent.ID, node.Parent.ID)
		require.Equal(t, d.Owner.ID, node.Owner.ID)
		require.Equal(t, impact.Affected.ID, node.AffectedResource.ID)
		require.Equal(t, previewResourceNames[impact.Affected.Kind], node.AffectedResource.Type)
		if impact.IsDerived {
			require.Equal(t, direct, *node.DerivedFrom)
			require.Equal(t, graphql2.DeletionPolicyInformational, node.Policy)
			require.Equal(t, "PRESERVED", node.Change)
			affected[node.AffectedResource.ID] = true
		} else {
			require.Nil(t, node.DerivedFrom)
			require.Equal(t, graphql2.DeletionPolicyBlock, node.Policy)
		}
		// Project every edge alone: the direct cause need not be on the page.
		one, err := previewProject(t, p, []ds.DeletionImpact{impact}, &previewProjectionFixture{})
		require.NoError(t, err)
		require.Equal(t, *all.Impacts.Edges[i].Node, *one.Impacts.Edges[0].Node)
		require.Equal(t, all.Impacts.Edges[i].Cursor, one.Impacts.Edges[0].Cursor)
		cursor, err := decodeDeletionPreviewCursor(previewTestSigner{}, one.Impacts.Edges[0].Cursor)
		require.NoError(t, err)
		require.Equal(t, impact.EdgeID, cursor.Position)
		require.Equal(t, p.ImpactVersion(), cursor.Impact)
		require.Equal(t, ds.PolicyVersion, cursor.Policy)
	}
	require.Equal(t, map[string]bool{d.Parent.ID: true, d.Owner.ID: true}, affected)
	require.Equal(t, before, p.Impacts())
	require.Equal(t, p.ImpactVersion(), all.ImpactVersion)
	require.Equal(t, ds.PolicyVersion, all.PolicyVersion)
	require.Len(t, all.Targets, 1)
}
func TestDeletionPreviewProjectionOwnerDedupAndAbsence(t *testing.T) {
	u := previewObject(ds.ResourceUser, "U")
	schedule := previewObject(ds.ResourceSchedule, "schedule")
	for _, tc := range []struct {
		name  string
		dep   ds.Dependency
		count int
	}{
		{"same parent and owner", ds.Dependency{Target: u, Referencing: previewObject(ds.ResourceScheduleRule, "rule"), Parent: schedule, Owner: schedule, Relationship: ds.RelationshipRuleTarget}, 2},
		{"no owner", ds.Dependency{Target: u, Referencing: previewObject(ds.ResourceAlertLog, "log"), Relationship: ds.RelationshipUserLog}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := previewPlan(t, previewPlanInput(u, tc.dep))
			require.Len(t, p.Impacts(), tc.count)
			result, err := previewProject(t, p, p.Impacts(), &previewProjectionFixture{})
			require.NoError(t, err)
			for _, edge := range result.Impacts.Edges {
				if tc.dep.Owner == (ds.Resource{}) {
					require.Nil(t, edge.Node.Owner)
					require.Nil(t, edge.Node.Parent)
				} else {
					require.Equal(t, edge.Node.Parent, edge.Node.Owner)
				}
				require.NotNil(t, edge.Node.AffectedResource)
			}
		})
	}
}
func TestDeletionPreviewProjectionRejectsAlteredPlannerRows(t *testing.T) {
	p, _ := previewUserAction(t)
	var direct, derived ds.DeletionImpact
	for _, d := range p.Impacts() {
		if d.IsDerived {
			derived = d
		} else {
			direct = d
		}
	}
	for name, mutate := range map[string]func(*ds.DeletionImpact){
		"missing cause":     func(d *ds.DeletionImpact) { d.DerivedFrom = "" },
		"wrong cause":       func(d *ds.DeletionImpact) { d.DerivedFrom = strings.Repeat("b", 64) },
		"wrong affected":    func(d *ds.DeletionImpact) { d.Affected = d.Target },
		"missing affected":  func(d *ds.DeletionImpact) { d.Affected = ds.Resource{} },
		"swapped ancestors": func(d *ds.DeletionImpact) { d.Owner, d.Parent = d.Parent, d.Owner },
		"unknown kind":      func(d *ds.DeletionImpact) { d.Owner.Kind = 255 },
		"invalid id":        func(d *ds.DeletionImpact) { d.Owner.ID = "unsafe?destination=private" },
		"empty id":          func(d *ds.DeletionImpact) { d.Owner.ID = "" },
		"foreign owner":     func(d *ds.DeletionImpact) { d.Owner.ID = uuid.NewString() },
		"false direct":      func(d *ds.DeletionImpact) { d.IsDerived = false },
		"changed edge":      func(d *ds.DeletionImpact) { d.EdgeID = strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := derived
			mutate(&bad)
			f := &previewProjectionFixture{}
			result, err := previewProject(t, p, []ds.DeletionImpact{bad}, f)
			require.Equal(t, previewUnavailable(), err)
			require.Nil(t, result)
			require.Empty(t, f.queries)
		})
	}
	direct.DerivedFrom = derived.EdgeID
	result, err := previewProject(t, p, []ds.DeletionImpact{direct}, &previewProjectionFixture{})
	require.Equal(t, previewUnavailable(), err)
	require.Nil(t, result)
	// The planner accepts safe composite identities; the wire projection must
	// still reject unknown/unsafe identities rather than fabricate a label.
	for _, id := range []string{"", "private?locator", strings.Repeat("a", 257)} {
		input := previewPlanInput(previewObject(ds.ResourceUser, "U"), ds.Dependency{})
		input.Collection.Dependencies = nil
		input.Targets[0].ID = id
		input.Intent[0].Resource = input.Targets[0]
		input.Collection.Checked = input.Targets
		_, err := ds.BuildPlan(input, ds.Budget{})
		require.Error(t, err)
	}
}
func TestDeletionPreviewProjectionCatalogFailsClosed(t *testing.T) {
	p, _ := previewUserAction(t)
	for _, f := range []*previewProjectionFixture{{missing: ds.ResourceEscalationPolicy}, {missing: ds.ResourceUser}, {unexpected: true}} {
		result, err := previewProject(t, p, p.Impacts(), f)
		require.Equal(t, previewUnavailable(), err)
		require.Nil(t, result)
	}
	// Two distinct Owner names must not be satisfied by two copies of one row.
	p, d := previewUserAction(t)
	other := d
	other.Owner = previewObject(ds.ResourceEscalationPolicy, "other policy")
	other.Parent = previewObject(ds.ResourceEscalationPolicyStep, "other step")
	other.Referencing = previewObject(ds.ResourceEscalationPolicyAction, "other action")
	p = previewPlan(t, previewPlanInput(p.Targets()[0], d, other))
	result, err := previewProject(t, p, p.Impacts(), &previewProjectionFixture{duplicate: ds.ResourceEscalationPolicy})
	require.Equal(t, previewUnavailable(), err)
	require.Nil(t, result)
}
func TestDeletionPreviewProjectionEightRootCompatibility(t *testing.T) {
	u := previewObject(ds.ResourceUser, "owner")
	s := previewObject(ds.ResourceService, "service")
	schedule := previewObject(ds.ResourceSchedule, "schedule")
	for _, kind := range []ds.ResourceKind{ds.ResourceEscalationPolicy, ds.ResourceSchedule, ds.ResourceRotation, ds.ResourceNotificationRule, ds.ResourceUserOverride, ds.ResourceContactMethod, ds.ResourceService, ds.ResourceIntegrationKey} {
		t.Run(previewResourceNames[kind], func(t *testing.T) {
			root := previewObject(kind, "root")
			var deps []ds.Dependency
			switch kind {
			case ds.ResourceNotificationRule:
				deps = []ds.Dependency{{Target: root, Referencing: u, Relationship: ds.RelationshipNotificationConfiguration, State: ds.BusinessState{NotificationRisk: ds.NotificationRiskNone}}}
			case ds.ResourceIntegrationKey:
				deps = []ds.Dependency{{Target: root, Referencing: s, Relationship: ds.RelationshipIntegrationSource}}
			case ds.ResourceUserOverride:
				deps = []ds.Dependency{{Target: root, Referencing: schedule, Relationship: ds.RelationshipOverrideCoverage, State: ds.BusinessState{Period: ds.PeriodEnded}, Before: ds.Configuration{WindowStart: time.Unix(1, 0), WindowEnd: time.Unix(2, 0)}}}
			default:
				deps = []ds.Dependency{{Target: root, Referencing: previewObject(ds.ResourceFavorite, "favorite"), Relationship: ds.RelationshipFavorite}}
				if kind == ds.ResourceContactMethod {
					deps[0] = ds.Dependency{Target: root, Referencing: u, Relationship: ds.RelationshipStatusContact}
				}
			}
			p := previewPlan(t, previewPlanInput(root, deps...))
			old := p.Impacts()
			result, err := previewProject(t, p, old, &previewProjectionFixture{})
			require.NoError(t, err)
			require.Equal(t, old, p.Impacts())
			require.Equal(t, p.ImpactVersion(), result.ImpactVersion)
			require.Len(t, result.Targets, 1)
			require.Equal(t, root.ID, result.Targets[0].ID)
			for i, edge := range result.Impacts.Edges {
				require.Equal(t, old[i].Affected.ID, edge.Node.AffectedResource.ID)
				require.Equal(t, old[i].EdgeID, edge.Node.EdgeID)
			}
		})
	}
}
func TestDeletionPreviewProjectionSafeAuditIdentity(t *testing.T) {
	u := previewObject(ds.ResourceUser, "U")
	audit := previewObject(ds.ResourceUserSession, "safe session audit identity")
	d := ds.Dependency{Target: u, Referencing: audit, Relationship: ds.RelationshipUserIdentity, Before: ds.Configuration{References: []ds.Resource{u}}}
	p := previewPlan(t, previewPlanInput(u, d))
	f := &previewProjectionFixture{}
	result, err := previewProject(t, p, p.Impacts(), f)
	require.NoError(t, err)
	require.Equal(t, audit.ID, result.Impacts.Edges[0].Node.AffectedResource.ID)
	require.Equal(t, "USER_SESSION "+audit.ID, result.Impacts.Edges[0].Node.AffectedResource.Label)
	require.Nil(t, result.Impacts.Edges[0].Node.Owner)
	b, err := json.Marshal(result)
	require.NoError(t, err)
	for _, word := range []string{"token", "password", "destination", "credential", "payload"} {
		require.NotContains(t, strings.ToLower(string(b)), word)
	}
	for _, q := range f.queries {
		require.NotContains(t, q, "auth_user_sessions")
	}
	require.Equal(t, `SELECT audit_resource_id::text,name FROM integration_keys WHERE audit_resource_id=ANY($1::uuid[])`, previewNameQueries[ds.ResourceIntegrationKey])
}
func TestDeletionPreviewAffectedReadAuthority(t *testing.T) {
	for _, pa := range []bool{false, true} {
		ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, pa)
		a, err := newPreviewAuthority(ctx)
		require.NoError(t, err)
		owner := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
		other := previewObject(ds.ResourceUser, "other")
		for _, kind := range []ds.ResourceKind{ds.ResourceAuthSubject, ds.ResourceUserSession, ds.ResourceBasicAuthLink, ds.ResourceVerificationState} {
			impact := ds.DeletionImpact{Dependency: ds.Dependency{Owner: other}, Decision: ds.Decision{Affected: previewObject(kind, "private audit identity")}}
			require.Equal(t, pa, a.canReadImpact(impact, nil), "foreign affected identity")
			impact.Before.References = []ds.Resource{owner}
			require.True(t, a.canReadImpact(impact, nil), "own affected identity")
			impact.Before.References = nil
			require.True(t, a.canReadImpact(impact, map[ds.Resource]ds.Resource{impact.Affected: owner}), "collected verification owner")
			impact.Affected = ds.Resource{}
			impact.Owner = previewObject(ds.ResourceUserSession, "private owner")
			require.Equal(t, pa, a.canReadImpact(impact, nil), "foreign owner identity")
		}
	}
	system, err := newPreviewAuthority(permission.SystemContext(context.Background(), "ProjectionTest"))
	require.NoError(t, err)
	require.True(t, system.canReadImpact(ds.DeletionImpact{Decision: ds.Decision{Affected: previewObject(ds.ResourceUserSession, "audit")}}, nil))
}
func TestDeletionPreviewProjectionAuthorityBoundary(t *testing.T) {
	for _, pa := range []bool{false, true} {
		ctx, _, human := ikAuthorityContext(t, organization.OrganizationRoleMember, pa)
		a, err := newPreviewAuthority(ctx)
		require.NoError(t, err)
		for _, cross := range []bool{false, true} {
			f := &previewProjectionFixture{org: human.home, human: human}
			if cross {
				f.org = uuid.New()
			}
			tx := previewProjectionTransaction(t, f)
			called := false
			accepted := false
			_, err := collector.Collect(ctx, tx, previewObject(ds.ResourceService, "root"), collector.Preview, collector.DefaultLimits(), func(ctx context.Context, tx *sql.Tx, target collector.Target) error {
				called = true
				err := a.authorizeTarget(ctx, tx, target)
				accepted = err == nil
				if err != nil {
					return err
				}
				return errors.New("stop fixture after root authorization")
			})
			require.Error(t, err)
			require.Equal(t, !cross, called, "foreign roots are denied during collection")
			require.Equal(t, pa && !cross, accepted)
		}
		role := permission.RoleUser
		if pa {
			role = permission.RoleAdmin
		}
		bare := auth.WithRequester(permission.UserSourceContext(context.Background(), human.user.String(), role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: human.session.String()}), *auth.RequesterFromContext(ctx))
		for _, bad := range []context.Context{permission.SystemContext(ctx, "mixed"), executioncontext.WithExecutionContext(bare, executioncontext.ExecutionContext{}), permission.UserContext(context.Background(), human.user.String(), permission.RoleAdmin), auth.WithRequester(permission.SystemContext(context.Background(), "mixed"), *auth.RequesterFromContext(ctx))} {
			_, err := newPreviewAuthority(bad)
			require.Error(t, err)
		}
	}
	systemCtx := permission.SystemContext(context.Background(), "ProjectionTest")
	a, err := newPreviewAuthority(systemCtx)
	require.NoError(t, err)
	f := &previewProjectionFixture{org: uuid.New()}
	_, err = collector.Collect(systemCtx, previewProjectionTransaction(t, f), previewObject(ds.ResourceService, "root"), collector.Preview, collector.DefaultLimits(), func(ctx context.Context, tx *sql.Tx, target collector.Target) error {
		require.NoError(t, a.authorizeTarget(ctx, tx, target))
		return errors.New("stop fixture after system authorization")
	})
	require.Error(t, err)
}
func TestDeletionPreviewProjectionSchemaCompatibility(t *testing.T) {
	schema := graphql2.NewExecutableSchema(graphql2.Config{}).Schema()
	for field, typ := range map[string]string{"owner": "DeletionResource", "derivedFrom": "ID", "affectedResource": "DeletionResource"} {
		require.Equal(t, typ, schema.Types["DeletionImpact"].Fields.ForName(field).Type.String())
	}
	for _, root := range graphql2.AllDeletionTargetType {
		query := `query {deletionPreview(input:{operation:DELETE_RESOURCES,targets:[{type:` + string(root) + `,id:"00000000-0000-4000-8000-000000000001"}]}){targets{type id name label organization{id name}} operation impactVersion policyVersion complete canProceed requiresConfirmation impacts{edges{cursor node{edgeID target{type id} referencingResource{type id} parent{type id} relation change policy impact requiredAction canModifyReference isDerived isPlannedCoDeletion}}pageInfo{endCursor hasNextPage}}}}`
		_, err := gqlparser.LoadQueryWithRules(schema, query, nil)
		require.Empty(t, err)
	}
	_, err := gqlparser.LoadQueryWithRules(schema, `query{deletionPreview(input:{operation:DELETE_RESOURCES,targets:[{type:USER,id:"00000000-0000-4000-8000-000000000001"}]}){impacts{edges{node{owner{type id label} derivedFrom affectedResource{type id label}}}}}}`, nil)
	require.Empty(t, err)
}
func TestDeletionPreviewProjectionPlannerFailureBoundaries(t *testing.T) {
	_, d := previewUserAction(t)
	input := previewPlanInput(d.Target, d)
	for _, complete := range []ds.DependencyCompleteness{ds.DependenciesUnknown, ds.DependenciesIncomplete, ds.DependenciesUnsupported} {
		bad := input
		bad.Collection.Completeness = complete
		_, err := ds.BuildPlan(bad, ds.Budget{})
		require.Error(t, err)
	}
	_, err := ds.BuildPlan(input, ds.Budget{MaxTargets: 1, MaxDependencies: 1, MaxImpacts: 1})
	require.Equal(t, &ds.DeletionSafetyError{Code: ds.DeletionPreviewLimitExceeded}, err)
	unblocked := previewPlanInput(d.Target, ds.Dependency{Target: d.Target, Referencing: previewObject(ds.ResourceAlertLog, "history"), Relationship: ds.RelationshipUserLog})
	p := previewPlan(t, unblocked)
	changed := unblocked
	changed.ScopeFingerprint = strings.Repeat("b", 64)
	newer := previewPlan(t, changed)
	require.NotEqual(t, p.ImpactVersion(), newer.ImpactVersion())
	require.Equal(t, &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}, newer.Check(p.ImpactVersion(), true))
	require.True(t, slices.IsSortedFunc(p.Impacts(), func(a, b ds.DeletionImpact) int { return strings.Compare(a.EdgeID, b.EdgeID) }))
}
