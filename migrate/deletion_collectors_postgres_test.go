package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type deletionFixture struct {
	boundedFixture
	policy, step, service, key, keyAudit, cm, nr, override, channel, participant, session, sessionAudit uuid.UUID
	closed, active                                                                                      int64
	now                                                                                                 time.Time
}

func newDeletionFixture(t *testing.T, ctx context.Context, db *sql.DB) deletionFixture {
	t.Helper()
	f := deletionFixture{boundedFixture: newBoundedFixture(t, ctx, db), policy: uuid.New(), step: uuid.New(), service: uuid.New(), key: uuid.New(), cm: uuid.New(), nr: uuid.New(), override: uuid.New(), channel: uuid.New(), session: uuid.New()}
	_, roleErr := db.ExecContext(ctx, `UPDATE users SET role='user' WHERE id=$1 OR id=$2`, f.actor, f.user)
	require.NoError(t, roleErr)
	store := organization.NewStore(db)
	for _, id := range []uuid.UUID{f.actor, f.user} {
		_, err := store.CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{UserID: id, UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID: f.org, EffectiveOrganizationClassification: organization.ClassificationNormal, Role: organization.OrganizationRoleMember, MappingOutcome: organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{AuthoritativeEvaluatedAt: time.Now(), SourceConfigVersion: "synthetic-collector-test", MatchedCount: 1}}})
		require.NoError(t, err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := db.ExecContext(ctx, query, args...)
		require.NoError(t, err)
	}
	exec(`INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, f.policy, f.org)
	exec(`INSERT INTO escalation_policy_steps(id,escalation_policy_id,step_number) VALUES($1,$2,0)`, f.step, f.policy)
	exec(`INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, f.service, f.org, f.policy)
	exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, f.step, f.user)
	exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, f.step, f.schedule)
	exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, f.step, f.rotation)
	exec(`INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.user)
	exec(`INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.rotation)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&f.now))
	exec(`INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5,$6)`, f.override, f.schedule, f.user, f.actor, f.now.Add(-time.Hour), f.now.Add(time.Hour))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM rotation_participants WHERE rotation_id=$1`, f.rotation).Scan(&f.participant))
	exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value,dest,pending) VALUES($1,$2,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text),false)`, f.cm, f.user)
	exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, f.nr, f.user, f.cm)
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'synthetic key','generic') RETURNING audit_resource_id`, f.key, f.service).Scan(&f.keyAudit))
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,summary) VALUES($1,'closed','SYNTHETIC_PRIVATE_ALERT') RETURNING id`, f.service).Scan(&f.closed))
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'triggered',$2,'SYNTHETIC_PRIVATE_ALERT') RETURNING id`, f.service, uuid.New().String()).Scan(&f.active))
	var acknowledged int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'active',$2,'SYNTHETIC_PRIVATE_ALERT') RETURNING id`, f.service, uuid.NewString()).Scan(&acknowledged))
	exec(`INSERT INTO escalation_policy_state(alert_id,escalation_policy_id,escalation_policy_step_id,service_id) VALUES($1,$3,$4,$5),($2,$3,$4,$5) ON CONFLICT(alert_id) DO UPDATE SET escalation_policy_step_id=excluded.escalation_policy_step_id`, f.closed, f.active, f.policy, f.step, f.service)
	exec(`INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2),($1,$3)`, f.user, f.closed, f.active)
	exec(`INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2)`, f.user, acknowledged)
	exec(`INSERT INTO outgoing_messages(id,user_id,contact_method_id,service_id,schedule_id,escalation_policy_id,alert_id,message_type) VALUES($1,$2,$3,$4,$5,$6,$7,'test_notification')`, uuid.New(), f.user, f.cm, f.service, f.schedule, f.policy, f.closed)
	exec(`INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text))`, f.channel)
	exec(`INSERT INTO pending_signals(service_id,dest_id,params) VALUES($1,$2,'{"private":"SYNTHETIC_PRIVATE_SIGNAL"}')`, f.service, f.channel)
	exec(`INSERT INTO user_favorites(user_id,tgt_rotation_id) VALUES($1,$2)`, f.actor, f.rotation)
	exec(`INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time) VALUES($1,$2,$3)`, f.schedule, f.user, f.now.Add(-time.Hour))
	exec(`INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time) VALUES($1,$2,$3)`, f.step, f.user, f.now.Add(-time.Hour))
	exec(`INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('synthetic',$1,$2,$3)`, uuid.New().String(), f.user, f.cm)
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO auth_user_sessions(id,user_id) VALUES($1,$2) RETURNING audit_resource_id`, f.session, f.user).Scan(&f.sessionAudit))
	exec(`INSERT INTO auth_basic_users(user_id,username,password_hash) VALUES($1,($1::uuid)::text,'SYNTHETIC_NOT_A_REAL_PASSWORD_HASH')`, f.user)
	exec(`INSERT INTO gql_api_keys(id,name,description,policy,expires_at,created_by,updated_by,deleted_by) VALUES($1,($1::uuid)::text,'synthetic','{}',$2,$3,$3,$3)`, uuid.New(), f.now.Add(time.Hour), f.user)
	setDeletionJSON(t, ctx, db, f, f.user.String(), f.now.Add(-2*time.Hour), f.now.Add(2*time.Hour))
	return f
}

func setDeletionJSON(t *testing.T, ctx context.Context, db *sql.DB, f deletionFixture, user string, start, end time.Time) {
	t.Helper()
	raw := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}}`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), user)
	_, err := db.ExecContext(ctx, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb) ON CONFLICT(schedule_id) DO UPDATE SET data=excluded.data`, f.schedule, raw)
	require.NoError(t, err)
}

func collectDeletion(t *testing.T, ctx context.Context, db *sql.DB, root ds.Resource, limits collector.Limits) (collector.Result, error) {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback()) }()
	result, err := collector.Collect(ctx, tx, root, collector.Preview, limits, authorizeDeletionFixture(root))
	var readOnly string
	if err == nil {
		require.NoError(t, tx.QueryRowContext(ctx, `SHOW transaction_read_only`).Scan(&readOnly), "collector must leave ownership with caller")
		require.Equal(t, "on", readOnly)
	}
	return result, err
}

// This fixture is an explicitly trusted server allowlist, independent of the
// selector reaching Collect. Production callers must supply their real policy.
func authorizeDeletionFixture(approved ds.Resource) collector.AuthorizeFacts {
	return func(_ context.Context, _ *sql.Tx, target collector.Target) error {
		if target.Resource() != approved {
			return fmt.Errorf("synthetic authorization rejected")
		}
		return nil
	}
}

func deletionPlan(t *testing.T, root ds.Resource, result collector.Result) ds.DeletionPlan {
	t.Helper()
	plan, err := ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: []ds.Resource{root}, Intent: []ds.DestructiveChange{{Resource: root, Kind: ds.ChangeDeleted}}, ScopeFingerprint: result.ScopeFingerprint, Collection: result.Collection}, ds.Budget{})
	require.NoError(t, err)
	return plan
}

// Hash every public business/audit row server-side. Synthetic credential fields
// never leave PostgreSQL and are not printed. This also covers notification
// jobs, all successful audit witnesses, assignments, and migration provenance.
func deletionSnapshot(t *testing.T, ctx context.Context, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname`)
	require.NoError(t, err)
	var names []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		names = append(names, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	result := map[string]string{}
	for _, name := range names {
		var hash string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT md5(COALESCE(jsonb_agg(v ORDER BY v::text)::text,'[]')) FROM (SELECT to_jsonb(t) v FROM `+pgx.Identifier{"public", name}.Sanitize()+` t) rows`).Scan(&hash))
		result[name] = hash
	}
	return result
}

func TestPostgresDeletionCollectorsRootGraphs(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionCollectorsTest")
	withoutState := uuid.NewString()
	corruptDeletionFixture(t, ctx, db, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'triggered',$2,'synthetic no runtime state')`, f.service, withoutState)
	var withoutStateID int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM alerts WHERE dedup_key=$1`, withoutState).Scan(&withoutStateID))
	before := deletionSnapshot(t, ctx, db)
	policies := map[ds.DeletionPolicy]bool{}
	for _, tc := range []struct {
		kind    ds.ResourceKind
		id      uuid.UUID
		blocked bool
	}{
		{ds.ResourceService, f.service, true}, {ds.ResourceEscalationPolicy, f.policy, true}, {ds.ResourceSchedule, f.schedule, true},
		{ds.ResourceRotation, f.rotation, true}, {ds.ResourceUser, f.user, true}, {ds.ResourceContactMethod, f.cm, false},
		{ds.ResourceNotificationRule, f.nr, false}, {ds.ResourceIntegrationKey, f.keyAudit, false}, {ds.ResourceUserOverride, f.override, false},
	} {
		t.Run(fmt.Sprint(tc.kind), func(t *testing.T) {
			root := ds.Resource{Kind: tc.kind, ID: tc.id.String()}
			limits := collector.DefaultLimits()
			limits.PageSize = 1
			result, err := collectDeletion(t, ctx, db, root, limits)
			require.NoError(t, err)
			require.Equal(t, ds.DependenciesComplete, result.Collection.Completeness)
			plan := deletionPlan(t, root, result)
			require.Equal(t, !tc.blocked, plan.CanProceed())
			for _, impact := range plan.Impacts() {
				policies[impact.Policy] = true
			}
			if tc.kind == ds.ResourceRotation || tc.kind == ds.ResourceSchedule {
				for _, change := range plan.Changes() {
					require.NotEqual(t, ds.ResourceUser, change.Resource.Kind, "staffing targets must survive")
				}
			}
			if tc.kind == ds.ResourceService {
				states := map[ds.AlertState]bool{}
				for _, d := range result.Collection.Dependencies {
					if d.Relationship == ds.RelationshipServiceAlert {
						states[d.State.Alert] = true
					}
				}
				require.True(t, states[ds.AlertTriggered])
				require.True(t, states[ds.AlertActive])
				require.True(t, states[ds.AlertClosed])
			}
			if tc.kind == ds.ResourceEscalationPolicy {
				found := false
				for _, d := range result.Collection.Dependencies {
					if d.Relationship == ds.RelationshipServiceAlert && d.Referencing.ID == fmt.Sprint(withoutStateID) {
						found = true
					}
				}
				require.True(t, found, "Policy collection must include open Alerts without execution-state rows")
			}
			if tc.kind == ds.ResourceUser {
				for _, change := range plan.Changes() {
					require.NotContains(t, []ds.ResourceKind{ds.ResourceRotation, ds.ResourceSchedule}, change.Resource.Kind)
				}
				var endpoints, fragments int
				for _, d := range result.Collection.Dependencies {
					if d.Relationship == ds.RelationshipOverrideAddUser || d.Relationship == ds.RelationshipOverrideRemoveUser {
						endpoints++
					}
					if d.Relationship == ds.RelationshipShiftUser {
						fragments++
					}
				}
				require.Positive(t, endpoints)
				require.Positive(t, fragments)
			}
			raw, err := json.Marshal(result)
			require.NoError(t, err)
			for _, private := range []string{f.key.String(), f.session.String(), "SYNTHETIC_PRIVATE_ALERT", "SYNTHETIC_PRIVATE_SIGNAL", "SYNTHETIC_NOT_A_REAL_PASSWORD_HASH"} {
				require.NotContains(t, string(raw), private)
			}
		})
	}
	for _, policy := range []ds.DeletionPolicy{ds.PolicyBlock, ds.PolicyCascade, ds.PolicyWarning, ds.PolicyInformational} {
		require.True(t, policies[policy], "planner must preserve every approved V1 policy")
	}
	require.Equal(t, before, deletionSnapshot(t, ctx, db), "read-only collection must preserve every business and audit row")
	// Same row observed through two genuine paths remains one change with both
	// relationships; conflicting observations are rejected by frozen BuildPlan.
	root := ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: f.policy.String()}
	result, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	result.Collection.Dependencies = append(result.Collection.Dependencies, result.Collection.Dependencies...)
	plan := deletionPlan(t, root, result)
	require.False(t, plan.CanProceed())
	for _, change := range plan.Changes() {
		if change.Resource.Kind == ds.ResourceEscalationPolicyAction {
			require.Len(t, change.Edges, 2, "Policy and Step paths must both survive canonical deduplication")
		}
	}
	for i, d := range result.Collection.Dependencies {
		if d.Relationship == ds.RelationshipExecutionState {
			other := d
			other.State.Alert = ds.AlertClosed
			if d.State.Alert == ds.AlertClosed {
				other.State.Alert = ds.AlertTriggered
			}
			result.Collection.Dependencies = append(result.Collection.Dependencies, other)
			_ = i
			break
		}
	}
	_, err = ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: []ds.Resource{root}, Intent: []ds.DestructiveChange{{Resource: root, Kind: ds.ChangeDeleted}}, ScopeFingerprint: result.ScopeFingerprint, Collection: result.Collection}, ds.Budget{})
	require.Error(t, err)
}

func TestPostgresDeletionCollectorsCompletenessAndBounds(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionCollectorsTest")
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	for _, change := range []func(*collector.Limits){
		func(l *collector.Limits) { l.MaxRows = 1 }, func(l *collector.Limits) { l.MaxQueries = 2 }, func(l *collector.Limits) { l.MaxFragments = 1 }, func(l *collector.Limits) { l.MaxJSONBytes = 10 },
		func(l *collector.Limits) { l.PageSize = 1; l.MaxQueries = 4 },
		func(l *collector.Limits) { l.PageSize = 1; l.MaxQueries = 5 },
	} {
		limits := collector.DefaultLimits()
		change(&limits)
		result, err := collectDeletion(t, ctx, db, root, limits)
		var typed *ds.DeletionSafetyError
		require.ErrorAs(t, err, &typed)
		require.Equal(t, ds.DeletionPreviewLimitExceeded, typed.Code)
		require.NotEqual(t, ds.DependenciesComplete, result.Collection.Completeness)
		require.Empty(t, result.Collection.Dependencies)
		require.Empty(t, result.Collection.Checked)
	}
	for _, raw := range []string{`null`, `{}`, `{"V1":null}`, `{"V1":{"TemporarySchedules":null}}`, `{"V1":{"TemporarySchedules":{}}}`, `{"V1":{"TemporarySchedules":[{"Shifts":null}]}}`} {
		_, err := db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, raw, f.schedule)
		require.NoError(t, err)
		result, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.Error(t, err)
		require.NotEqual(t, ds.DependenciesComplete, result.Collection.Completeness)
	}
	setDeletionJSON(t, ctx, db, f, uuid.NewString(), f.now.Add(-time.Hour), f.now.Add(time.Hour))
	schedule := ds.Resource{Kind: ds.ResourceSchedule, ID: f.schedule.String()}
	result, err := collectDeletion(t, ctx, db, schedule, collector.Limits{})
	require.Error(t, err)
	require.Empty(t, result.Collection.Dependencies, "raw nonexistent UserID must not disappear as an empty scan")
	setDeletionJSON(t, ctx, db, f, f.user.String(), f.now.Add(-time.Hour), f.now.Add(time.Hour))
	// Same-owner equality is real relational evidence, not an unconditional flag.
	_, err = db.ExecContext(ctx, `UPDATE user_notification_rules SET user_id=$1 WHERE id=$2`, f.actor, f.nr)
	require.Error(t, err, "native trigger already enforces same-owner equality")
	corruptDeletionFixture(t, ctx, db, `UPDATE user_notification_rules SET user_id=$1 WHERE id=$2`, f.actor, f.nr)
	result, err = collectDeletion(t, ctx, db, ds.Resource{Kind: ds.ResourceContactMethod, ID: f.cm.String()}, collector.Limits{})
	require.Error(t, err)
	require.Empty(t, result.Collection.Dependencies)
	_, err = db.ExecContext(ctx, `UPDATE user_notification_rules SET user_id=$1 WHERE id=$2`, f.user, f.nr)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO labels(tgt_schedule_id,key,value) VALUES($1,'synthetic','synthetic')`, f.schedule)
	require.NoError(t, err)
	result, err = collectDeletion(t, ctx, db, schedule, collector.Limits{})
	require.Error(t, err)
	require.Equal(t, ds.DependenciesUnsupported, result.Collection.Completeness)
	_, err = ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: []ds.Resource{schedule}, Intent: []ds.DestructiveChange{{Resource: schedule, Kind: ds.ChangeDeleted}}, ScopeFingerprint: strings.Repeat("0", 64), Collection: result.Collection}, ds.Budget{})
	require.Error(t, err)
	corruptDeletionFixture(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, uuid.New(), f.user)
	result, err = collectDeletion(t, ctx, db, root, collector.Limits{})
	require.Error(t, err)
	require.NotEqual(t, ds.DependenciesComplete, result.Collection.Completeness)
}

// Deliberately malformed fixtures remain confined to this harness's disposable
// database and connection. Restore the native trigger setting before release.
func corruptDeletionFixture(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `SET session_replication_role=replica`)
	require.NoError(t, err)
	defer func() {
		_, err := conn.ExecContext(ctx, `SET session_replication_role=origin`)
		require.NoError(t, err)
	}()
	_, err = conn.ExecContext(ctx, query, args...)
	require.NoError(t, err)
}

func deletionHuman(t *testing.T, ctx context.Context, db *sql.DB, user uuid.UUID) context.Context {
	t.Helper()
	session := uuid.NewString()
	ctx = permission.UserSourceContext(ctx, user.String(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(user.String(), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
	require.NoError(t, err)
	value, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, value)
}

func TestPostgresDeletionCollectorsScopeAndSnapshot(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	human := deletionHuman(t, ctx, db, f.actor)
	cm := ds.Resource{Kind: ds.ResourceContactMethod, ID: f.cm.String()}
	ownerTx, err := db.BeginTx(human, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	called := false
	_, err = collector.Collect(human, ownerTx, cm, collector.Preview, collector.Limits{}, func(_ context.Context, actual *sql.Tx, target collector.Target) error {
		called = true
		require.Same(t, ownerTx, actual)
		require.Equal(t, f.org, target.OrganizationID())
		require.Equal(t, ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}, target.Owner())
		require.Equal(t, cm, target.Resource())
		return nil
	})
	require.NoError(t, err)
	require.True(t, called)
	require.NoError(t, ownerTx.Rollback())
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	result, err := collectDeletion(t, human, db, root, collector.Limits{})
	require.NoError(t, err)
	require.False(t, deletionPlan(t, root, result).CanProceed())
	foreign := newDeletionFixture(t, ctx, db)
	for _, id := range []uuid.UUID{foreign.user, uuid.New()} {
		result, err := collectDeletion(t, human, db, ds.Resource{Kind: ds.ResourceUser, ID: id.String()}, collector.Limits{})
		require.Error(t, err)
		require.Equal(t, "deletion safety is unavailable", err.Error())
		require.Empty(t, result.Collection.Dependencies)
		require.Empty(t, result.ScopeFingerprint)
	}
	// A foreign referencing object is not filtered away and then reported empty.
	_, err = db.ExecContext(ctx, `INSERT INTO rotation_participants(rotation_id,user_id,position) VALUES($1,$2,2)`, foreign.rotation, f.user)
	require.NoError(t, err)
	result, err = collectDeletion(t, human, db, root, collector.Limits{})
	require.Error(t, err)
	require.Empty(t, result.Collection.Dependencies)
	// An actual resource selector does not confer authority on a legacy context.
	legacy := permission.UserContext(ctx, f.actor.String(), permission.RoleAdmin)
	_, err = collectDeletion(t, legacy, db, root, collector.Limits{})
	require.Error(t, err)
	// A complete empty Policy scan can be planned; complete is distinct from
	// malformed/foreign/timeout/unsupported results above.
	empty := uuid.New()
	_, err = db.ExecContext(ctx, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, empty, f.org)
	require.NoError(t, err)
	policy := ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: empty.String()}
	result, err = collectDeletion(t, human, db, policy, collector.Limits{})
	require.NoError(t, err)
	require.Empty(t, result.Collection.Dependencies)
	require.True(t, deletionPlan(t, policy, result).CanProceed())
	// Caller snapshot remains stable while another connection adds a dependency.
	tx, err := db.BeginTx(human, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	first, err := collector.Collect(human, tx, policy, collector.Preview, collector.Limits{}, authorizeDeletionFixture(policy))
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, uuid.New(), f.org, empty)
	require.NoError(t, err)
	second, err := collector.Collect(human, tx, policy, collector.Preview, collector.Limits{}, authorizeDeletionFixture(policy))
	require.NoError(t, err)
	require.Equal(t, deletionPlan(t, policy, first).ImpactVersion(), deletionPlan(t, policy, second).ImpactVersion())
	require.NoError(t, tx.Rollback())
	fresh, err := collectDeletion(t, human, db, policy, collector.Limits{})
	require.NoError(t, err)
	require.False(t, deletionPlan(t, policy, fresh).CanProceed())
	// Read-write Preview and read-committed snapshots are rejected. Recheck
	// accepts the owning repeatable-read transaction but does not commit it.
	for _, options := range []sql.TxOptions{{Isolation: sql.LevelRepeatableRead}, {ReadOnly: true, Isolation: sql.LevelReadCommitted}} {
		tx, err := db.BeginTx(human, &options)
		require.NoError(t, err)
		_, err = collector.Collect(human, tx, policy, collector.Preview, collector.Limits{}, authorizeDeletionFixture(policy))
		require.Error(t, err)
		require.NoError(t, tx.Rollback())
	}
	tx, err = db.BeginTx(human, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	require.NoError(t, err)
	_, err = collector.Collect(human, tx, policy, collector.Recheck, collector.Limits{}, authorizeDeletionFixture(policy))
	require.NoError(t, err)
	require.NoError(t, tx.Rollback())
	// No history or owner is manufactured to get a plan through validation.
	require.True(t, slices.Contains(result.Collection.Checked, policy))
}
