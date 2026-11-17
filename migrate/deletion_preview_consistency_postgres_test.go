package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

type previewConsistencyFixture struct {
	input graphql2.DeletionPlanInput
	raw   []assignment.RawTarget
	add   func()
	state func() string
	actor uuid.UUID
}

// Each scenario starts with two genuinely executable roots. The unsupported
// relation is inserted only after obtaining a real Preview/Confirmation, so
// the mutation must independently observe it and reject the whole batch.
func newPreviewConsistencyFixture(t *testing.T, ctx context.Context, db *sql.DB, shape string) previewConsistencyFixture {
	t.Helper()
	snapshot := func(query string, args ...any) func() string {
		// Keep a separate physical connection throughout Preview/Mutation.
		// State assertions therefore observe committed results independently
		// of the business transaction and its connection-release lifecycle.
		observer, err := db.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, observer.Close()) })
		return func() string {
			var data string
			require.NoError(t, observer.QueryRowContext(ctx, query, args...).Scan(&data))
			return data
		}
	}
	switch shape {
	case "service_message":
		f, g := newServiceProfileFixture(t, ctx, db), newServiceProfileFixture(t, ctx, db)
		channel := uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, channel)
		return previewConsistencyFixture{
			input: graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: []graphql2.DeletionResourceInput{
				{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()}, {Type: graphql2.DeletionTargetTypeService, ID: g.service.String()},
			}}, raw: serviceProfileInput(f.service, g.service), actor: f.actor,
			add: func() {
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(service_id,channel_id,message_type,last_status,sent_at) VALUES($1,$2,'test_notification','sent',now())`, f.service, channel)
			},
			state: snapshot(`SELECT jsonb_build_array(
			 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM services s WHERE id IN ($1,$2)),
			 (SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM outgoing_messages m WHERE service_id IN ($1,$2)),
			 (SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed'))::text`, f.service, g.service),
		}
	case "schedule_history_open", "schedule_history_ended":
		f, g := newScheduleProfileFixture(t, ctx, db, true), newScheduleProfileFixture(t, ctx, db, true)
		return previewConsistencyFixture{
			input: graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: scheduleProfilePreviewInput(f.schedule, g.schedule)},
			raw:   scheduleProfileInput(f.schedule, g.schedule), actor: f.actor,
			add: func() {
				end := "NULL"
				if shape == "schedule_history_ended" {
					end = "now()-'1h'::interval"
				}
				enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,now()-'2h'::interval,`+end+`)`, f.schedule, f.user)
			},
			state: snapshot(`SELECT jsonb_build_array(
			 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM schedules s WHERE id IN ($1,$2)),
			 (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM schedule_on_call_users h WHERE schedule_id IN ($1,$2)),
			 (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM schedule_rules r WHERE schedule_id IN ($1,$2)),
			 (SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM user_overrides o WHERE tgt_schedule_id IN ($1,$2)),
			 (SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE outcome='committed'))::text`, f.schedule, g.schedule),
		}
	case "user_closed_cycle":
		f, g := userNativeLifecycle(t, ctx, db, 1, 1, true), userNativeLifecycle(t, ctx, db, 1, 1, true)
		policy, service := uuid.New(), uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, policy, f.org)
		serviceProfileInsert(t, ctx, db, service, f.org, policy)
		aid := serviceProfileAlert(t, ctx, db, service, "closed")
		actor := uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO users(id,name,role) VALUES($1,'synthetic consistency actor','admin')`, actor)
		enforcementExec(t, ctx, db, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'preview-consistency',1)`, actor, f.org)
		return previewConsistencyFixture{
			input: graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: userProfilePreview(f.user, g.user)},
			raw:   userProfileInput(f.user, g.user), actor: actor,
			add: func() {
				enforcementExec(t, ctx, db, `INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2)`, f.user, aid)
			},
			state: snapshot(`SELECT jsonb_build_array(
			 (SELECT jsonb_agg(to_jsonb(u) ORDER BY id) FROM users u WHERE id IN ($1,$2)),
			 (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM notification_policy_cycles c WHERE user_id IN ($1,$2)),
			 (SELECT jsonb_agg(audit_resource_id ORDER BY audit_resource_id) FROM auth_user_sessions WHERE user_id IN ($1,$2)),
			 (SELECT jsonb_agg(id ORDER BY id) FROM user_contact_methods WHERE user_id IN ($1,$2)),
			 (SELECT jsonb_agg(id ORDER BY id) FROM user_notification_rules WHERE user_id IN ($1,$2)),
			 (SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'),
			 (SELECT count(*) FROM user_delete_audit_effects),
			 (SELECT count(*) FROM user_session_revoke_audit_events WHERE record_kind='success_witness'))::text`, f.user, g.user),
		}
	default:
		t.Fatal("unknown synthetic consistency scenario")
		return previewConsistencyFixture{}
	}
}

// Produce the current domain version without the native feasibility gate. This
// is test evidence, never a guard or authority, and cannot bypass enforcement.
func previewConsistencyVersion(t *testing.T, ctx context.Context, db *sql.DB, input graphql2.DeletionPlanInput) string {
	t.Helper()
	var targets []ds.Resource
	var intent []ds.DestructiveChange
	var fingerprints []string
	collection := ds.Collection{Completeness: ds.DependenciesComplete}
	kinds := map[graphql2.DeletionTargetType]ds.ResourceKind{graphql2.DeletionTargetTypeService: ds.ResourceService, graphql2.DeletionTargetTypeSchedule: ds.ResourceSchedule, graphql2.DeletionTargetTypeUser: ds.ResourceUser}
	for _, target := range input.Targets {
		root := ds.Resource{Kind: kinds[target.Type], ID: target.ID}
		facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.NoError(t, err)
		targets = append(targets, root)
		intent = append(intent, ds.DestructiveChange{Resource: root, Kind: ds.ChangeDeleted})
		fingerprints = append(fingerprints, facts.ScopeFingerprint)
		collection.Checked = append(collection.Checked, facts.Collection.Checked...)
		collection.Dependencies = append(collection.Dependencies, facts.Collection.Dependencies...)
	}
	fp, err := collector.BatchScopeFingerprint(targets, fingerprints)
	require.NoError(t, err)
	plan, err := ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: targets, Intent: intent, Collection: collection, ScopeFingerprint: fp}, ds.Budget{})
	require.NoError(t, err)
	require.True(t, plan.CanProceed(), "this scenario isolates the static native capability gap")
	return plan.ImpactVersion()
}

func TestPostgresDeletionPreviewStaticAuditConsistency(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "PreviewConsistencyNative")
	app := enforcementApp(t, ctx, db)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT current_setting('server_version')`).Scan(&version))
	require.Equal(t, "17.11", version)
	require.Equal(t, 307, enforcementCount(t, ctx, db, `SELECT max(canonical_position) FROM ms_oncall_migration_provenance`))
	require.Equal(t, 307, enforcementCount(t, ctx, db, `SELECT count(*) FROM gorp_migrations`))
	require.Equal(t, 3, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND confdeltype='c' AND (
	 (conrelid='outgoing_messages'::regclass AND confrelid='services'::regclass) OR
	 (conrelid='schedule_on_call_users'::regclass AND confrelid='schedules'::regclass) OR
	 (conrelid='notification_policy_cycles'::regclass AND confrelid='users'::regclass))`))
	for _, shape := range []string{"service_message", "schedule_history_open", "schedule_history_ended", "user_closed_cycle"} {
		t.Run(shape, func(t *testing.T) {
			f := newPreviewConsistencyFixture(t, ctx, db, shape)
			before := f.state()
			p := previewOK(t, previewHTTP(t, ctx, app, f.input, 1, nil))
			require.True(t, p.CanProceed)
			require.Equal(t, before, f.state(), "Preview must not write business or audit state")
			confirmation := &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}
			f.add()
			before = f.state()
			// Characterize the original gap with a fresh domain version as
			// well; stale-version rejection alone would not prove G04.
			current := previewConsistencyVersion(t, ctx, db, f.input)
			require.Contains(t, enforcementHTTP(t, ctx, app, f.raw, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: current, AcknowledgeImpacts: true}, false), string(ds.DeletionUnavailable))
			// No success is implied by an older Preview. The actual mutation
			// fails closed, preserving both explicit roots and their children.
			result := enforcementHTTP(t, ctx, app, f.raw, confirmation, false)
			require.True(t, strings.Contains(result, string(ds.DeletionUnavailable)) || strings.Contains(result, string(ds.DeletionDependencyChanged)))
			require.Equal(t, before, f.state())
			for _, targets := range [][]graphql2.DeletionResourceInput{f.input.Targets[:1], f.input.Targets} {
				input := f.input
				input.Targets = targets
				r := previewHTTP(t, ctx, app, input, 1, nil)
				t.Logf("%s: preview data=%t canProceed=%t; enforcement=DELETION_UNAVAILABLE", shape, r.Data.Preview != nil, r.Data.Preview != nil && r.Data.Preview.CanProceed)
				previewRejected(t, r, string(ds.DeletionUnavailable))
			}
			// The same limitation is visible to the existing trusted Human
			// authority, not just the compiled System test context.
			human := previewAdmit(t, base, db, f.actor)
			input := f.input
			input.Targets = input.Targets[:1]
			previewRejected(t, previewHTTP(t, human, app, input, 1, nil), string(ds.DeletionUnavailable))
			require.Contains(t, enforcementHTTP(t, human, app, f.raw[:1], nil, false), string(ds.DeletionUnavailable))
			require.Equal(t, before, f.state())
		})
	}
}

func TestPostgresDeletionPreviewMixedUnsupportedAndBlocked(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "PreviewConsistencyNative")
	app := enforcementApp(t, ctx, db)
	f := newServiceProfileFixture(t, ctx, db)
	input := previewInput(graphql2.DeletionTargetTypeService, f.service)
	input.Targets = append(input.Targets, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
	previewRejected(t, previewHTTP(t, ctx, app, input, 1, nil), string(ds.DeletionUnavailable))
	require.Contains(t, enforcementHTTP(t, ctx, app, []assignment.RawTarget{serviceProfileInput(f.service)[0], {Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()}}, nil, false), string(ds.DeletionUnavailable))
	input = previewInput(graphql2.DeletionTargetTypeService, f.service)
	serviceProfileAlert(t, ctx, db, f.service, "active")
	p := previewOK(t, previewHTTP(t, ctx, app, input, 1, nil))
	require.False(t, p.CanProceed)
	require.False(t, p.RequiresConfirmation)
	require.Contains(t, enforcementHTTP(t, ctx, app, serviceProfileInput(f.service), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}, false), string(ds.DeletionBlocked))
	g := newServiceProfileFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `INSERT INTO labels(tgt_service_id,key,value) VALUES($1,'synthetic','unsupported')`, g.service)
	previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeService, g.service), 1, nil), string(ds.DeletionUnavailable))
	require.Contains(t, enforcementHTTP(t, ctx, app, serviceProfileInput(g.service), nil, false), string(ds.DeletionUnavailable))
	serviceProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionPreviewScheduleAuditShape(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "PreviewConsistencyNative")
	app := enforcementApp(t, ctx, db)
	f := newScheduleProfileFixture(t, ctx, db, false)
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(scheduleProfileJSON(f)), &data))
	envelope := data["V1"].(map[string]any)["TemporarySchedules"].([]any)[0].(map[string]any)
	envelope["Shifts"].([]any)[0].(map[string]any)["Start"] = f.now.Add(time.Hour)
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	scheduleProfileData(t, ctx, db, f, string(raw))
	// Collector's effective interval is valid, but frozen B2 requires raw
	// containment. Neither path may silently trim the real configuration.
	version := scheduleProfileVersion(t, ctx, db, f.schedule)
	before := jsonWriterData(t, ctx, db, f.schedule)
	previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeSchedule, f.schedule), 1, nil), string(ds.DeletionUnavailable))
	require.Contains(t, enforcementHTTP(t, ctx, app, scheduleProfileInput(f.schedule), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: version, AcknowledgeImpacts: true}, false), string(ds.DeletionUnavailable))
	require.Equal(t, before, jsonWriterData(t, ctx, db, f.schedule))
	scheduleProfileNoSuccess(t, ctx, db)
}
