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
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/override"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/util/timeutil"
)

type scheduleProfileFixture struct {
	epProfileFixture
	rule, override, otherSchedule, channel uuid.UUID
	now                                    time.Time
}

func scheduleProfileInsert(t *testing.T, ctx context.Context, db *sql.DB, id, org uuid.UUID) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,($1::uuid)::text,'UTC')`, id, org)
}

func newScheduleProfileFixture(t *testing.T, ctx context.Context, db *sql.DB, children bool) scheduleProfileFixture {
	t.Helper()
	f := scheduleProfileFixture{epProfileFixture: newEPProfileFixture(t, ctx, db, false), rule: uuid.New(), override: uuid.New(), otherSchedule: uuid.New(), channel: uuid.New()}
	scheduleProfileInsert(t, ctx, db, f.otherSchedule, f.org)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT statement_timestamp()`).Scan(&f.now))
	if children {
		enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, f.rule, f.schedule, f.user)
		enforcementExec(t, ctx, db, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5,$6)`, f.override, f.schedule, f.user, f.actor, f.now.Add(-3*time.Hour), f.now.Add(-2*time.Hour))
	}
	return f
}

func scheduleProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceSchedule, ID: id.String()}
}
func scheduleProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var raw []collector.Selector
	for _, id := range ids {
		raw = append(raw, collector.Selector{Kind: ds.ResourceSchedule, ID: id.String()})
	}
	return raw
}
func scheduleProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var raw []assignment.RawTarget
	for _, id := range ids {
		raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeSchedule, ID: id.String()})
	}
	return raw
}
func scheduleProfilePreviewInput(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var raw []graphql2.DeletionResourceInput
	for _, id := range ids {
		raw = append(raw, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: id.String()})
	}
	return raw
}
func scheduleProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, scheduleProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, scheduleProfileRoot(id), facts).ImpactVersion()
}
func scheduleProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(id), version, true, authorizeDeletionFixture(scheduleProfileRoot(id)))
	require.NoError(t, err)
	return bound
}
func scheduleProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE outcome='committed'`))
}
func scheduleProfileData(t *testing.T, ctx context.Context, db *sql.DB, f scheduleProfileFixture, raw string) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb) ON CONFLICT(schedule_id) DO UPDATE SET data=excluded.data`, f.schedule, raw)
}
func scheduleProfileJSON(f scheduleProfileFixture) string {
	s, e := f.now.Add(2*time.Hour).Format(time.RFC3339Nano), f.now.Add(3*time.Hour).Format(time.RFC3339Nano)
	return fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}}`, s, e, s, e, f.user)
}

func TestPostgresDeletionEnforcementScheduleBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, children := range []bool{false, true} {
		f := newScheduleProfileFixture(t, ctx, db, children)
		confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
		if children {
			_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), nil)
			enforceCode(t, err, ds.DeletionConfirmationRequired)
			stale := *confirm
			stale.ExpectedImpactVersion = "stale"
			_, err = app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), &stale)
			enforceCode(t, err, ds.DeletionDependencyChanged)
		}
		ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule, f.schedule, uuid.New()), confirm)
		require.NoError(t, err)
		require.True(t, ok)
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND operation='schedule.delete' AND provenance='EXPLICIT'`, f.schedule))
	}
	f, g := newScheduleProfileFixture(t, ctx, db, true), newScheduleProfileFixture(t, ctx, db, true)
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule, g.schedule)...)
	ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule, g.schedule, f.schedule), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = app.Mutation().DeleteAll(ctx, scheduleProfileInput(uuid.Nil), nil)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	_, err = app.Mutation().DeleteAll(ctx, scheduleProfileInput(slicesRepeatService(f.schedule, 51)...), nil)
	require.Error(t, err)
	require.NotEqual(t, string(ds.DeletionUnavailable), err.Error())
}

func TestPostgresDeletionEnforcementScheduleClosureAudit(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	f := newScheduleProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, f.schedule, f.rotation)
	// All three Override states belong to Schedule and cascade. User-root
	// BLOCK policy is separately retained by the unchanged domain tests.
	for _, window := range [][2]time.Duration{{-time.Hour, time.Hour}, {2 * time.Hour, 3 * time.Hour}} {
		enforcementExec(t, ctx, db, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5)`, f.schedule, f.user, f.actor, f.now.Add(window[0]), f.now.Add(window[1]))
	}
	enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_schedule_id) VALUES($1,$2)`, f.user, f.schedule)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, f.otherSchedule, f.user)
	enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text))`, f.channel)
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(scheduleProfileJSON(f)), &data))
	v1 := data["V1"].(map[string]any)
	temps := v1["TemporarySchedules"].([]any)
	shift := temps[0].(map[string]any)["Shifts"].([]any)[0]
	temps[0].(map[string]any)["Shifts"] = []any{shift, shift}
	v1["TemporarySchedules"] = []any{temps[0], temps[0]}
	v1["OnCallNotificationRules"] = []any{map[string]any{"ID": f.schedule.String() + ":0", "ChannelID": f.channel, "Time": nil, "WeekdayFilter": nil, "NextNotification": nil}}
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	scheduleProfileData(t, ctx, db, f, string(raw))
	var envelope int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1`, f.schedule).Scan(&envelope))
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
	ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	for _, target := range []struct {
		table string
		id    uuid.UUID
	}{{"users", f.user}, {"users", f.actor}, {"rotations", f.rotation}, {"notification_channels", f.channel}, {"schedules", f.otherSchedule}} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+target.table+` WHERE id=$1`, target.id))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.rotation))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE schedule_id=$1`, f.otherSchedule))
	for _, table := range []string{"schedule_rules", "user_overrides", "schedule_data", "user_favorites"} {
		col := map[string]string{"schedule_rules": "schedule_id", "user_overrides": "tgt_schedule_id", "schedule_data": "schedule_id", "user_favorites": "tgt_schedule_id"}[table]
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE `+col+`=$1`, f.schedule))
	}
	var effects []sraudit.Effect
	require.NoError(t, db.QueryRowContext(ctx, `SELECT effects FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.schedule).Scan(&raw))
	require.NoError(t, json.Unmarshal(raw, &effects))
	require.Len(t, effects, 13) // 2 Rules + 3 Overrides + Favorite + 2 Temp + 4 Shift + OnCall
	counts := map[string]int{}
	for _, effect := range effects {
		counts[effect.ResourceType]++
		require.Equal(t, "CASCADE", effect.Provenance)
		require.Equal(t, "schedule_delete", effect.Cause)
		if effect.Fragment != nil {
			require.Equal(t, envelope, effect.Fragment.EnvelopeID)
			require.Contains(t, []int{0, 1}, effect.Fragment.Ordinal)
			require.Equal(t, "envelope_cascade", effect.DeletionMechanism)
		}
	}
	require.Equal(t, 3, counts[sraudit.Override])
	require.Equal(t, 4, counts[sraudit.FixedShift])
	require.Equal(t, 1, counts[sraudit.OnCallRule])
}

func TestPostgresDeletionEnforcementScheduleActionBlock(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newScheduleProfileFixture(t, ctx, db, true)
	for range 2 {
		p := uuid.New()
		epProfileInsert(t, ctx, db, p, f.org)
		for range 4 {
			step := uuid.New()
			enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, step, p)
			enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, step, f.schedule)
		}
	}
	facts, err := collectDeletion(t, ctx, db, scheduleProfileRoot(f.schedule), collector.Limits{})
	require.NoError(t, err)
	require.Len(t, slices.DeleteFunc(facts.Collection.Dependencies, func(d ds.Dependency) bool { return d.Relationship != ds.RelationshipActionTarget }), 8)
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
	for _, confirmation := range []*graphql2.DeletionSafetyConfirmationInput{nil, confirm, {ExpectedImpactVersion: confirm.ExpectedImpactVersion, AcknowledgeImpacts: true}} {
		_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirmation)
		enforceCode(t, err, ds.DeletionBlocked)
	}
	require.Equal(t, 8, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE schedule_id=$1`, f.schedule))
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newScheduleProfileFixture(t, ctx, db, true)
	scheduleProfileData(t, ctx, db, f, scheduleProfileJSON(f))
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_schedule_sink_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_schedule_sink_failure BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_schedule_sink_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	require.Error(t, err)
	for _, table := range []string{"schedules", "schedule_rules", "user_overrides", "schedule_data"} {
		col := map[string]string{"schedules": "id", "schedule_rules": "schedule_id", "user_overrides": "tgt_schedule_id", "schedule_data": "schedule_id"}[table]
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE `+col+`=$1`, f.schedule))
	}
	scheduleProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_schedule_sink_failure ON schedule_rotation_delete_audit_events`)
	ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPostgresDeletionEnforcementScheduleJSONFailClosed(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"null", "empty", "wrong_type", "null_array", "missing_user", "invalid_uuid", "nonexistent_user", "bad_start", "bad_end", "zero_interval", "unknown_member", "disjoint_shift", "crossing_shift", "oncall_time", "budget"} {
		t.Run(kind, func(t *testing.T) {
			f := newScheduleProfileFixture(t, ctx, db, false)
			raw := scheduleProfileJSON(f)
			switch kind {
			case "null":
				raw = "null"
			case "empty":
				raw = "{}"
			case "wrong_type":
				raw = `{"V1":{"TemporarySchedules":{},"OnCallNotificationRules":[]}}`
			case "null_array":
				raw = `{"V1":{"TemporarySchedules":null,"OnCallNotificationRules":[]}}`
			case "missing_user":
				raw = strings.ReplaceAll(raw, fmt.Sprintf(`"UserID":%q`, f.user), `"UserID":null`)
			case "invalid_uuid":
				raw = strings.ReplaceAll(raw, f.user.String(), "invalid")
			case "nonexistent_user":
				raw = strings.ReplaceAll(raw, f.user.String(), uuid.NewString())
			case "bad_start":
				raw = strings.ReplaceAll(raw, f.now.Add(2*time.Hour).Format(time.RFC3339Nano), "invalid")
			case "bad_end":
				raw = strings.ReplaceAll(raw, f.now.Add(3*time.Hour).Format(time.RFC3339Nano), "invalid")
			case "zero_interval":
				raw = strings.ReplaceAll(raw, f.now.Add(3*time.Hour).Format(time.RFC3339Nano), f.now.Add(2*time.Hour).Format(time.RFC3339Nano))
			case "unknown_member":
				raw = strings.Replace(raw, `"V1":{`, `"V1":{"Unknown":true,`, 1)
			case "disjoint_shift", "crossing_shift":
				var data map[string]any
				require.NoError(t, json.Unmarshal([]byte(raw), &data))
				tmp := data["V1"].(map[string]any)["TemporarySchedules"].([]any)[0].(map[string]any)
				sh := tmp["Shifts"].([]any)[0].(map[string]any)
				if kind == "crossing_shift" {
					sh["Start"] = f.now.Add(time.Hour)
				} else {
					sh["Start"], sh["End"] = f.now.Add(4*time.Hour), f.now.Add(5*time.Hour)
				}
				b, err := json.Marshal(data)
				require.NoError(t, err)
				raw = string(b)
			case "oncall_time":
				enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, f.channel)
				raw = fmt.Sprintf(`{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[{"ID":%q,"ChannelID":%q,"Time":"invalid"}]}}`, f.schedule.String()+":0", f.channel)
			case "budget":
				enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) SELECT $1,jsonb_build_object('V1',jsonb_build_object('TemporarySchedules',jsonb_agg(jsonb_build_object('Start','2020-01-01T00:00:00Z','End','2020-01-02T00:00:00Z','Shifts','[]'::jsonb)),'OnCallNotificationRules','[]'::jsonb)) FROM generate_series(1,10001)`, f.schedule)
			}
			if kind != "budget" {
				scheduleProfileData(t, ctx, db, f, raw)
			}
			_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
			require.Error(t, err)
			if kind == "budget" {
				enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, f.schedule))
		})
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"history_open", "history_ended", "message", "calendar", "label"} {
		f := newScheduleProfileFixture(t, ctx, db, true)
		switch kind {
		case "history_open":
			enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id) VALUES($1,$2)`, f.schedule, f.user)
		case "history_ended":
			enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,$3,$4)`, f.schedule, f.user, f.now.Add(-time.Hour), f.now)
		case "message":
			enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, f.channel)
			enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(id,schedule_id,channel_id,message_type) VALUES($1,$2,$3,'schedule_on_call_notification')`, uuid.New(), f.schedule, f.channel)
		case "calendar":
			enforcementExec(t, ctx, db, `INSERT INTO user_calendar_subscriptions(id,user_id,schedule_id,name,config) VALUES($1,$2,$3,'synthetic','{}')`, uuid.New(), f.user, f.schedule)
		case "label":
			enforcementExec(t, ctx, db, `INSERT INTO labels(key,value,tgt_schedule_id) VALUES('synthetic','unsupported',$1)`, f.schedule)
		}
		previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeSchedule, f.schedule), 1, nil), string(ds.DeletionUnavailable))
		_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule, f.otherSchedule), nil)
		enforceCode(t, err, ds.DeletionUnavailable)
		require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{f.schedule, f.otherSchedule})))
	}
	f := newScheduleProfileFixture(t, ctx, db, true)
	for _, other := range []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: f.user.String()}, {Type: assignment.TargetTypeRotation, ID: f.rotation.String()}, {Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()}, {Type: assignment.TargetTypeNotificationRule, ID: uuid.NewString()}, {Type: assignment.TargetTypeContactMethod, ID: uuid.NewString()}, {Type: assignment.TargetTypeIntegrationKey, ID: uuid.NewString()}} {
		_, err := app.Mutation().DeleteAll(ctx, append(scheduleProfileInput(f.schedule), other), nil)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func scheduleProfileRelatedWrites(t *testing.T, ctx context.Context, db *sql.DB, f scheduleProfileFixture) []serviceProfileWrite {
	t.Helper()
	store, err := schedule.NewStore(ctx, db, nil)
	require.NoError(t, err)
	rules, err := rule.NewStore(ctx, db)
	require.NoError(t, err)
	uo, err := override.NewStore(ctx, db)
	require.NoError(t, err)
	scheduleProfileData(t, ctx, db, f, scheduleProfileJSON(f))
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, f.schedule, f.rotation)
	enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, f.channel)
	var favorite int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO user_favorites(user_id,tgt_schedule_id) VALUES($1,$2) RETURNING id`, f.user, f.schedule).Scan(&favorite))
	q := func(name, query string, args ...any) serviceProfileWrite {
		return serviceProfileWrite{name: name, run: func(c context.Context, tx *sql.Tx) error { _, err := tx.ExecContext(c, query, args...); return err }}
	}
	tmp := schedule.TemporarySchedule{Start: f.now.Add(4 * time.Hour), End: f.now.Add(5 * time.Hour), Shifts: []schedule.FixedShift{{Start: f.now.Add(4 * time.Hour), End: f.now.Add(5 * time.Hour), UserID: f.user.String()}}}
	r := rule.NewAlwaysActive(f.schedule.String(), assignment.UserTarget(f.user.String()))
	r.ID = f.rule.String()
	r.Start = timeutil.Clock(time.Hour)
	return []serviceProfileWrite{
		{name: "rule_create_store", run: func(c context.Context, tx *sql.Tx) error {
			_, err := rules.CreateRuleTx(c, tx, rule.NewAlwaysActive(f.schedule.String(), assignment.UserTarget(f.actor.String())))
			return err
		}},
		{name: "rule_update_store", run: func(c context.Context, tx *sql.Tx) error { return rules.UpdateTx(c, tx, r) }},
		{name: "rule_delete_raw", run: func(c context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(c, `DELETE FROM schedule_rules WHERE id=$1`, f.rule)
			return err
		}},
		q("rule_retarget", `UPDATE schedule_rules SET tgt_user_id=$2 WHERE id=$1`, f.rule, f.actor),
		q("rule_reparent", `UPDATE schedule_rules SET schedule_id=$2 WHERE id=$1`, f.rule, f.otherSchedule),
		{name: "override_create_store", run: func(c context.Context, tx *sql.Tx) error {
			_, err := uo.CreateUserOverrideTxScoped(c, tx, &override.UserOverride{Target: assignment.ScheduleTarget(f.schedule.String()), AddUserID: f.user.String(), Start: f.now.Add(6 * time.Hour), End: f.now.Add(7 * time.Hour)}, &f.org)
			return err
		}},
		{name: "override_ended_to_future_store", run: func(c context.Context, tx *sql.Tx) error {
			return uo.UpdateUserOverrideTxScoped(c, tx, &override.UserOverride{ID: f.override.String(), Target: assignment.ScheduleTarget(f.schedule.String()), AddUserID: f.user.String(), RemoveUserID: f.actor.String(), Start: f.now.Add(6 * time.Hour), End: f.now.Add(7 * time.Hour)}, &f.org)
		}},
		q("override_reparent", `UPDATE user_overrides SET tgt_schedule_id=$2 WHERE id=$1`, f.override, f.otherSchedule),
		q("override_delete_sql", `DELETE FROM user_overrides WHERE id=$1`, f.override),
		{name: "set_temporary_store", run: func(c context.Context, tx *sql.Tx) error {
			return store.SetTemporaryScheduleScoped(c, tx, f.schedule, tmp, &f.org)
		}},
		{name: "set_clear_temporary_store", run: func(c context.Context, tx *sql.Tx) error {
			return store.SetClearTemporaryScheduleScoped(c, tx, f.schedule, tmp, f.now.Add(time.Hour), f.now.Add(6*time.Hour), &f.org)
		}},
		{name: "clear_temporary_store", run: func(c context.Context, tx *sql.Tx) error {
			return store.ClearTemporarySchedulesScoped(c, tx, f.schedule, f.now.Add(time.Hour), f.now.Add(6*time.Hour), &f.org)
		}},
		{name: "set_oncall_store", run: func(c context.Context, tx *sql.Tx) error {
			return store.SetOnCallNotificationRulesScoped(c, tx, f.schedule, []schedule.OnCallNotificationRule{{ChannelID: f.channel}}, &f.org)
		}},
		{name: "engine_select_update", run: func(c context.Context, tx *sql.Tx) error {
			_, err := gadb.New(tx).SchedMgrDataForUpdate(c)
			if err != nil {
				return err
			}
			return gadb.New(tx).SchedMgrSetData(c, gadb.SchedMgrSetDataParams{ScheduleID: f.schedule, Data: json.RawMessage(scheduleProfileJSON(f))})
		}},
		{name: "engine_set_data", run: func(c context.Context, tx *sql.Tx) error {
			return gadb.New(tx).SchedMgrSetData(c, gadb.SchedMgrSetDataParams{ScheduleID: f.schedule, Data: json.RawMessage(scheduleProfileJSON(f))})
		}},
		{name: "data_notification_migration", run: func(c context.Context, tx *sql.Tx) error {
			return gadb.New(tx).SchedMgrSetDataV1Rules(c, gadb.SchedMgrSetDataV1RulesParams{ScheduleID: f.schedule, Replacement: json.RawMessage(`[]`)})
		}},
		{name: "cleanup_select_update", run: func(c context.Context, tx *sql.Tx) error {
			_, err := gadb.New(tx).CleanupMgrScheduleData(c, f.schedule)
			if err == sql.ErrNoRows {
				return nil
			}
			if err != nil {
				return err
			}
			return gadb.New(tx).CleanupMgrUpdateScheduleData(c, gadb.CleanupMgrUpdateScheduleDataParams{ScheduleID: f.schedule, Data: json.RawMessage(scheduleProfileJSON(f))})
		}},
		{name: "cleanup_skip", run: func(c context.Context, tx *sql.Tx) error {
			return gadb.New(tx).CleanupMgrScheduleDataSkip(c, f.schedule)
		}},
		q("envelope_rewrite", `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules}','[]') WHERE schedule_id=$1`, f.schedule),
		q("envelope_reparent", `UPDATE schedule_data SET schedule_id=$2 WHERE schedule_id=$1`, f.schedule, f.otherSchedule),
		q("envelope_delete", `DELETE FROM schedule_data WHERE schedule_id=$1`, f.schedule),
		q("favorite_insert", `INSERT INTO user_favorites(user_id,tgt_schedule_id) VALUES($1,$2)`, f.actor, f.schedule),
		q("favorite_owner", `UPDATE user_favorites SET user_id=$2 WHERE id=$1`, favorite, f.actor),
		q("favorite_delete", `DELETE FROM user_favorites WHERE id=$1`, favorite),
		q("root_update", `UPDATE schedules SET name=name WHERE id=$1`, f.schedule),
		q("user_target", `UPDATE users SET name=name WHERE id=$1`, f.user),
		q("user_assignment", `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`, f.user),
		q("rotation_target", `UPDATE rotations SET name=name WHERE id=$1`, f.rotation),
		q("organization", `UPDATE organizations SET display_name=display_name WHERE id=$1`, f.org),
		q("history_insert", `INSERT INTO schedule_on_call_users(schedule_id,user_id) VALUES($1,$2)`, f.schedule, f.user),
		q("message_insert", `INSERT INTO outgoing_messages(id,schedule_id,channel_id,message_type) VALUES($1,$2,$3,'schedule_on_call_notification')`, uuid.New(), f.schedule, f.channel),
	}
}

func TestPostgresDeletionEnforcementScheduleDeleteFirst(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	for index := 0; index < 31; index++ {
		f := newScheduleProfileFixture(t, ctx, db, true)
		w := scheduleProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			app := enforcementApp(t, ctx, traced)
			confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
			deleted := make(chan error, 1)
			go func() {
				_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
				deleted <- err
			}()
			select {
			case <-barrier.arrived:
			case err := <-deleted:
				t.Fatalf("certification not reached: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			writer := epProfileWriter(t, ctx, db)
			wc, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := serviceProfileWait(t, wc, db, writer, func() error { return w.run(wc, writer) })
			close(barrier.resume)
			require.NoError(t, <-deleted)
			err = <-done
			if err == nil {
				require.NoError(t, writer.Commit())
			} else {
				pg := sqlutil.MapError(err)
				if pg == nil {
					expected := map[string]string{
						"override_create_store":          "invalid value for 'TargetID': schedule does not exist",
						"override_ended_to_future_store": "invalid value for 'ID': user override not found",
					}[w.name]
					require.NotEmpty(t, expected)
					require.EqualError(t, err, expected)
				} else {
					require.Equal(t, "23503", pg.Code)
				}
				require.NoError(t, writer.Rollback())
			}
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.schedule))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.rotation))
		})
	}
}

func TestPostgresDeletionEnforcementScheduleWriterFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for index := 0; index < 31; index++ {
		f := newScheduleProfileFixture(t, ctx, db, true)
		w := scheduleProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			version := scheduleProfileVersion(t, ctx, db, f.schedule)
			writer := epProfileWriter(t, ctx, db)
			require.NoError(t, w.run(ctx, writer))
			_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: version, AcknowledgeImpacts: true})
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, writer.Commit())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
			if w.name == "history_insert" || w.name == "message_insert" {
				return
			}
			facts, err := collectDeletion(t, ctx, db, scheduleProfileRoot(f.schedule), collector.Limits{})
			if err != nil {
				require.Contains(t, []string{"clear_temporary_store", "set_clear_temporary_store"}, w.name)
				return
			}
			fresh := deletionPlan(t, scheduleProfileRoot(f.schedule), facts).ImpactVersion()
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), fresh, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())
			if fresh != version {
				tx = nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.NoError(t, tx.Rollback())
			}
		})
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleActionWriters(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	for _, first := range []string{"delete", "writer"} {
		for _, kind := range []string{"add_store", "retarget_to", "retarget_away", "delete_store"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := newScheduleProfileFixture(t, ctx, db, false)
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
				target := f.otherSchedule
				if kind == "retarget_away" || kind == "delete_store" {
					target = f.schedule
				}
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,schedule_id) VALUES($1,$2,$3)`, f.action, f.step, target)
				app := enforcementApp(t, ctx, db)
				registry := nfydest.NewRegistry()
				registry.RegisterProvider(ctx, app.ScheduleStore)
				store, err := escalation.NewStore(ctx, db, escalation.Config{Registry: registry})
				require.NoError(t, err)
				version := scheduleProfileVersion(t, ctx, db, f.schedule)
				writer := epProfileWriter(t, ctx, db)
				run := func() error {
					switch kind {
					case "add_store":
						return store.AddStepActionTx(ctx, writer, f.step, schedule.DestFromID(f.schedule.String()))
					case "delete_store":
						_, err := writer.ExecContext(ctx, `DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 AND schedule_id=$2`, f.step, f.schedule)
						return err
					default:
						dest := f.schedule
						if kind == "retarget_away" {
							dest = f.otherSchedule
						}
						_, err := writer.ExecContext(ctx, `UPDATE escalation_policy_actions SET schedule_id=$2 WHERE id=$1`, f.action, dest)
						return err
					}
				}
				if first == "writer" {
					require.NoError(t, run())
					tx := nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
					fresh := scheduleProfileVersion(t, ctx, db, f.schedule)
					tx = nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), fresh, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
					if kind == "add_store" || kind == "retarget_to" {
						enforceCode(t, err, ds.DeletionBlocked)
					} else {
						require.NoError(t, err)
					}
					require.NoError(t, tx.Rollback())
					return
				}
				tx := nrBegin(t, ctx, db)
				if kind == "retarget_away" || kind == "delete_store" {
					_, _, err := guard.StabilizeSchedule(ctx, tx, scheduleProfileSelectors(f.schedule))
					require.NoError(t, err)
					done := serviceProfileWait(t, ctx, db, writer, run)
					require.NoError(t, tx.Rollback())
					require.NoError(t, <-done)
					require.NoError(t, writer.Commit())
				} else {
					bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
					done := serviceProfileWait(t, ctx, db, writer, run)
					receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
					require.NoError(t, err)
					require.Len(t, receipts, 1)
					require.NoError(t, tx.Commit())
					err = <-done
					require.Error(t, err)
					require.Equal(t, "23503", sqlutil.MapError(err).Code)
					require.NoError(t, writer.Rollback())
				}
			})
		}
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleGuardLifecycle(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	f := newScheduleProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	version := scheduleProfileVersion(t, ctx, db, f.schedule)
	raw := scheduleProfileSelectors(f.schedule)
	for _, phase := range []string{"before_locks", "after_locks", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, _, err := guard.StabilizeSchedule(ctx, tx, raw)
			require.NoError(t, err)
			if phase == "after_locks" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, scheduleProfileRoot(f.schedule), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
			require.NoError(t, err)
			plan := deletionPlan(t, scheduleProfileRoot(f.schedule), facts)
			_, err = guard.Bind(ctx, tx, checked, append(raw, raw...), plan, version, true)
			enforceCode(t, err, ds.DeletionUnavailable)
			_, err = guard.Bind(ctx, tx, checked, raw, ds.DeletionPlan{}, version, true)
			enforceCode(t, err, ds.DeletionUnavailable)
			bound, err := guard.Bind(ctx, tx, checked, raw, plan, version, true)
			require.NoError(t, err)
			if phase == "after_witness" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			_, err = tx.ExecContext(ctx, `ROLLBACK TO checkpoint`)
			require.NoError(t, err)
			if phase != "after_witness" {
				_, err = app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
			}
			receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts, 1)
			_, err = app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
	_, err := tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO old_generation`)
	require.NoError(t, err)
	for _, bound := range []context.Context{old, newer} {
		_, err = guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeSchedule(bound, other, []string{f.schedule.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeSchedule(bound, tx, []string{uuid.NewString()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeCM(bound, tx, []string{f.schedule.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeNR(bound, tx, []string{f.schedule.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeSchedule(context.WithValue(ctx, serviceProfileContextKey{}, "schedule-only-v1"), tx, []string{f.schedule.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeSchedule(context.WithValue(bound, serviceProfileContextKey{}, true), tx, []string{f.schedule.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT 1/0`)
	require.Error(t, err)
	_, err = collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, fn := range []func() error{
		func() error { return app.ScheduleStore.DeleteManyTx(ctx, nil, []string{f.schedule.String()}, nil) },
		func() error {
			tx := nrBegin(t, ctx, db)
			defer func() { _ = tx.Rollback() }()
			return app.ScheduleStore.DeleteManyTx(ctx, tx, []string{f.schedule.String()}, nil)
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	f := newScheduleProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	for _, legacy := range []bool{false, true} {
		absent := uuid.New()
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(absent), "", false, authorizeDeletionFixture(scheduleProfileRoot(absent)))
		require.NoError(t, err)
		scheduleProfileInsert(t, ctx, db, absent, f.org)
		enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, absent, f.user)
		enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}')`, absent)
		if legacy {
			require.NoError(t, app.ScheduleStore.DeleteManyTx(bound, tx, []string{absent.String()}, nil))
		} else {
			receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{absent.String()}, nil)
			require.NoError(t, err)
			require.Empty(t, receipts)
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, absent))
	}
	absent := uuid.New()
	tx := nrBegin(t, ctx, db)
	version := scheduleProfileVersion(t, ctx, db, f.schedule)
	bound, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule, absent), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
	require.NoError(t, err)
	scheduleProfileInsert(t, ctx, db, absent, f.org)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, absent, f.user)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}')`, absent)
	receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String(), absent.String()}, nil)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.Equal(t, f.schedule, receipts[0].ID)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, absent))
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleControllerMissingWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "ScheduleProfileTest")
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f, other := newScheduleProfileFixture(t, ctx, db, true), newScheduleProfileFixture(t, ctx, db, true)
			enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			human := previewAdmit(t, ctx, db, f.actor)
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			app := enforcementApp(t, sys, traced)
			missing := uuid.New()
			input := scheduleProfileInput(missing)
			var confirm *graphql2.DeletionSafetyConfirmationInput
			if mixed {
				input = append(scheduleProfileInput(f.schedule), input...)
				confirm = enforcementPreview(t, human, app, scheduleProfilePreviewInput(f.schedule)...)
			}
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().DeleteAll(human, input, confirm); done <- err }()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			scheduleProfileInsert(t, ctx, db, missing, other.org)
			enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, missing, other.user)
			enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}')`, missing)
			close(barrier.resume)
			require.NoError(t, <-done)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, missing))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, missing))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE schedule_id=$1`, missing))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, missing))
			if mixed {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
			}
		})
	}
}

func TestPostgresDeletionEnforcementScheduleIndependent(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for index := 0; index < 8; index++ {
			f := newScheduleProfileFixture(t, ctx, db, true)
			other := newDeletionFixture(t, ctx, db)
			writes := []nrWrite{
				{name: "organization", query: `UPDATE organizations SET display_name=display_name WHERE id=$1`, args: []any{other.org}},
				{name: "service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
				{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
				{name: "cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
				{name: "nr", query: `UPDATE user_notification_rules SET delay_minutes=3 WHERE id=$1`, args: []any{other.nr}},
				{name: "key", query: `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`, args: []any{other.keyAudit}},
				{name: "user", query: `UPDATE users SET name=name WHERE id=$1`, args: []any{other.user}},
				{name: "schedule", query: `UPDATE schedules SET name=name WHERE id=$1`, args: []any{other.schedule}},
			}
			w := writes[index]
			t.Run(first+"_"+w.name, func(t *testing.T) {
				writer := epProfileWriter(t, ctx, db)
				_, err := writer.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'`)
				require.NoError(t, err)
				run := func() {
					res, err := writer.ExecContext(ctx, w.query, w.args...)
					require.NoError(t, err)
					n, err := res.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
				}
				conf, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
				if first == "delete" {
					conf.Tracer = barrier
				}
				traced := sql.OpenDB(stdlib.GetConnector(*conf))
				defer traced.Close()
				app := enforcementApp(t, ctx, traced)
				confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
				if first == "writer" {
					run()
					ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
					require.NoError(t, err)
					require.True(t, ok)
					require.NoError(t, writer.Commit())
				} else {
					done := make(chan error, 1)
					go func() {
						_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
						done <- err
					}()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					// No strong public relation lock belongs to this Profile.
					// Ordinary writes to these unrelated resources still commit.
					require.Equal(t, 0, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND l.granted`))
					run()
					require.NoError(t, writer.Commit())
					close(barrier.resume)
					require.NoError(t, <-done)
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.schedule))
			})
		}
	}
}

func TestPostgresDeletionEnforcementScheduleAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_ADMIN", "ORG_MEMBER", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := newScheduleProfileFixture(t, ctx, db, true)
			if role == "ORG_MEMBER" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			if role == "PLATFORM_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			}
			human := previewAdmit(t, ctx, db, f.actor)
			if role == "ORG_MEMBER" {
				_, err := app.Mutation().DeleteAll(human, scheduleProfileInput(f.schedule), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
				return
			}
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: f.schedule.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, q, f.actor)
				require.NoError(t, err)
				tx := nrBegin(t, human, db)
				_, err = collector.Enforce(human, tx, scheduleProfileSelectors(f.schedule), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				_ = scheduleProfileEnforce(t, human, tx, f.schedule, confirm.ExpectedImpactVersion)
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				done := nrWaiter(t, writerCtx, db, writer, q, f.actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				cancel()
			}
			ok, err := app.Mutation().DeleteAll(human, scheduleProfileInput(f.schedule), confirm)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
	f, other := newScheduleProfileFixture(t, ctx, db, true), newScheduleProfileFixture(t, ctx, db, true)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, scheduleProfileInput(other.schedule), nil)
	require.Error(t, err)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: f.schedule.String()})
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, scheduleProfileInput(f.schedule), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
}

func TestPostgresDeletionEnforcementScheduleCarrierIsolation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	f := newScheduleProfileFixture(t, ctx, db, true)
	other := newServiceProfileFixture(t, ctx, db)
	nr := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	for _, root := range []ds.Resource{nrRoot(nr.nr), cmRoot(nr.cm), serviceProfileRoot(other.service), epProfileRoot(f.policy)} {
		facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.NoError(t, err)
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, []collector.Selector{{Kind: root.Kind, ID: root.ID}}, deletionPlan(t, root, facts).ImpactVersion(), true, authorizeDeletionFixture(root))
		require.NoError(t, err)
		_, err = app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	tx := nrBegin(t, ctx, db)
	bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, scheduleProfileVersion(t, ctx, db, f.schedule))
	for _, fn := range []func() error{
		func() error {
			_, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{other.service.String()}, nil)
			return err
		},
		func() error { _, err := guard.ConsumeEP(bound, tx, []string{f.policy.String()}); return err },
		func() error { _, err := guard.ConsumeCM(bound, tx, []string{nr.cm.String()}); return err },
		func() error { _, err := guard.ConsumeNR(bound, tx, []string{nr.nr.String()}); return err },
		func() error {
			_, err := app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{nr.key.String()}, nil)
			return err
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	require.NoError(t, tx.Rollback())
	scheduleProfileNoSuccess(t, ctx, db)
}
