package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

type userNativeParents struct{ schedule, rotation, policy, step, action, rule, participant, override uuid.UUID }

func userNativeParentRows(t *testing.T, ctx context.Context, db *sql.DB, f userNativeFixture) userNativeParents {
	t.Helper()
	p := userNativeParents{f.newSchedule(t, ctx), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	enforcementExec(t, ctx, db, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, p.rotation, f.org)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, p.policy, f.org)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,step_number) VALUES($1,$2,0)`, p.step, p.policy)
	return p
}
func userNativeAddReference(t *testing.T, ctx context.Context, db *sql.DB, f userNativeFixture, p userNativeParents, kind string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	switch kind {
	case "action":
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, p.action, p.step, f.user)
	case "rule":
		enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, p.rule, p.schedule, f.user)
	case "participant":
		enforcementExec(t, ctx, db, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0)`, p.participant, p.rotation, f.user)
	case "active_override", "future_override", "ended_override":
		start, end := now.Add(-time.Hour), now.Add(time.Hour)
		if kind == "future_override" {
			start, end = now.Add(time.Hour), now.Add(2*time.Hour)
		}
		if kind == "ended_override" {
			start, end = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}
		enforcementExec(t, ctx, db, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5)`, p.override, p.schedule, f.user, start, end)
	case "active_json", "future_json", "ended_json":
		temp := userPhaseATemp(f.user)
		if kind == "active_json" {
			temp.Start, temp.End = now.Add(-time.Hour), now.Add(time.Hour)
		}
		if kind == "ended_json" {
			temp.Start, temp.End = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}
		temp.Shifts[0].Start, temp.Shifts[0].End = temp.Start, temp.End
		if kind == "ended_json" {
			// An ended record is a persisted lifecycle state; the public setter
			// correctly refuses creating a brand-new past interval.
			raw, err := json.Marshal(map[string]any{"V1": map[string]any{"TemporarySchedules": []any{temp}, "OnCallNotificationRules": []any{}}})
			require.NoError(t, err)
			enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb) ON CONFLICT(schedule_id) DO UPDATE SET data=excluded.data`, p.schedule, string(raw))
		} else {
			require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, p.schedule, temp, &f.org))
		}
	case "active_cycle", "closed_cycle":
		service := uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, service, f.org, p.policy)
		status := "active"
		if kind == "closed_cycle" {
			status = "closed"
		}
		var alert int64
		require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,summary,dedup_key) VALUES($1,$2,'synthetic',$3) RETURNING id`, service, status, func() any {
			if status == "closed" {
				return nil
			}
			return uuid.NewString()
		}()).Scan(&alert))
		enforcementExec(t, ctx, db, `INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2)`, f.user, alert)
	}
}

func TestPostgresDeletionEnforcementUserBlockAndHistory(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"action", "rule", "participant", "active_override", "future_override", "active_json", "future_json", "active_cycle", "closed_cycle", "ended_override", "ended_json", "history_identity"} {
		t.Run(kind, func(t *testing.T) {
			f := userNativeLifecycle(t, ctx, db, 1, 1, true)
			p := userNativeParentRows(t, ctx, db, f)
			old := userProfileVersion(t, ctx, db, f.user)
			userNativeAddReference(t, ctx, db, f, p, kind)
			if kind == "history_identity" {
				require.NoError(t, f.users.AddAuthSubjectTx(ctx, nil, &user.AuthSubject{ProviderID: "synthetic", SubjectID: uuid.NewString(), UserID: f.user.String()}))
				enforcementExec(t, ctx, db, `INSERT INTO auth_basic_users(user_id,username,password_hash) VALUES($1,$2,'SYNTHETIC_NOT_A_PASSWORD')`, f.user, uuid.NewString())
				enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,now()-'2h'::interval,now()-'1h'::interval)`, p.schedule, f.user)
				enforcementExec(t, ctx, db, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time,end_time) VALUES($1,$2,now()-'2h'::interval,now()-'1h'::interval)`, p.step, f.user)
				enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_user_id) VALUES($1,$1)`, f.user)
			}
			facts, err := collectDeletion(t, ctx, db, userProfileRoot(f.user), collector.Limits{})
			require.NoError(t, err)
			plan := deletionPlan(t, userProfileRoot(f.user), facts)
			confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
			_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
			switch kind {
			case "closed_cycle":
				enforceCode(t, err, ds.DeletionUnavailable)
			case "ended_override", "ended_json", "history_identity":
				require.True(t, plan.CanProceed())
				require.NoError(t, err)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				if kind == "ended_json" {
					require.Contains(t, jsonWriterData(t, ctx, db, p.schedule), f.user.String())
				}
				if kind == "ended_override" {
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, p.override))
				}
				if kind == "history_identity" {
					for _, typ := range []string{"auth_subject", "basic_auth_link", "schedule_on_call_history", "ep_step_on_call_history", "user_favorite"} {
						want := 1
						if typ == "auth_subject" {
							want = 2
						} // BasicAuth database trigger adds its own subject.
						require.Equal(t, want, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND resource_type=$2`, f.user, typ))
					}
				}
			default:
				require.False(t, plan.CanProceed())
				enforceCode(t, err, ds.DeletionBlocked)
				require.NotEqual(t, old, plan.ImpactVersion())
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.user))
			}
		})
	}
}

func TestPostgresDeletionEnforcementUserInvalidClosure(t *testing.T) {
	for _, kind := range []string{"assignment", "verification", "calendar", "message", "key_attribution", "cross_cm_nr", "cross_cm_subject", "json_unknown", "json_scope", "session_identity", "session_collision", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			base, _, db := boundedAuditDB(t, len(Names()))
			ctx := permission.SystemContext(base, "UserNative")
			app := enforcementApp(t, ctx, db)
			f := userNativeLifecycle(t, ctx, db, 1, 1, true)
			g := userNativeLifecycle(t, ctx, db, 1, 1, true)
			confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
			use := ctx
			switch kind {
			case "assignment":
				enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, f.user)
			case "verification":
				enforcementExec(t, ctx, db, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,123456,now()+'1h'::interval)`, uuid.New(), f.cms[0])
			case "calendar":
				enforcementExec(t, ctx, db, `INSERT INTO user_calendar_subscriptions(id,user_id,schedule_id,name,config) VALUES($1,$2,$3,'synthetic','{}')`, uuid.New(), f.user, f.newSchedule(t, ctx))
			case "message":
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(id,user_id,contact_method_id,message_type) VALUES($1,$2,$3,'test_notification')`, uuid.New(), f.user, f.cms[0])
			case "key_attribution":
				enforcementExec(t, ctx, db, `INSERT INTO gql_api_keys(id,name,description,policy,expires_at,created_by) VALUES($1,'synthetic','synthetic','{}',now()+'1h'::interval,$2)`, uuid.New(), f.user)
			case "cross_cm_nr":
				_, err := db.ExecContext(ctx, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,5)`, g.user, f.cms[0])
				require.Error(t, err, "existing same-owner trigger must reject the invalid row")
				return
			case "cross_cm_subject":
				enforcementExec(t, ctx, db, `INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('synthetic',$1,$2,$3)`, uuid.NewString(), g.user, f.cms[0])
			case "json_unknown":
				enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"Unknown":true}}')`, f.newSchedule(t, ctx))
			case "json_scope":
				p := userNativeParentRows(t, ctx, db, f)
				userNativeAddReference(t, ctx, db, f, p, "ended_json")
				enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, p.schedule, g.org)
			case "session_identity":
				// Identity trigger stays enabled: the legitimate column default can
				// be given the same synthetic locator at INSERT to test the gate.
				id := uuid.New()
				enforcementExec(t, ctx, db, `INSERT INTO auth_user_sessions(id,audit_resource_id,user_id) VALUES($1,$1,$2)`, id, f.user)
			case "session_collision":
				enforcementExec(t, ctx, db, `INSERT INTO auth_user_sessions(id,user_id) VALUES($1,$2)`, f.sessionSafe, g.user)
			case "canceled":
				var cancel context.CancelFunc
				use, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := app.Mutation().DeleteAll(use, userProfileInput(f.user), confirm)
			require.Error(t, err)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.user))
		})
	}
}

func TestPostgresDeletionEnforcementUserScope(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	app := enforcementApp(t, ctx, db)
	f, g := userNativeLifecycle(t, ctx, db, 1, 1, true), userNativeLifecycle(t, ctx, db, 1, 1, true)
	confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, f.user, g.org)
	var err error
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	// Persisted human platform admin and organization roles remain authoritative.
	enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, g.user)
	human := previewAdmit(t, base, db, g.user)
	confirm = enforcementPreview(t, human, app, userProfilePreview(f.user)...)
	_, err = app.Mutation().DeleteAll(human, userProfileInput(f.user), confirm)
	require.NoError(t, err)
	_, err = app.Mutation().DeleteAll(previewAdmit(t, base, db, userNativeLifecycle(t, ctx, db, 0, 0, false).user), userProfileInput(g.user), nil)
	require.Error(t, err)
	h := userNativeLifecycle(t, ctx, db, 1, 1, true)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.user, g.org)
	confirm = enforcementPreview(t, human, app, userProfilePreview(h.user)...)
	enforcementExec(t, ctx, db, `UPDATE users SET role='user' WHERE id=$1`, g.user)
	_, err = app.Mutation().DeleteAll(human, userProfileInput(h.user), confirm)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, h.user))
}
