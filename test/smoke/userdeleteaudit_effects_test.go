package smoke

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func sd8Assign(t *testing.T, h *harness.Harness, user, org string) {
	t.Helper()
	sd8Exec(t, h, `UPDATE users SET role='user' WHERE id=$1 AND role='unknown'`, user)
	sd8Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,source_config_version,authoritative_evaluated_at) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',1,'sd8-synthetic',now())`, user, org)
}

func TestUserDeleteAuditCompleteB2(t *testing.T) {
	h := sd1Harness(t)
	u, v, w := sd7User(t, h), sd7User(t, h), sd7User(t, h)
	sd8Assign(t, h, u, harness.SmokeOrganizationID)
	s, rot := sd6Root(t, h, "schedule", harness.SmokeOrganizationID), sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
	parts := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for i, user := range []string{u, v, w} {
		sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, parts[i], rot, user, i)
	}
	sd8Exec(t, h, `UPDATE rotation_state SET rotation_participant_id=$2,position=2 WHERE rotation_id=$1`, rot, parts[2])
	cm, nr := sd8CMNR(t, h, u)
	sd8Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id,start_time,end_time) VALUES($1,$2,$3,'08:00','09:00')`, uuid.New(), s, u)
	sd8Exec(t, h, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$2,$3,$4,'2020-01-01','2020-01-02')`, uuid.New(), s, u, v)
	sd8Exec(t, h, `INSERT INTO user_favorites(id,user_id,tgt_user_id,tgt_service_id,tgt_schedule_id,tgt_rotation_id,tgt_escalation_policy_id) VALUES(9007199254740993,$1,$2,$3,$4,$5,$6)`, u, v, h.UUID("service-a"), s, rot, h.UUID("policy-a"))
	sd8Exec(t, h, `INSERT INTO user_favorites(id,user_id,tgt_user_id) VALUES(-9007199254740993,$1,$2)`, v, u)
	step := sd5Step(t, h, h.UUID("policy-a"))
	sd8Exec(t, h, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, uuid.New(), step, u)
	sd8Exec(t, h, `INSERT INTO schedule_on_call_users(id,schedule_id,user_id,start_time,end_time) VALUES(9007199254740993,$1,$2,'-infinity',NULL),(9007199254740994,$1,$2,'10000-01-01 00:00:00+00','10001-01-01 00:00:00+00'),(9007199254740995,$1,$2,'0001-01-01 00:00:00+00 BC','294276-01-01 00:00:00+00')`, s, u)
	sd8Exec(t, h, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01',NULL),($1,$2,'2020-01-01','infinity')`, step, u)
	sd8Exec(t, h, `INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('SYNTHETIC_PRIVATE','first',$1,$3),('SYNTHETIC_PRIVATE','second',$2,$3)`, u, v, cm)
	sd8Exec(t, h, `INSERT INTO auth_user_sessions(id,user_id,user_agent) VALUES($1,$2,'SYNTHETIC_PRIVATE')`, uuid.New(), u)
	sd8Exec(t, h, `INSERT INTO auth_basic_users(id,user_id,username,password_hash) VALUES(9007199254740993,$1,'SYNTHETIC_PRIVATE','SYNTHETIC_PRIVATE')`, u)
	// Seed a Schema-reachable stale status setting via CM retargeting. Every
	// statement keeps the existing owner checks and FK triggers enabled.
	sd8Exec(t, h, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, cm, v)
	sd8Exec(t, h, `UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, v, cm)
	sd8Exec(t, h, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, cm, u)
	sd8Exec(t, h, `UPDATE users SET alert_status_log_contact_method_id=$2 WHERE id=$1`, u, cm)
	app := sd7App(h)
	ok, err := app.Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
	require.NoError(t, err)
	require.True(t, ok)
	types := map[string]int64{}
	rows, err := h.App().DB().Query(`SELECT resource_type,count(*) FROM user_delete_audit_effects GROUP BY resource_type`)
	require.NoError(t, err)
	for rows.Next() {
		var typ string
		var n int64
		require.NoError(t, rows.Scan(&typ, &n))
		types[typ] = n
	}
	require.NoError(t, rows.Err())
	rows.Close()
	expected := map[string]int64{"schedule_rule": 1, "rotation_participant": 3, "rotation_participant_count": 1, "rotation_state": 1, "user_override": 1, "contact_method": 1, "notification_rule": 1, "user_favorite": 2, "escalation_policy_action": 1, "schedule_on_call_history": 3, "ep_step_on_call_history": 2, "user_organization_assignment": 1, "auth_subject": 3, "user_session": 1, "basic_auth_link": 1, "user_status_contact_setting": 1}
	require.Equal(t, expected, types)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1 AND alert_status_log_contact_method_id IS NULL`, v))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, w))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE payload::text LIKE '%SYNTHETIC_PRIVATE%'`))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_favorite' AND resource_key IN ('9007199254740993','-9007199254740993')`))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_favorite' AND resource_key='9007199254740993' AND payload#>>'{before,target_user_id}'=$1 AND payload#>>'{before,target_service_id}'=$2 AND payload#>>'{before,target_schedule_id}'=$3 AND payload#>>'{before,target_rotation_id}'=$4 AND payload#>>'{before,target_escalation_policy_id}'=$5`, v, h.UUID("service-a"), s, rot, h.UUID("policy-a")))
	require.EqualValues(t, 3, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='schedule_on_call_history' AND ((resource_key='9007199254740993' AND payload#>>'{before,start}'='-infinity' AND payload#>'{before,end}'='null') OR (resource_key='9007199254740994' AND payload#>>'{before,start}'='10000-01-01T00:00:00Z' AND payload#>>'{before,end}'='10001-01-01T00:00:00Z') OR (resource_key='9007199254740995' AND payload#>>'{before,start}'='0001-01-01T00:00:00Z BC' AND payload#>>'{before,end}'='294276-01-01T00:00:00Z'))`))
	for table, id := range map[string]string{"schedules": s, "rotations": rot, "escalation_policy_steps": step, "escalation_policies": h.UUID("policy-a")} {
		require.Equal(t, 1, serviceManagementCount(t, h, table, id))
	}
	var before string
	require.NoError(t, h.App().DB().QueryRow(`SELECT payload->'before'::text FROM user_delete_audit_effects WHERE resource_type='notification_rule' AND resource_key=$1`, nr).Scan(&before))
	require.Contains(t, before, cm)
	t.Log("complete whitelist", types)
}

func TestUserDeleteAuditAtomicFailure(t *testing.T) {
	h := sd1Harness(t)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	for _, mode := range []string{"root_suppressed", "child_suppressed", "last_page", "deferred_commit"} {
		t.Run(mode, func(t *testing.T) {
			u := sd7User(t, h)
			sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,$2,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM generate_series(1,300) g`, s, u)
			table, event, condition, body := "users", "DELETE", "", `RETURN NULL;`
			switch mode {
			case "child_suppressed":
				table = "schedule_on_call_users"
			case "last_page":
				table, event, condition, body = "user_delete_audit_effects", "INSERT", "WHEN (NEW.effect_ordinal=299)", `RAISE EXCEPTION 'SYNTHETIC_PRIVATE';`
			case "deferred_commit":
				table, event, body = "user_delete_audit_events", "INSERT", `IF NEW.record_kind='success_witness' THEN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END IF;RETURN NEW;`
			}
			timing := "BEFORE"
			prefix := ""
			deferred := ""
			if mode == "deferred_commit" {
				timing = "AFTER"
				prefix = "CONSTRAINT "
				deferred = "DEFERRABLE INITIALLY DEFERRED"
			}
			sd8Exec(t, h, `CREATE FUNCTION sd8_atomic_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN `+body+`END;$$;CREATE `+prefix+`TRIGGER sd8_atomic_failure `+timing+` `+event+` ON `+table+` `+deferred+` FOR EACH ROW `+condition+` EXECUTE FUNCTION sd8_atomic_failure()`)
			ok, err := sd7App(h).Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.Error(t, err)
			require.False(t, ok)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 300, sd8Scalar(t, h, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=$1`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
			sd8Exec(t, h, `DROP TRIGGER sd8_atomic_failure ON `+table+`;DROP FUNCTION sd8_atomic_failure()`)
			raw, _ := json.Marshal(err.Error())
			require.NotContains(t, string(raw), "SYNTHETIC_PRIVATE")
			t.Logf("%s: business fully restored, no success/detail rows", mode)
		})
	}
}
