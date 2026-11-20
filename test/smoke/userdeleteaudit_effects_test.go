package smoke

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func sd8Assign(t *testing.T, h *harness.Harness, user, org string) {
	t.Helper()
	sd8Exec(t, h, `UPDATE users SET role='user' WHERE id=$1 AND role='unknown'`, user)
	sd8Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,source_config_version,authoritative_evaluated_at) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',1,'sd8-synthetic',now())`, user, org)
}

func TestUserDeleteAuditCompleteB2(t *testing.T) {
	t.Run("legacy_referenced_user_is_preserved", func(t *testing.T) {
		h := sd1Harness(t)
		u, v, w := sd7User(t, h), sd7User(t, h), sd7User(t, h)
		sd8Assign(t, h, u, harness.SmokeOrganizationID)
		sd8Assign(t, h, v, harness.SmokeOrganizationID)
		sd8Assign(t, h, w, harness.SmokeOrganizationID)
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
		input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
		before := smokeUserBusinessState(t, h)
		_, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
		smokeDeletionCode(t, previewErr, ds.DeletionUnavailable)
		ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, nil)
		require.Error(t, err)
		require.False(t, ok)
		require.Equal(t, before, smokeUserBusinessState(t, h), "all historical B2 fixture rows, including referenced Rule/Participant/Action/Override, remain")
		require.Zero(t, smokeDeletionSuccesses(t, h))
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
	})
	t.Run("legal_owned_b2", func(t *testing.T) {
		h := sd1Harness(t)
		u, v, w := sd7User(t, h), sd7User(t, h), sd7User(t, h)
		for _, user := range []string{u, v, w} {
			sd8Assign(t, h, user, harness.SmokeOrganizationID)
		}
		s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
		rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
		cm, nr := sd8CMNR(t, h, u)
		step := sd5Step(t, h, h.UUID("policy-a"))
		sd8Exec(t, h, `INSERT INTO user_favorites(id,user_id,tgt_user_id,tgt_service_id,tgt_schedule_id,tgt_rotation_id,tgt_escalation_policy_id) VALUES(9007199254740993,$1,$2,$3,$4,$5,$6)`, u, v, h.UUID("service-a"), s, rot, h.UUID("policy-a"))
		sd8Exec(t, h, `INSERT INTO user_favorites(id,user_id,tgt_user_id) VALUES(-9007199254740993,$1,$2)`, v, u)
		sd8Exec(t, h, `INSERT INTO schedule_on_call_users(id,schedule_id,user_id,start_time,end_time) VALUES(9007199254740993,$1,$2,'-infinity',NULL),(9007199254740994,$1,$2,'10000-01-01 00:00:00+00','10001-01-01 00:00:00+00'),(9007199254740995,$1,$2,'0001-01-01 00:00:00+00 BC','294276-01-01 00:00:00+00')`, s, u)
		sd8Exec(t, h, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01',NULL),($1,$2,'2020-01-01','infinity')`, step, u)
		sd8Exec(t, h, `INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('SYNTHETIC_PRIVATE','first',$1,$2)`, u, cm)
		locator := uuid.NewString()
		sd8Exec(t, h, `INSERT INTO auth_user_sessions(id,user_id,user_agent) VALUES($1,$2,'SYNTHETIC_PRIVATE')`, locator, u)
		var safeSession string
		require.NoError(t, h.App().DB().QueryRow(`SELECT audit_resource_id::text FROM auth_user_sessions WHERE id=$1`, locator).Scan(&safeSession))
		sd8Exec(t, h, `INSERT INTO auth_basic_users(id,user_id,username,password_hash) VALUES(9007199254740993,$1,'SYNTHETIC_PRIVATE','SYNTHETIC_PRIVATE')`, u)
		ok, err := smokeDeleteAll(t, h, sd7App(h), sd3System(), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
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
		require.Equal(t, map[string]int64{"contact_method": 1, "notification_rule": 1, "user_favorite": 2, "schedule_on_call_history": 3, "ep_step_on_call_history": 2, "user_organization_assignment": 1, "auth_subject": 2, "user_session": 1, "basic_auth_link": 1}, types)
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
		require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id IN ($1,$2)`, v, w))
		require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_favorite' AND resource_key IN ('9007199254740993','-9007199254740993')`))
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_favorite' AND resource_key='9007199254740993' AND payload#>>'{before,target_user_id}'=$1 AND payload#>>'{before,target_service_id}'=$2 AND payload#>>'{before,target_schedule_id}'=$3 AND payload#>>'{before,target_rotation_id}'=$4 AND payload#>>'{before,target_escalation_policy_id}'=$5`, v, h.UUID("service-a"), s, rot, h.UUID("policy-a")))
		require.EqualValues(t, 3, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='schedule_on_call_history' AND ((resource_key='9007199254740993' AND payload#>>'{before,start}'='-infinity' AND payload#>'{before,end}'='null') OR (resource_key='9007199254740994' AND payload#>>'{before,start}'='10000-01-01T00:00:00Z' AND payload#>>'{before,end}'='10001-01-01T00:00:00Z') OR (resource_key='9007199254740995' AND payload#>>'{before,start}'='0001-01-01T00:00:00Z BC' AND payload#>>'{before,end}'='294276-01-01T00:00:00Z'))`))
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_session' AND resource_key=$1 AND payload#>>'{before,version}'='2'`, safeSession))
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE payload::text LIKE '%SYNTHETIC_PRIVATE%' OR resource_key=$1 OR payload::text LIKE '%'||$1||'%'`, locator))
		for table, id := range map[string]string{"schedules": s, "rotations": rot, "escalation_policy_steps": step, "escalation_policies": h.UUID("policy-a")} {
			require.Equal(t, 1, serviceManagementCount(t, h, table, id))
		}
		var before string
		require.NoError(t, h.App().DB().QueryRow(`SELECT payload->'before'::text FROM user_delete_audit_effects WHERE resource_type='notification_rule' AND resource_key=$1`, nr).Scan(&before))
		require.Contains(t, before, cm)
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness' AND request_id IS NOT NULL AND execution_id IS NOT NULL AND attempt_id IS NOT NULL AND effect_count=14`, u))
	})
}

func smokeUserBusinessState(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	state := map[string]string{}
	for _, table := range []string{"users", "user_organization_assignments", "user_contact_methods", "user_notification_rules", "auth_subjects", "auth_user_sessions", "auth_basic_users", "schedules", "rotations", "rotation_participants", "rotation_state", "schedule_rules", "user_overrides", "user_favorites", "escalation_policy_actions", "schedule_on_call_users", "ep_step_on_call_users"} {
		var digest string
		require.NoError(t, h.App().DB().QueryRow(`SELECT md5(coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]')::text) FROM `+table+` x`).Scan(&digest))
		state[table] = digest
	}
	return state
}

func TestUserDeleteAuditAtomicFailure(t *testing.T) {
	h := sd1Harness(t)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	for _, mode := range []string{"root_suppressed", "child_suppressed", "last_page", "deferred_commit"} {
		t.Run(mode, func(t *testing.T) {
			u := sd7User(t, h)
			sd8Assign(t, h, u, harness.SmokeOrganizationID)
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
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			confirmation, previewErr := smokeDeletionConfirmation(t, h, permission.SystemContext(t.Context(), "Engine"), input)
			require.NoError(t, previewErr)
			require.NotNil(t, confirmation)
			sd8Exec(t, h, `CREATE SEQUENCE sd8_fault_hits`)
			body = `PERFORM nextval('sd8_fault_hits');` + body
			sd8Exec(t, h, `CREATE FUNCTION sd8_atomic_failure() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN `+body+`END;$$;CREATE `+prefix+`TRIGGER sd8_atomic_failure `+timing+` `+event+` ON `+table+` `+deferred+` FOR EACH ROW `+condition+` EXECUTE FUNCTION sd8_atomic_failure()`)
			before := smokeUserBusinessState(t, h)
			ok, err := sd7App(h).Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), input, confirmation)
			require.Error(t, err)
			require.False(t, ok)
			require.Equal(t, before, smokeUserBusinessState(t, h), "all business rows restored after the reached fault")
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM sd8_fault_hits WHERE is_called`), "nontransactional sequence proves target fault trigger ran")
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 300, sd8Scalar(t, h, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=$1`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
			sd8Exec(t, h, `DROP TRIGGER sd8_atomic_failure ON `+table+`;DROP FUNCTION sd8_atomic_failure(); DROP SEQUENCE sd8_fault_hits`)
			raw, _ := json.Marshal(err.Error())
			require.NotContains(t, string(raw), "SYNTHETIC_PRIVATE")
			t.Logf("%s: business fully restored, no success/detail rows", mode)
		})
	}
}
