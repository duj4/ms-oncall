package smoke

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditAllTypedRoots(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", true)
			db := h.App().DB()
			u := sd7User(t, h)
			sd8Assign(t, h, u, harness.SmokeOrganizationID)
			// A genuine prior signed owner request creates v1 history and a Session.
			priorCM, priorNR := sd8CMNR(t, h, u)
			priorToken := h.GraphQLToken(u)
			status, prior := sd8HTTP(t, h, cmnrAuditQuery(priorCM, priorNR), priorToken)
			require.Equal(t, 200, status)
			require.Empty(t, prior.Errors)
			var oldHistory string
			require.NoError(t, db.QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM user_cmnr_delete_audit_events e WHERE schema_version=1 AND actor_id=$1`, u).Scan(&oldHistory))
			s, rot := sd6Root(t, h, "schedule", harness.SmokeOrganizationID), sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
			_ = sd6Rule(t, h, s, rot)
			override := uuid.NewString()
			sd8Exec(t, h, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, override, s, u)
			sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01','2020-01-02')`, s, u)
			policy := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, policy)
			_ = sd6Action(t, h, step, "schedule", s)
			key, _ := sd3Key(t, h, h.UUID("service-c"))
			cm, nr := sd8CMNR(t, h, u)
			if fail {
				sd8Exec(t, h, `CREATE FUNCTION sd8_mixed_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd8_mixed_fail BEFORE INSERT ON user_cmnr_delete_audit_events FOR EACH ROW WHEN (NEW.schema_version=2) EXECUTE FUNCTION sd8_mixed_fail()`)
			}
			targets := []string{fmt.Sprintf(`{type:rotation,id:%q}`, rot), fmt.Sprintf(`{type:userOverride,id:%q}`, override), fmt.Sprintf(`{type:schedule,id:%q}`, s), fmt.Sprintf(`{type:integrationKey,id:%q}`, key.String()), fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-b")), fmt.Sprintf(`{type:escalationPolicy,id:%q}`, policy), fmt.Sprintf(`{type:contactMethod,id:%q}`, cm), fmt.Sprintf(`{type:notificationRule,id:%q}`, nr)}
			var expected func()
			if fail {
				expected = h.ExpectBackendError("deleteAll transaction failed")
			}
			status, result := sd8HTTP(t, h, sd8Query(u, targets...), h.GraphQLToken(h.UUID("user-a")))
			require.Equal(t, 200, status)
			if expected != nil {
				expected()
			}
			if fail {
				require.NotEmpty(t, result.Errors)
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
				for table, id := range map[string]string{"users": u, "schedules": s, "rotations": rot, "user_overrides": override, "services": h.UUID("service-b"), "escalation_policies": policy, "user_contact_methods": cm, "user_notification_rules": nr, "integration_keys": key.String()} {
					require.Equal(t, 1, serviceManagementCount(t, h, table, id))
				}
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Zero(t, sd4Count(t, h))
				require.Zero(t, sd5Count(t, h))
				require.Zero(t, sd6Count(t, h))
				require.Zero(t, sd7Count(t, h))
			} else {
				require.Empty(t, result.Errors)
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type IN ('user_override','schedule_on_call_history','contact_method','notification_rule')`), "earlier explicit groups and later derived explicit events are represented once")
				var attempt string
				require.NoError(t, db.QueryRow(`SELECT attempt_id FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u).Scan(&attempt))
				var roots, correlations int
				require.NoError(t, db.QueryRow(`SELECT count(*),count(DISTINCT ROW(request_id,execution_id,attempt_id)) FROM (
    SELECT request_id,execution_id,attempt_id FROM user_delete_audit_events WHERE record_kind='success_witness'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM user_cmnr_delete_audit_events WHERE record_kind='success_witness'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM service_delete_audit_events WHERE outcome='committed'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM integration_key_delete_audit_events WHERE record_kind='success_witness'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM schedule_rotation_delete_audit_events WHERE record_kind='success_witness'
    UNION ALL SELECT request_id,execution_id,attempt_id FROM user_override_delete_audit_events WHERE record_kind='success_witness') events WHERE attempt_id=$1`, attempt).Scan(&roots, &correlations))
				require.Equal(t, 9, roots)
				require.Equal(t, 1, correlations)
				status, _ = sd8HTTP(t, h, sd8Query(uuid.NewString()), priorToken)
				require.Equal(t, 401, status)
				// Preserve every previously written typed family while deleting its
				// real historical actor, including this request's User root.
				history := map[string]string{}
				for _, table := range []string{"service_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events", "user_override_delete_audit_events", "user_delete_audit_events"} {
					var snapshot string
					require.NoError(t, db.QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM `+table+` e WHERE attempt_id=$1`, attempt).Scan(&snapshot))
					history[table] = snapshot
				}
				status, self := sd8HTTP(t, h, sd8Query(h.UUID("user-a")), h.GraphQLToken(h.UUID("user-a")))
				require.Equal(t, 200, status)
				require.Empty(t, self.Errors)
				for table, before := range history {
					var after string
					require.NoError(t, db.QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM `+table+` e WHERE attempt_id=$1`, attempt).Scan(&after))
					require.Equal(t, before, after, table)
				}
			}
			var after string
			require.NoError(t, db.QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM user_cmnr_delete_audit_events e WHERE schema_version=1 AND actor_id=$1`, u).Scan(&after))
			require.Equal(t, oldHistory, after, "all bytes of prior v1 logical rows survive User deletion/rollback")
		})
	}
}
