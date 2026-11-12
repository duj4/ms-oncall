package smoke

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUODeleteAuditAllTypedGroupsAtomicity(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("late_cmnr_failure=%t", fail), func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", true)
			db := h.App().DB()
			s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
			_ = sd6Rule(t, h, s, r)
			override := sd7Root(t, h, s)
			policy := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, policy)
			_ = sd6Action(t, h, step, sraudit.Schedule, s)
			key, _ := sd3Key(t, h, h.UUID("service-c"))
			cm, nr := uuid.NewString(), uuid.NewString()
			_, err := db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'SYNTHETIC_PRIVATE','{"Type":"builtin-smtp-email","Args":{"email_address":"SYNTHETIC_DEST@example.invalid"}}')`, cm, h.UUID("user-a"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, nr, h.UUID("user-a"), cm)
			require.NoError(t, err)
			if fail {
				_, err = db.Exec(`CREATE FUNCTION sd6_mixed_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd6_mixed_fail BEFORE INSERT ON user_cmnr_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd6_mixed_fail()`)
				require.NoError(t, err)
			}
			others := fmt.Sprintf(`{type:rotation,id:%q},{type:service,id:%q},{type:escalationPolicy,id:%q},{type:integrationKey,id:%q},{type:contactMethod,id:%q},{type:notificationRule,id:%q}`, r, h.UUID("service-b"), policy, key.String(), cm, nr) + fmt.Sprintf(`,{type:userOverride,id:%q}`, override)
			var expected func()
			if fail {
				expected = h.ExpectBackendError("deleteAll transaction failed")
			}
			response := stepOrganizationQuery(t, h, sd6Query(sraudit.Schedule, []string{s}, others))
			if expected != nil {
				expected()
			}
			if fail {
				require.NotEmpty(t, response.Errors)
				require.Zero(t, sd6Count(t, h))
				require.Zero(t, sd7Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", override))
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Zero(t, sd4Count(t, h))
				require.Zero(t, sd5Count(t, h))
				for table, id := range map[string]string{"schedules": s, "rotations": r, "services": h.UUID("service-b"), "escalation_policies": policy, "integration_keys": key.String(), "user_contact_methods": cm, "user_notification_rules": nr} {
					require.Equal(t, 1, serviceManagementCount(t, h, table, id))
				}
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_cmnr_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
				require.Zero(t, n)
			} else {
				require.Empty(t, response.Errors)
				require.Equal(t, 2, sd6Count(t, h))
				require.Equal(t, 1, sd7Count(t, h))
				require.NotContains(t, fmt.Sprint(sd6Effects(t, h, s)), override)
				require.Equal(t, 1, sd1Count(t, h, "committed"))
				require.Equal(t, 1, sd4Count(t, h))
				require.Equal(t, 1, sd5Count(t, h))
				var roots, correlations int
				require.NoError(t, db.QueryRow(`SELECT count(*),count(DISTINCT ROW(request_id,execution_id,attempt_id)) FROM (
 SELECT request_id,execution_id,attempt_id FROM service_delete_audit_events WHERE outcome='committed'
 UNION ALL SELECT request_id,execution_id,attempt_id FROM user_cmnr_delete_audit_events WHERE record_kind='success_witness'
 UNION ALL SELECT request_id,execution_id,attempt_id FROM integration_key_delete_audit_events WHERE record_kind='success_witness'
 UNION ALL SELECT request_id,execution_id,attempt_id FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'
 UNION ALL SELECT request_id,execution_id,attempt_id FROM user_override_delete_audit_events WHERE record_kind='success_witness'
 UNION ALL SELECT request_id,execution_id,attempt_id FROM schedule_rotation_delete_audit_events WHERE record_kind='success_witness') e`).Scan(&roots, &correlations))
				require.Equal(t, 8, roots)
				require.Equal(t, 1, correlations)
			}
			require.NotContains(t, sd6Rows(t, h)+sd1Rows(t, h)+sd4Rows(t, h)+sd5Rows(t, h)+cmnrAuditRows(t, h), "SYNTHETIC_")
		})
	}
}
