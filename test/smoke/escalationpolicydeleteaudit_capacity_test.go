package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestEscalationPolicyDeleteAuditCountBudgetAcrossRoots(t *testing.T) {
	t.Parallel()
	for _, count := range []int{epaudit.MaxEffects, epaudit.MaxEffects + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			roots := []string{}
			input := []assignment.RawTarget{}
			for i := 0; i < 50; i++ {
				root := sd5EP(t, h, harness.SmokeOrganizationID)
				roots = append(roots, root)
				input = append(input, sd3Target(assignment.TargetTypeEscalationPolicy, root))
			}
			// The original triggers and constraints execute unchanged. Spread steps
			// across 50 roots so each trigger counts only a bounded small root.
			_, err := db.Exec(`UPDATE config_limits SET max=-1 WHERE id='ep_steps_per_policy'`)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO escalation_policy_steps(escalation_policy_id) SELECT roots[(n-1)%50+1] FROM (SELECT $1::uuid[] roots) r CROSS JOIN generate_series(1,$2) n`, pq.Array(roots), count)
			require.NoError(t, err)
			ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), input)
			var actual int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id=ANY($1::uuid[])`, pq.Array(roots)).Scan(&actual))
			if count == epaudit.MaxEffects {
				require.NoError(t, err)
				require.True(t, ok)
				require.Zero(t, actual)
				require.Equal(t, 50, sd5Count(t, h))
				var total, bytes int
				require.NoError(t, db.QueryRow(`SELECT sum(jsonb_array_length(effects)),sum(octet_length(effects::text)) FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'`).Scan(&total, &bytes))
				require.Equal(t, count, total)
				require.LessOrEqual(t, bytes, epaudit.MaxJSONBytes)
				t.Logf("actual 50-root count boundary: effects=%d PG bytes=%d", total, bytes)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, count, actual)
				require.Zero(t, sd5Count(t, h))
				var observations, attempts int
				require.NoError(t, db.QueryRow(`SELECT count(*),count(DISTINCT attempt_id) FROM escalation_policy_delete_audit_events`).Scan(&observations, &attempts))
				require.Equal(t, 50, observations)
				require.Equal(t, 1, attempts, "sticky capacity failure must not retry")
			}
		})
	}
}

func TestEscalationPolicyDeleteAuditByteBudgetAcrossRoots(t *testing.T) {
	t.Parallel()
	for _, extra := range []int{0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root, other := sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
			owner, org, r := uuid.New(), uuid.MustParse(harness.SmokeOrganizationID), uuid.MustParse(root)
			id := int64(1000000000000000000)
			f := epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Favorite, RootID: r, TargetOrganizationID: org, ResourceNumericID: &id, OwnerUserID: &owner, OwnerOrganizationID: &org, OwnerOrgResolution: "known_normal", Relation: "escalation_policy.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "escalation_policy_delete"}
			raw, err := json.Marshal([]epaudit.Effect{f})
			require.NoError(t, err)
			var unit int
			require.NoError(t, db.QueryRow(`SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&unit))
			count := (epaudit.MaxJSONBytes + unit - 1) / unit
			reduce := count*unit - epaudit.MaxJSONBytes - extra
			require.Positive(t, reduce)
			require.Less(t, reduce, count)
			require.Less(t, count, epaudit.MaxEffects)
			_, err = db.Exec(`INSERT INTO users(id,name,role) SELECT gen_random_uuid(),'SD5 byte owner','user' FROM generate_series(1,$1)`, count)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at,source_config_version) SELECT id,$1,'NORMAL',$1,'ORG_MEMBER','EXACTLY_ONE',1,now(),'sd5-byte-capacity' FROM users WHERE name='SD5 byte owner'`, harness.SmokeOrganizationID)
			require.NoError(t, err)
			// A 19-digit identity versus an 18-digit identity changes the closed
			// projection by exactly one byte. This reaches 8 MiB and 8 MiB+1 exactly.
			_, err = db.Exec(`INSERT INTO user_favorites(id,user_id,tgt_escalation_policy_id) SELECT CASE WHEN n<=$3 THEN 100000000000000000+n ELSE 1000000000000000000+n END,id,CASE WHEN n%2=0 THEN $1::uuid ELSE $2::uuid END FROM (SELECT id,row_number() OVER(ORDER BY id) n FROM users WHERE name='SD5 byte owner') owners`, root, other, reduce)
			require.NoError(t, err)
			ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root), sd3Target(assignment.TargetTypeEscalationPolicy, other)})
			if extra == 0 {
				require.NoError(t, err)
				require.True(t, ok)
				var bytes, effects int
				require.NoError(t, db.QueryRow(`SELECT sum(octet_length(effects::text)),sum(jsonb_array_length(effects)) FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'`).Scan(&bytes, &effects))
				require.Equal(t, epaudit.MaxJSONBytes, bytes)
				require.Equal(t, count, effects)
				require.Equal(t, 2, sd5Count(t, h))
				t.Logf("actual multi-root byte boundary: effects=%d PG bytes=%d", effects, bytes)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				require.Zero(t, sd5Count(t, h))
				var actual int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_favorites WHERE tgt_escalation_policy_id IN ($1,$2)`, root, other).Scan(&actual))
				require.Equal(t, count, actual)
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root))
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", other))
			}
		})
	}
}

func TestEscalationPolicyDeleteAuditFailureCapacity250(t *testing.T) {
	t.Parallel()
	for _, failEP := range []bool{false, true} {
		t.Run(fmt.Sprint(failEP), func(t *testing.T) { sd5FailureCapacity250(t, failEP) })
	}
}
func sd5FailureCapacity250(t *testing.T, failEP bool) {
	h := sd1Harness(t)
	db := h.App().DB()
	input := []assignment.RawTarget{}
	_, err := db.Exec(`UPDATE config_limits SET max=-1 WHERE id IN ('contact_methods_per_user','notification_rules_per_user')`)
	require.NoError(t, err)
	for i := 0; i < 50; i++ {
		root := sd5EP(t, h, harness.SmokeOrganizationID)
		svc, cm, nr := uuid.NewString(), uuid.NewString(), uuid.NewString()
		_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,$4)`, svc, harness.SmokeOrganizationID, root, "SD5 capacity "+svc)
		require.NoError(t, err)
		key, _ := sd3Key(t, h, svc)
		_, err = db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'SD5 capacity',$3)`, cm, h.UUID("user-a"), fmt.Sprintf(`{"Type":"builtin-smtp-email","Args":{"email_address":"capacity-%d@example.invalid"}}`, i))
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, nr, h.UUID("user-a"), cm)
		require.NoError(t, err)
		input = append(input, sd3Target(assignment.TargetTypeService, svc), sd3Target(assignment.TargetTypeIntegrationKey, key.String()), sd3Target(assignment.TargetTypeEscalationPolicy, root), sd3Target(assignment.TargetTypeContactMethod, cm), sd3Target(assignment.TargetTypeNotificationRule, nr))
	}
	if failEP {
		_, err := db.Exec(`CREATE FUNCTION sd5_failure_writer_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_FAILURE_WRITER'; END $$; CREATE TRIGGER sd5_failure_writer_fail BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='attempt_observation') EXECUTE FUNCTION sd5_failure_writer_fail()`)
		require.NoError(t, err)
	}
	// The existing last group fails only after every covered group has run. No
	// Session auditing is added; this is an atomic rollback/failure-writer probe.
	input = append(input, sd3Target(assignment.TargetTypeUserSession, "malformed"))
	ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), input)
	require.Error(t, err)
	require.False(t, ok)
	var total, executions, attempts, successes int
	require.NoError(t, db.QueryRow(`WITH events AS (
	 SELECT execution_id,attempt_id,outcome FROM service_delete_audit_events
	 UNION ALL SELECT execution_id,attempt_id,outcome FROM user_cmnr_delete_audit_events
	 UNION ALL SELECT execution_id,attempt_id,outcome FROM integration_key_delete_audit_events
	 UNION ALL SELECT execution_id,attempt_id,outcome FROM escalation_policy_delete_audit_events)
	 SELECT count(*),count(DISTINCT execution_id),count(DISTINCT attempt_id),count(*) FILTER(WHERE outcome='committed') FROM events`).Scan(&total, &executions, &attempts, &successes))
	want, groups := 250, 1
	if failEP {
		want, groups = 0, 0
		require.Contains(t, err.Error(), "audit persistence unavailable")
	}
	require.Equal(t, want, total)
	require.Equal(t, groups, executions)
	require.Equal(t, groups, attempts)
	require.Zero(t, successes)
	for table, want := range map[string]int{"service_delete_audit_events": 50, "user_cmnr_delete_audit_events": 100, "integration_key_delete_audit_events": 50, "escalation_policy_delete_audit_events": 50} {
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		if failEP {
			want = 0
		}
		require.Equal(t, want, count)
	}
	var services, eps int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM services WHERE name LIKE 'SD5 capacity %'`).Scan(&services))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM escalation_policies WHERE name LIKE 'SD5 %'`).Scan(&eps))
	require.Equal(t, 50, services)
	require.Equal(t, 50, eps)
}
