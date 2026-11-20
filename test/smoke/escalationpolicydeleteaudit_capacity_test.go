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
			ok, err := smokeDeleteAll(t, h, sd5App(h), sd3System(), input)
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
			ok, err := smokeDeleteAll(t, h, sd5App(h), sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root), sd3Target(assignment.TargetTypeEscalationPolicy, other)})
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
	// The full historical 250-target shape and its malformed 251st Session
	// remain negative controls. No mixed-root transaction is executable today.
	require.Len(t, input, 250)
	before := serviceManagementSnapshot(t, h)
	cmnrBefore := cmnrSnapshot(t, db)
	for _, raw := range [][]assignment.RawTarget{input, append(append([]assignment.RawTarget{}, input...), sd3Target(assignment.TargetTypeUserSession, "malformed"))} {
		ok, err := sd5App(h).Mutation().DeleteAll(sd3System(), raw, nil)
		require.Error(t, err)
		require.False(t, ok)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
		require.Equal(t, cmnrBefore, cmnrSnapshot(t, db))
		require.Zero(t, smokeDeletionSuccesses(t, h))
	}
	// Each refused request may record a non-assertive, unknown-root attempt.
	// It must never claim that any of the 250 business targets was deleted.
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE record_kind='attempt_observation' AND root_id IS NULL AND effects='[]'`))
	var services, policies []assignment.RawTarget
	for _, raw := range input {
		if raw.Type == assignment.TargetTypeService {
			services = append(services, raw)
		}
		if raw.Type == assignment.TargetTypeEscalationPolicy {
			policies = append(policies, raw)
		}
	}
	require.Len(t, services, 50)
	require.Len(t, policies, 50)
	// A legal, separately confirmed Service batch removes its own Keys. The
	// formerly referenced EP batch can then reach its own real Audit writer.
	ok, err := smokeDeleteAll(t, h, sd5App(h), sd3System(), services)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 50, sd1Count(t, h, "committed"))
	for _, root := range policies {
		sd5Step(t, h, root.ID)
	}
	confirmation := smokePlanConfirmation(t, h, sd3System(), policies)
	sd8Exec(t, h, `CREATE SEQUENCE sd5_capacity_hits;
CREATE FUNCTION sd5_capacity_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
IF nextval('sd5_capacity_hits')=50 THEN RAISE EXCEPTION 'SYNTHETIC_LAST_APPENDER'; END IF; RETURN NEW; END $$;
CREATE TRIGGER sd5_capacity_fault BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd5_capacity_fault()`)
	if failEP {
		sd8Exec(t, h, `CREATE SEQUENCE sd5_failure_hits;
CREATE FUNCTION sd5_failure_writer_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('sd5_failure_hits'); RAISE EXCEPTION 'SYNTHETIC_FAILURE_WRITER'; END $$;
CREATE TRIGGER sd5_failure_writer_fail BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='attempt_observation') EXECUTE FUNCTION sd5_failure_writer_fail()`)
	}
	ok, err = sd5App(h).Mutation().DeleteAll(sd3System(), policies, confirmation)
	require.Error(t, err)
	require.False(t, ok)
	require.EqualValues(t, 50, sd8Scalar(t, h, `SELECT last_value FROM sd5_capacity_hits`), "50th real success appender reached, then entire transaction rolled back")
	require.Zero(t, sd5Count(t, h))
	for _, root := range policies {
		require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root.ID))
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id=$1`, root.ID))
	}
	var observations, executions, attempts int
	require.NoError(t, db.QueryRow(`SELECT count(*),count(DISTINCT execution_id),count(DISTINCT attempt_id) FROM escalation_policy_delete_audit_events WHERE record_kind='attempt_observation' AND root_id IS NOT NULL`).Scan(&observations, &executions, &attempts))
	if failEP {
		require.Contains(t, err.Error(), "audit persistence unavailable")
		require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM sd5_failure_hits WHERE is_called`), "failure writer actually reached")
		require.Equal(t, []int{0, 0, 0}, []int{observations, executions, attempts})
		sd8Exec(t, h, `DROP TRIGGER sd5_failure_writer_fail ON escalation_policy_delete_audit_events; DROP FUNCTION sd5_failure_writer_fail(); DROP SEQUENCE sd5_failure_hits`)
	} else {
		require.Equal(t, []int{50, 1, 1}, []int{observations, executions, attempts})
	}
	sd8Exec(t, h, `DROP TRIGGER sd5_capacity_fault ON escalation_policy_delete_audit_events; DROP FUNCTION sd5_capacity_fault(); DROP SEQUENCE sd5_capacity_hits`)
	// Positive maximum native-root batch uses NEW roots, not an automatic
	// retry of the faulted operation. The original faulted roots stay intact.
	var fresh []assignment.RawTarget
	for i := 0; i < 50; i++ {
		root := sd5EP(t, h, harness.SmokeOrganizationID)
		sd5Step(t, h, root)
		fresh = append(fresh, sd3Target(assignment.TargetTypeEscalationPolicy, root))
	}
	ok, err = smokeDeleteAll(t, h, sd5App(h), sd3System(), fresh)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 50, sd5Count(t, h))
	for _, root := range fresh {
		require.Zero(t, serviceManagementCount(t, h, "escalation_policies", root.ID))
		require.Len(t, sd5Effects(t, h, root.ID), 1)
	}
	for _, root := range policies {
		require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root.ID))
	}
	require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
	require.Zero(t, sd4Count(t, h))
	require.EqualValues(t, 50, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE name='SD5 capacity'`))
	require.NotContains(t, sd5Rows(t, h), "SYNTHETIC_")
	t.Log("legacy 250/251 mixed inputs refused atomically; legal 50-root Audit success and 50th-appender rollback verified; no 250-row shared failure-writer claim")
}
