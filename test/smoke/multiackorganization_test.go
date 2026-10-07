package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
)

// Include xmin so even a same-value UPDATE is observable. The Engine is paused
// before snapshots, and session creation happens before denial probes.
func multiAckOrganizationSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{
		"escalation_policies", "escalation_policy_steps", "escalation_policy_actions",
		"services", "alerts", "alert_logs", "notification_policy_cycles", "outgoing_messages", "river_job",
		"schedules", "schedule_rules", "rotations", "rotation_participants", "rotation_state",
	} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) || jsonb_build_object('row_version', r.xmin::text) ORDER BY to_jsonb(r)::text), '[]')::text FROM `+table+` r`).Scan(&rows))
		result[table] = rows
	}
	return result
}

func TestMultiAckOrganizationGraphQLRoundTripAndDenial(t *testing.T) {
	t.Parallel()
	h := harness.NewHarness(t, stepParentOrganizationSQL, "")
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	db := h.App().DB()
	_, err := db.Exec(`UPDATE user_organization_assignments SET organization_role = 'ORG_ADMIN' WHERE user_id = $1`, h.UUID("user-a"))
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE user_organization_assignments SET effective_organization_id = $1, effective_normal_organization_id = $1, organization_role = 'ORG_ADMIN' WHERE user_id = $2`,
		h.UUID("org-b"), h.UUID("user-other"))
	require.NoError(t, err)
	actors := []struct{ user, ownPolicy, foreignPolicy, ownStep, foreignStep string }{
		{"user-a", "policy-a", "policy-b", "step-a1", "step-b1"},
		{"user-other", "policy-b", "policy-a", "step-b1", "step-a1"},
		// The existing legacy Admin is an admitted Org A human, not PlatformAdmin.
		{harness.DefaultGraphQLAdminUserID, "policy-a", "policy-b", "step-a1", "step-b1"},
	}
	userID := func(name string) string {
		if name == harness.DefaultGraphQLAdminUserID {
			return name
		}
		return h.UUID(name)
	}
	query := func(t *testing.T, actor, text string) *stepOrganizationResponse {
		t.Helper()
		return stepOrganizationPost(t, h, map[string]any{"query": text}, h.GraphQLToken(userID(actor)), false)
	}
	read := func(t *testing.T, actor, policy, step string, enabled bool) {
		t.Helper()
		response := query(t, actor, fmt.Sprintf(`{escalationPolicy(id:%q){steps{id multiAck}}}`, h.UUID(policy)))
		require.Empty(t, response.Errors)
		var data struct {
			EscalationPolicy struct {
				Steps []struct {
					ID       string
					MultiAck bool
				}
			}
		}
		require.NoError(t, json.Unmarshal(response.Data, &data))
		for _, s := range data.EscalationPolicy.Steps {
			if s.ID == step {
				require.Equal(t, enabled, s.MultiAck)
				return
			}
		}
		t.Fatal("authorized Step missing from parent materialization")
	}
	for _, actor := range actors {
		t.Run(actor.user+" own policy", func(t *testing.T) {
			for _, field := range []string{"", "multiAck:false", "multiAck:true"} {
				response := query(t, actor.user, fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:60,%s}){id multiAck}}`, h.UUID(actor.ownPolicy), field))
				id := stepOrganizationCreateID(t, response)
				var enabled bool
				var parent string
				require.NoError(t, db.QueryRow(`SELECT multi_ack, escalation_policy_id FROM escalation_policy_steps WHERE id = $1`, id).Scan(&enabled, &parent))
				require.Equal(t, h.UUID(actor.ownPolicy), parent)
				require.Equal(t, field == "multiAck:true", enabled)
				var created struct{ CreateEscalationPolicyStep struct{ MultiAck bool } }
				require.NoError(t, json.Unmarshal(response.Data, &created))
				require.Equal(t, enabled, created.CreateEscalationPolicyStep.MultiAck)
				read(t, actor.user, actor.ownPolicy, id, enabled)
			}
			for _, enabled := range []bool{true, false} {
				response := query(t, actor.user, fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,multiAck:%t})}`, h.UUID(actor.ownStep), enabled))
				require.Empty(t, response.Errors)
				read(t, actor.user, actor.ownPolicy, h.UUID(actor.ownStep), enabled)
				// An omitted update must leave the boolean exactly as stored.
				response = query(t, actor.user, fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:8})}`, h.UUID(actor.ownStep)))
				require.Empty(t, response.Errors)
				read(t, actor.user, actor.ownPolicy, h.UUID(actor.ownStep), enabled)
			}
		})
	}
	// Current accepted EP administration includes same-Organization legacy
	// 'user' + ORG_MEMBER; MultiAck must not invent an ORG_ADMIN-only gate.
	_, err = db.Exec(`UPDATE user_organization_assignments SET organization_role = 'ORG_MEMBER' WHERE user_id = $1`, h.UUID("user-a"))
	require.NoError(t, err)
	require.Empty(t, query(t, "user-a", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,multiAck:true})}`, h.UUID("step-a1"))).Errors)
	read(t, "user-a", "policy-a", h.UUID("step-a1"), true)

	for _, side := range []string{"a", "b"} {
		org := harness.SmokeOrganizationID
		if side == "b" {
			org = h.UUID("org-b")
		}
		_, err = db.Exec(`INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,$3,$4)`, h.UUID("svc-"+side), org, "MultiAck service "+side, h.UUID("policy-"+side))
		require.NoError(t, err)
		id := 201
		if side == "b" {
			id = 202
		}
		_, err = db.Exec(`INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES($1,$2,'MultiAck denial sentinel',$3)`, id, h.UUID("svc-"+side), "auto:c8:"+side)
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO notification_policy_cycles(alert_id,user_id,multi_ack) VALUES($1,$2,true)`, id, h.UUID("user-a"))
		require.NoError(t, err)
		// Intentionally seed cross-Org on-call membership to test the accepted
		// materialization filter, without depending on User affiliation rules.
		for _, actor := range actors {
			_, err = db.Exec(`INSERT INTO ep_step_on_call_users(user_id,ep_step_id,start_time)
				SELECT $1,$2,now() WHERE NOT EXISTS(SELECT FROM ep_step_on_call_users WHERE user_id=$1 AND ep_step_id=$2 AND end_time IS NULL)`, userID(actor.user), h.UUID("step-"+side+"1"))
			require.NoError(t, err)
		}
	}
	// Test-only BEFORE triggers detect any attempted DML, including statements
	// later rolled back. Foreign denial must report the authorization error and
	// never reach these sentinels. They add no production schema/migration.
	_, err = db.Exec(`CREATE FUNCTION c8_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'C8 unexpected mutation of %', TG_TABLE_NAME; END $$`)
	require.NoError(t, err)
	for table := range multiAckOrganizationSnapshot(t, h) {
		_, err = db.Exec(`CREATE TRIGGER c8_dml_guard BEFORE INSERT OR UPDATE OR DELETE ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION c8_reject_mutation()`)
		require.NoError(t, err)
	}
	for _, actor := range actors {
		t.Run(actor.user+" foreign UUID denial", func(t *testing.T) {
			before := multiAckOrganizationSnapshot(t, h)
			// Holding the foreign Step must not block source authorization.
			lock, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer lock.Rollback()
			_, err = lock.Exec(`SELECT id FROM escalation_policy_steps WHERE id=$1 FOR UPDATE`, h.UUID(actor.foreignStep))
			require.NoError(t, err)
			for _, enabled := range []bool{true, false} {
				response := query(t, actor.user, fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,multiAck:%t,delayMinutes:17,actions:[]})}`, h.UUID(actor.foreignStep), enabled))
				stepOrganizationUnavailable(t, response, "updateEscalationPolicyStep", "EscalationPolicyStepID")
				require.Equal(t, before, multiAckOrganizationSnapshot(t, h))
			}
			for _, child := range []string{"", `newSchedule:{name:"C8 denied schedule",timeZone:"Etc/UTC"}`} {
				response := query(t, actor.user, fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:60,multiAck:true,%s}){id}}`, h.UUID(actor.foreignPolicy), child))
				stepOrganizationUnavailable(t, response, "createEscalationPolicyStep", "EscalationPolicyID")
				require.Equal(t, before, multiAckOrganizationSnapshot(t, h))
			}
			response := query(t, actor.user, fmt.Sprintf(`{escalationPolicy(id:%q){steps{id multiAck}}}`, h.UUID(actor.foreignPolicy)))
			require.Empty(t, response.Errors)
			require.JSONEq(t, `{"escalationPolicy":null}`, string(response.Data), "foreign Policy cannot materialize a Step or its MultiAck configuration")
			require.NotContains(t, string(response.Data), h.UUID(actor.foreignStep))
			response = query(t, actor.user, fmt.Sprintf(`{user(id:%q){onCallSteps{id multiAck}}}`, userID(actor.user)))
			require.Empty(t, response.Errors)
			require.Contains(t, string(response.Data), h.UUID(actor.ownStep))
			require.NotContains(t, string(response.Data), h.UUID(actor.foreignStep))
			require.Equal(t, before, multiAckOrganizationSnapshot(t, h))
		})
	}
	// No fixture auto-assignment: these humans are created after initialization.
	for _, name := range []string{"missing", "default"} {
		_, err = db.Exec(`INSERT INTO users(id,name,email,role) VALUES($1,$2,'','user')`, h.UUID(name), name)
		require.NoError(t, err)
		if name == "default" {
			_, err = db.Exec(`INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
				VALUES($1,$2,'DEFAULT',NULL,'NONE','ZERO',now(),'c8-test',0)`, h.UUID(name), organization.DefaultOrganizationID)
			require.NoError(t, err)
		}
		before := multiAckOrganizationSnapshot(t, h)
		for _, text := range []string{
			fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:60,multiAck:true}){id}}`, h.UUID("policy-a")),
			fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,multiAck:true})}`, h.UUID("step-a1")),
		} {
			response := query(t, name, text)
			require.NotEmpty(t, response.Errors)
			require.Contains(t, response.Errors[0].Message, "normal Organization scoped authority is required")
			require.Equal(t, before, multiAckOrganizationSnapshot(t, h))
		}
	}
	for table := range multiAckOrganizationSnapshot(t, h) {
		_, err = db.Exec(`DROP TRIGGER c8_dml_guard ON ` + table)
		require.NoError(t, err)
	}
	_, err = db.Exec(`DELETE FROM notification_policy_cycles; DELETE FROM alerts`)
	require.NoError(t, err)
}
