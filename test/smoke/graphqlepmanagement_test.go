package smoke

// EP-B1 signed-session HTTP tests with persisted PostgreSQL assertions.
// Adapted from the accepted EP-A0 probe; historical evidence remains immutable.
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/engine/escalationmanager"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

const epB1SQL = stepActionOrganizationSQL + `
INSERT INTO users(id,name,email,role) VALUES({{uuid "user-home"}},'Synthetic Home Responder','','user');
INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
VALUES({{uuid "user-home"}},{{smokeOrganizationID}},'NORMAL',{{smokeOrganizationID}},'ORG_MEMBER','EXACTLY_ONE',now(),'ep-b1-test',1);
INSERT INTO services(id,organization_id,escalation_policy_id,name)
VALUES({{uuid "service-a"}},{{smokeOrganizationID}},{{uuid "policy-a"}},'Synthetic Linked Service');
`

func epB1Save(t *testing.T, name string, value any) {
	t.Helper()
	if os.Getenv("EP_B1_EVIDENCE") == "" {
		return
	}
	b, e := json.MarshalIndent(value, "", "  ")
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("EP_B1_EVIDENCE"), name+".json"), append(b, byte(10)), 0600))
}
func epB1Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, epB1SQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	h.GraphQLToken(h.UUID("user-a"))
	epB1Save(t, strings.ReplaceAll(t.Name(), "/", "_")+"-origin", map[string]any{"database": epB1Scalar(t, h, "SELECT current_database()"), "server_version": epB1Scalar(t, h, "SHOW server_version")})
	return h
}
func epB1Scalar(t *testing.T, h *harness.Harness, q string, args ...any) string {
	t.Helper()
	var s string
	require.NoError(t, h.App().DB().QueryRow(q, args...).Scan(&s))
	return s
}
func epB1Snapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	r := map[string]string{}
	for _, table := range []string{"escalation_policies", "escalation_policy_steps", "escalation_policy_actions", "schedules", "schedule_rules", "rotations", "rotation_participants", "rotation_state", "user_favorites", "services", "alerts", "alert_data", "alert_logs", "escalation_policy_state", "notification_policy_cycles", "ep_step_on_call_users", "outgoing_messages", "notification_channels", "labels", "user_contact_methods", "user_notification_rules"} {
		r[table] = epB1Scalar(t, h, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM "+table+" r")
	}
	r["authority"] = epB1Scalar(t, h, `SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb)::text FROM (SELECT u.id,u.role,a.effective_organization_id,a.organization_role,a.mapping_outcome FROM users u LEFT JOIN user_organization_assignments a ON a.user_id=u.id ORDER BY u.id) r`)
	return r
}
func epB1Call(t *testing.T, h *harness.Harness, name, query, token string, noRows bool) *stepOrganizationResponse {
	t.Helper()
	before := epB1Snapshot(t, h)
	body, e := json.Marshal(map[string]any{"query": query})
	require.NoError(t, e)
	req, e := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, e)
	req.Header.Set("Content-Type", "application/json")
	if token == "" {
		token = h.GraphQLToken(h.UUID("user-a"))
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	var wait func()
	if noRows {
		wait = h.ExpectBackendError("sql: no rows in result set")
	}
	resp, e := http.DefaultClient.Do(req)
	require.NoError(t, e)
	defer resp.Body.Close()
	raw, e := io.ReadAll(resp.Body)
	require.NoError(t, e)
	if wait != nil {
		wait()
	}
	after := epB1Snapshot(t, h)
	epB1Save(t, strings.ReplaceAll(t.Name(), "/", "_")+"-"+name, map[string]any{"method": "POST", "path": "/api/graphql", "authentication": "actual signed Human session cookie; token omitted", "request": json.RawMessage(body), "status": resp.StatusCode, "response": json.RawMessage(raw), "before": before, "after": after, "durable_state_changed": fmt.Sprint(before) != fmt.Sprint(after)})
	require.Equal(t, 200, resp.StatusCode)
	var out stepOrganizationResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	return &out
}
func epB1Exec(t *testing.T, h *harness.Harness, q string, args ...any) {
	t.Helper()
	_, e := h.App().DB().Exec(q, args...)
	require.NoError(t, e)
}
func epB1Delete(h *harness.Harness, ids ...string) string {
	var v []string
	for _, id := range ids {
		v = append(v, fmt.Sprintf("{type:escalationPolicy,id:%q}", h.UUID(id)))
	}
	return "mutation{deleteAll(input:[" + strings.Join(v, ",") + "])}"
}
func epB1Count(t *testing.T, h *harness.Harness, table, id string) string {
	return epB1Scalar(t, h, "SELECT count(*)::text FROM "+table+" WHERE id=$1", id)
}
func TestEPB1Roles(t *testing.T) {
	t.Parallel()
	for _, a := range []struct {
		name, role string
		pa         bool
	}{{"OrgMember", "ORG_MEMBER", false}, {"OrgAdmin", "ORG_ADMIN", false}, {"PlatformAdminMember", "ORG_MEMBER", true}, {"PlatformAdminAdmin", "ORG_ADMIN", true}} {
		t.Run(a.name, func(t *testing.T) {
			t.Parallel()
			h := epB1Harness(t)
			ikSetAuthority(t, h, a.role, a.pa)
			if !a.pa && a.role == "ORG_MEMBER" {
				for i, q := range epB1ManagementQueries(h) {
					before := epB1Snapshot(t, h)
					response := epB1Call(t, h, fmt.Sprintf("member_denial_%d", i), q, "", false)
					require.NotEmpty(t, response.Errors)
					require.Equal(t, before, epB1Snapshot(t, h))
				}
				// Personal favorite self-service remains a Member operation.
				response := epB1Call(t, h, "member_personal_favorite", fmt.Sprintf(`mutation{setFavorite(input:{target:{type:escalationPolicy,id:%q},favorite:true})}`, h.UUID("policy-a")), "", false)
				require.Empty(t, response.Errors)
				return
			}

			q := fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"Synthetic Modified EP",description:"Modified by role probe",repeat:5})}`, h.UUID("policy-a"))
			r := epB1Call(t, h, "home_ep_update", q, "", false)
			require.Empty(t, r.Errors)
			require.Equal(t, "Synthetic Modified EP", epB1Scalar(t, h, "SELECT name FROM escalation_policies WHERE id=$1", h.UUID("policy-a")))
			r = epB1Call(t, h, "home_ep_create", `mutation{createEscalationPolicy(input:{name:"Synthetic Created EP",favorite:true,steps:[{delayMinutes:2}]}){id}}`, "", false)
			require.Empty(t, r.Errors)
			r = epB1Call(t, h, "home_step_create", fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:6}){id}}`, h.UUID("policy-a")), "", false)
			require.Empty(t, r.Errors)
			q = fmt.Sprintf(`mutation{changed:updateEscalationPolicyStep(input:{id:%q,delayMinutes:17,multiAck:true,actions:[{type:"builtin-user",args:{user_id:%q}}]})}`, h.UUID("step-a1"), h.UUID("user-home"))
			r = epB1Call(t, h, "home_step_delay_multiack_action", q, "", false)
			require.Empty(t, r.Errors)
			require.Equal(t, "17", epB1Scalar(t, h, "SELECT delay::text FROM escalation_policy_steps WHERE id=$1", h.UUID("step-a1")))
			require.Equal(t, "true", epB1Scalar(t, h, "SELECT multi_ack::text FROM escalation_policy_steps WHERE id=$1", h.UUID("step-a1")))
			require.Equal(t, []string{"user:" + h.UUID("user-home")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
			q = fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,stepIDs:[%q,%q]})}`, h.UUID("policy-a"), h.UUID("step-a2"), h.UUID("step-a1"))
			r = epB1Call(t, h, "home_step_reorder_removal", q, "", false)
			require.Empty(t, r.Errors)
			require.Equal(t, "0", epB1Count(t, h, "escalation_policy_steps", h.UUID("step-a3")))
			require.Equal(t, "0", epB1Scalar(t, h, "SELECT step_number::text FROM escalation_policy_steps WHERE id=$1", h.UUID("step-a2")))
			r = epB1Call(t, h, "foreign_ep_update", fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,description:"Forbidden foreign"})}`, h.UUID("policy-b")), "", true)
			require.NotEmpty(t, r.Errors)
			r = epB1Call(t, h, "foreign_step_update", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:18})}`, h.UUID("step-b1")), "", false)
			require.NotEmpty(t, r.Errors)
			r = epB1Call(t, h, "foreign_step_create", fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:18}){id}}`, h.UUID("policy-b")), "", false)
			require.NotEmpty(t, r.Errors)
			r = epB1Call(t, h, "foreign_ep_delete", epB1Delete(h, "policy-b"), "", true)
			require.NotEmpty(t, r.Errors)
			epB1Exec(t, h, "INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'Synthetic Deletable EP')", h.UUID("delete-policy"), harness.SmokeOrganizationID)
			epB1Exec(t, h, "INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay,step_number) VALUES($1,$2,1,0)", h.UUID("delete-step"), h.UUID("delete-policy"))
			epB1Exec(t, h, "INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)", h.UUID("delete-step"), h.UUID("user-a"))
			r = epB1Call(t, h, "home_ep_delete", epB1Delete(h, "delete-policy"), "", false)
			require.Empty(t, r.Errors)
			require.Equal(t, "0", epB1Count(t, h, "escalation_policies", h.UUID("delete-policy")))
			require.Equal(t, "0", epB1Count(t, h, "escalation_policy_steps", h.UUID("delete-step")))
			require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1", h.UUID("delete-step")))
		})
	}
}
func TestEPB1NestedAndDestinations(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	cases := []struct {
		name, q string
		allow   bool
	}{
		{"standalone_nested_ep", `mutation{createEscalationPolicy(input:{name:"Member Nested EP",favorite:true,steps:[{delayMinutes:2,newSchedule:{name:"Member Nested Schedule",timeZone:"Etc/UTC",favorite:true}},{delayMinutes:3,newRotation:{name:"Member Nested Rotation",type:daily,timeZone:"Etc/UTC",start:"2026-10-31T00:00:00Z",favorite:true}}]}){...Identity}} fragment Identity on EscalationPolicy{id}`, true},
		{"service_parent_authorized", `mutation{createService(input:{name:"Denied Nested Service",newEscalationPolicy:{name:"Denied Nested EP",steps:[{delayMinutes:2}]}}){id}}`, true},
		{"later_nested_error", fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"Rollback Nested EP",favorite:true,steps:[{delayMinutes:2,newSchedule:{name:"Rollback Nested Schedule",timeZone:"Etc/UTC",favorite:true}},{delayMinutes:3,actions:[%s]}]}){id}}`, stepActionOrganizationTarget("rotation", h.UUID("rotation-b"))), false},
		{"later_invalid_step_rollback", `mutation{createEscalationPolicy(input:{name:"Rollback after write",favorite:true,steps:[{delayMinutes:2,newSchedule:{name:"Rollback Written Schedule",timeZone:"Etc/UTC",favorite:true}},{delayMinutes:0,actions:[]}]}){id}}`, false},
		{"disabled_labels", `mutation{createEscalationPolicy(input:{name:"Disabled Labels",labels:[{key:"synthetic",value:"probe"}]}){id}}`, false},
		{"set_label_disabled", fmt.Sprintf(`mutation{setLabel(input:{target:{type:escalationPolicy,id:%q},key:"synthetic",value:"probe"})}`, h.UUID("policy-a")), false},
		{"direct_nested_schedule", fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:4,newSchedule:{name:"Member Direct Nested Schedule",timeZone:"Etc/UTC"}}){id}}`, h.UUID("policy-a")), true},
		{"direct_nested_rotation", fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:4,newRotation:{name:"Member Direct Nested Rotation",type:daily,timeZone:"Etc/UTC",start:"2026-10-31T00:00:00Z"}}){id}}`, h.UUID("policy-a")), true},
		{"same_org_schedule_replace", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("schedule", h.UUID("schedule-a"))), true},
		{"same_org_schedule_rereplace", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("schedule", h.UUID("schedule-a2"))), true},
		{"same_org_rotation_replace", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("rotation", h.UUID("rotation-a"))), true},
		{"foreign_schedule_rollback", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:18,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("schedule", h.UUID("schedule-b"))), false},
		{"foreign_rotation_rollback", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:18,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("rotation", h.UUID("rotation-b"))), false},
		{"foreign_user_action", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("user", h.UUID("user-other"))), false},
		{"legacy_targets", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,targets:[{type:user,id:%q}]})}`, h.UUID("step-a1"), h.UUID("user-home")), true},
		{"remove_all_actions", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[]})}`, h.UUID("step-a1")), true},
		{"personal_favorite", fmt.Sprintf(`mutation{setFavorite(input:{target:{type:escalationPolicy,id:%q},favorite:true})}`, h.UUID("policy-a")), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := epB1Snapshot(t, h)
			r := epB1Call(t, h, c.name, c.q, "", false)
			if c.allow {
				require.Empty(t, r.Errors)
				require.NotEqual(t, before, epB1Snapshot(t, h))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, epB1Snapshot(t, h))
			}
		})
	}
}
func TestEPB1Admission(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	token := h.GraphQLToken(h.UUID("user-a"))
	q := fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:31})}`, h.UUID("step-a1"))
	r := epB1Call(t, h, "before_downgrade", q, token, false)
	require.Empty(t, r.Errors)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	q = fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:32})}`, h.UUID("step-a1"))
	r = epB1Call(t, h, "fresh_request_after_downgrade", q, token, false)
	require.NotEmpty(t, r.Errors)
	require.Equal(t, "31", epB1Scalar(t, h, "SELECT delay::text FROM escalation_policy_steps WHERE id=$1", h.UUID("step-a1")))
	// Keep the same signed session; remove current PG authority, then move to Default.
	old := epB1Scalar(t, h, "SELECT row_to_json(a)::text FROM user_organization_assignments a WHERE user_id=$1", h.UUID("user-a"))
	epB1Save(t, "admission_assignment", old)
	epB1Exec(t, h, "DELETE FROM user_organization_assignments WHERE user_id=$1", h.UUID("user-a"))
	queries := []string{q, `mutation{createEscalationPolicy(input:{name:"Missing Home"}){id}}`, fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,description:"missing"})}`, h.UUID("policy-a")), fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:3}){id}}`, h.UUID("policy-a")), epB1Delete(h, "policy-b")}
	for i, q := range queries {
		before := epB1Snapshot(t, h)
		r = epB1Call(t, h, fmt.Sprintf("missing_home_%d", i), q, token, false)
		require.NotEmpty(t, r.Errors)
		require.Equal(t, before, epB1Snapshot(t, h))
	}
	// Restore the exact assignment via JSON record, then use the accepted Default shape.
	epB1Exec(t, h, "INSERT INTO user_organization_assignments SELECT * FROM json_populate_record(NULL::user_organization_assignments,$1::json)", old)
	epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
	for i, q := range queries {
		before := epB1Snapshot(t, h)
		r = epB1Call(t, h, fmt.Sprintf("restricted_default_%d", i), q, token, false)
		require.NotEmpty(t, r.Errors)
		require.Equal(t, before, epB1Snapshot(t, h))
	}
}
func TestEPB1DeleteTransactions(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"member_ep_only", "linked_service_fk", "member_ep_service", "admin_service_ep", "mixed_rotation_schedule_ep", "missing", "duplicate", "over50", "earlier_rotation_failure", "later_ep_failure", "missing_cm_is_noop", "later_foreign_cm_failure", "earlier_schedule_failure", "mixed_home_foreign", "positive_cm_nr"} {
		t.Run(c, func(t *testing.T) {
			t.Parallel()
			h := epB1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", false)
			q := ""
			noRows := false
			allow := false
			epB1Exec(t, h, "INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'Synthetic Delete EP')", h.UUID("delete-policy"), harness.SmokeOrganizationID)
			switch c {
			case "member_ep_only":
				ikSetAuthority(t, h, "ORG_MEMBER", false)
				q = epB1Delete(h, "delete-policy")
			case "linked_service_fk":
				q = epB1Delete(h, "policy-a")
			case "member_ep_service":
				ikSetAuthority(t, h, "ORG_MEMBER", false)
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("service-a"), h.UUID("policy-a"))
			case "admin_service_ep":
				ikSetAuthority(t, h, "ORG_ADMIN", false)
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("service-a"), h.UUID("policy-a"))
				allow = true
			case "mixed_rotation_schedule_ep":
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:schedule,id:%q},{type:rotation,id:%q}])}`, h.UUID("delete-policy"), h.UUID("schedule-a"), h.UUID("rotation-a"))
				allow = true
			case "missing":
				q = epB1Delete(h, "delete-policy", "missing")
				noRows = true
			case "duplicate":
				q = epB1Delete(h, "delete-policy", "delete-policy")
				allow = true
			case "over50":
				var ids []string
				for i := 0; i < 51; i++ {
					ids = append(ids, fmt.Sprintf("many-%d", i))
				}
				q = epB1Delete(h, ids...)
			case "earlier_rotation_failure":
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:rotation,id:%q}])}`, h.UUID("delete-policy"), h.UUID("rotation-b"))
				noRows = true
			case "later_ep_failure":
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:rotation,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("rotation-a"), h.UUID("missing"))
				noRows = true
			case "missing_cm_is_noop":
				allow = true
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:contactMethod,id:%q}])}`, h.UUID("delete-policy"), h.UUID("missing-cm"))
			case "later_foreign_cm_failure":
				epB1Exec(t, h, "INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$2,'Foreign Synthetic CM','SMS','+12015550102')", h.UUID("foreign-cm"), h.UUID("user-other"))
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:contactMethod,id:%q}])}`, h.UUID("delete-policy"), h.UUID("foreign-cm"))
			case "earlier_schedule_failure":
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:escalationPolicy,id:%q},{type:schedule,id:%q}])}`, h.UUID("delete-policy"), h.UUID("schedule-b"))
				noRows = true
			case "mixed_home_foreign":
				q = epB1Delete(h, "delete-policy", "policy-b")
				noRows = true
			case "positive_cm_nr":
				epB1Exec(t, h, "INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$2,'Synthetic CM','SMS','+12015550101')", h.UUID("cm"), h.UUID("user-a"))
				epB1Exec(t, h, "INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)", h.UUID("nr"), h.UUID("user-a"), h.UUID("cm"))
				q = fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("cm"), h.UUID("nr"), h.UUID("delete-policy"))
				allow = true
			}
			before := epB1Snapshot(t, h)
			r := epB1Call(t, h, c, q, "", noRows)
			if allow {
				require.Empty(t, r.Errors)
				require.NotEqual(t, before, epB1Snapshot(t, h))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, epB1Snapshot(t, h))
			}
		})
	}
}
func TestEPB1Catalog(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	queries := map[string]string{
		"constraints": `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY child,name),'[]'::jsonb)::text FROM (SELECT c.conname name,c.conrelid::regclass::text child,c.confrelid::regclass::text parent,c.contype::text type,c.confdeltype::text delete_action,c.condeferrable,c.condeferred,pg_get_constraintdef(c.oid) definition FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public')r`,
		"triggers":    `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY relation,name),'[]'::jsonb)::text FROM (SELECT t.tgname name,t.tgrelid::regclass::text relation,pg_get_triggerdef(t.oid) definition,pg_get_functiondef(t.tgfoid) function FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal AND n.nspname='public')r`,
	}
	for name, q := range queries {
		epB1Save(t, "pg-"+name, json.RawMessage(epB1Scalar(t, h, q)))
	}
	epB1Save(t, "catalog-origin", map[string]any{"database": epB1Scalar(t, h, "SELECT current_database()"), "server_version": epB1Scalar(t, h, "SHOW server_version"), "engine": "paused before all mutation probes", "transport": "Unix socket; PostgreSQL has no TCP listener", "providers": "no external provider invocation"})

}

func TestEPB1EngineRouting(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	epB1Exec(t, h, "DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id=$1", h.UUID("step-a1"))
	epB1Exec(t, h, "INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)", h.UUID("step-a1"), h.UUID("user-a"))
	db, e := escalationmanager.NewDB(context.Background(), h.App().DB(), h.App().AlertLogStore)
	require.NoError(t, e)
	system := permission.SystemContext(context.Background(), "Engine")
	before := epB1Snapshot(t, h)
	epB1Exec(t, h, "INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic before change','ep-b1-before')", h.UUID("service-a"))
	require.NoError(t, db.UpdateAll(system))
	baseline := epB1Snapshot(t, h)
	require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM notification_policy_cycles WHERE user_id=$1", h.UUID("user-a")))
	r := epB1Call(t, h, "member_action_redirect", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[{type:"builtin-user",args:{user_id:%q}}]})}`, h.UUID("step-a1"), h.UUID("user-home")), "", false)
	require.NotEmpty(t, r.Errors)
	epB1Exec(t, h, "INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic after change','ep-b1-after')", h.UUID("service-a"))
	require.NoError(t, db.UpdateAll(system))
	after := epB1Snapshot(t, h)
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM notification_policy_cycles WHERE user_id=$1", h.UUID("user-home")))
	require.Equal(t, "2", epB1Scalar(t, h, "SELECT count(*)::text FROM notification_policy_cycles WHERE user_id=$1", h.UUID("user-a")))
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	r = epB1Call(t, h, "admin_action_replace", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[{type:"builtin-user",args:{user_id:%q}}]})}`, h.UUID("step-a1"), h.UUID("user-home")), "", false)
	require.Empty(t, r.Errors)
	epB1Exec(t, h, "INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic authorized change','ep-b1-admin')", h.UUID("service-a"))
	require.NoError(t, db.UpdateAll(system))
	require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM notification_policy_cycles WHERE user_id=$1", h.UUID("user-home")))
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM outgoing_messages"))
	epB1Save(t, "engine-routing-effect", map[string]any{"before": before, "baseline_engine": baseline, "after_denied_member_and_engine": after, "module": "only escalationmanager.UpdateAll(System); overall Engine remains paused", "routing_effect": "Member denial preserves original routing; authorized OrgAdmin replacement changes subsequent routing", "external_delivery": "NOT RUN; no provider sending module invoked"})
}
func TestEPB1SupplementalBoundaries(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, c := range []struct{ name, q string }{
		{"admin_foreign_user_create", fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,actions:[%s]}){id}}`, h.UUID("policy-a"), stepActionOrganizationTarget("user", h.UUID("user-other")))},
		{"admin_foreign_user_legacy_update", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,targets:[{type:user,id:%q}]})}`, h.UUID("step-a1"), h.UUID("user-other"))},
		{"admin_foreign_user_nested", fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"Admin Foreign User Nested",steps:[{delayMinutes:3,actions:[%s]}]}){id}}`, stepActionOrganizationTarget("user", h.UUID("user-other")))},
	} {
		r := epB1Call(t, h, c.name, c.q, "", false)
		require.NotEmpty(t, r.Errors)
	}
	token := h.GraphQLToken(h.UUID("user-a"))
	assignment := epB1Scalar(t, h, "SELECT row_to_json(a)::text FROM user_organization_assignments a WHERE user_id=$1", h.UUID("user-a"))
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	epB1Exec(t, h, "DELETE FROM user_organization_assignments WHERE user_id=$1", h.UUID("user-a"))
	q := fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:88})}`, h.UUID("step-a1"))
	before := epB1Snapshot(t, h)
	r := epB1Call(t, h, "pa_missing_home", q, token, false)
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, epB1Snapshot(t, h))
	epB1Exec(t, h, "INSERT INTO user_organization_assignments SELECT * FROM json_populate_record(NULL::user_organization_assignments,$1::json)", assignment)
	epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
	before = epB1Snapshot(t, h)
	r = epB1Call(t, h, "pa_restricted_default", q, token, false)
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, epB1Snapshot(t, h))
}
func TestEPB1PopulatedDelete(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	epB1Exec(t, h, "INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic retained alert','ep-b1-retained')", h.UUID("service-a"))
	epB1Exec(t, h, "INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'Unlinked populated EP')", h.UUID("pop-policy"), harness.SmokeOrganizationID)
	epB1Exec(t, h, "INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay,step_number) VALUES($1,$2,2,0)", h.UUID("pop-step"), h.UUID("pop-policy"))
	epB1Exec(t, h, "INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)", h.UUID("pop-step"), h.UUID("user-a"))
	epB1Exec(t, h, "INSERT INTO ep_step_on_call_users(ep_step_id,user_id) VALUES($1,$2)", h.UUID("pop-step"), h.UUID("user-a"))
	epB1Exec(t, h, "INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)", h.UUID("user-a"), h.UUID("pop-policy"))
	before := epB1Snapshot(t, h)
	r := epB1Call(t, h, "member_populated_ep_delete", epB1Delete(h, "pop-policy"), "", false)
	require.Empty(t, r.Errors)
	after := epB1Snapshot(t, h)
	for _, table := range []string{"services", "alerts", "alert_data", "alert_logs", "escalation_policy_state", "notification_policy_cycles", "outgoing_messages"} {
		require.Equal(t, before[table], after[table], table)
	}
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM ep_step_on_call_users WHERE ep_step_id=$1", h.UUID("pop-step")))
	r = epB1Call(t, h, "linked_ep_with_alert_blocked", epB1Delete(h, "policy-a"), "", false)
	require.NotEmpty(t, r.Errors)
	require.Equal(t, after, epB1Snapshot(t, h))
}
func TestEPB1FailedReorderSideEffects(t *testing.T) {
	t.Parallel()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	epB1Exec(t, h, "INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic rollback log check','ep-b1-rollback')", h.UUID("service-a"))
	before := epB1Snapshot(t, h)
	q := fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,description:"Must Roll Back",stepIDs:[%q,%q]})}`, h.UUID("policy-a"), h.UUID("step-a1"), h.UUID("step-b1"))
	r := epB1Call(t, h, "invalid_step_ids_after_policy_update", q, "", false)
	require.NotEmpty(t, r.Errors)
	after := epB1Snapshot(t, h)
	for _, table := range []string{"escalation_policies", "escalation_policy_steps", "escalation_policy_actions"} {
		require.Equal(t, before[table], after[table])
	}
	require.Equal(t, before["alert_logs"], after["alert_logs"], "F05: rejected EP updates must roll back related Alert Log entries")
	epB1Save(t, "reorder-rollback-log-observation", map[string]any{"before": before, "after": after, "alert_log_changed": before["alert_logs"] != after["alert_logs"], "configuration_rollback": true})
}

func epB1ManagementQueries(h *harness.Harness) []string {
	return []string{
		`mutation{createEscalationPolicy(input:{name:"Member forbidden",favorite:true,steps:[{delayMinutes:2,newSchedule:{name:"Nested forbidden",timeZone:"Etc/UTC",favorite:true}},{delayMinutes:3,newRotation:{name:"Nested forbidden rotation",type:daily,timeZone:"Etc/UTC",start:"2026-10-31T00:00:00Z",favorite:true}}]}){id}}`,
		`mutation{createService(input:{name:"Member forbidden service",newEscalationPolicy:{name:"Nested forbidden",steps:[{delayMinutes:2}]}}){id}}`,
		fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"Forbidden",description:"Forbidden",repeat:4,stepIDs:[%q]})}`, h.UUID("policy-a"), h.UUID("step-a2")),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,actions:[%s]}){id}}`, h.UUID("policy-a"), stepActionOrganizationTarget("user", h.UUID("user-home"))),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,newSchedule:{name:"Forbidden nested schedule",timeZone:"Etc/UTC"}}){id}}`, h.UUID("policy-a")),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,newRotation:{name:"Forbidden nested rotation",type:daily,timeZone:"Etc/UTC",start:"2026-10-31T00:00:00Z"}}){id}}`, h.UUID("policy-a")),
		fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:19,multiAck:true,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("user", h.UUID("user-home"))),
		fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[]})}`, h.UUID("step-a1")),
		fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,targets:[{type:schedule,id:%q}]})}`, h.UUID("step-a1"), h.UUID("schedule-a")),
		fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,repeat:8})}`, h.UUID("policy-b")),
		fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:20})}`, h.UUID("step-b1")),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2}){id}}`, h.UUID("policy-b")),
		epB1Delete(h, "policy-a"), epB1Delete(h, "policy-b"),
	}
}

func TestEPB1UserRelationships(t *testing.T) {
	t.Parallel()
	for _, actor := range []struct {
		name, role string
		pa         bool
	}{{"OrgAdmin", "ORG_ADMIN", false}, {"PlatformAdminMember", "ORG_MEMBER", true}, {"PlatformAdminAdmin", "ORG_ADMIN", true}} {
		t.Run(actor.name, func(t *testing.T) {
			t.Parallel()
			h := epB1Harness(t)
			ikSetAuthority(t, h, actor.role, actor.pa)
			// Missing assignment and restricted Default are persisted User states.
			epB1Exec(t, h, `INSERT INTO users(id,name,email,role) VALUES($1,'Unassigned synthetic','','user'),($2,'Restricted synthetic','','user')`, h.UUID("unassigned"), h.UUID("restricted"))
			epB1Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,(SELECT id FROM organizations WHERE classification='DEFAULT'),'DEFAULT','NONE','MULTIPLE',now(),'ep-b1-test',2)`, h.UUID("restricted"))
			// Global target role does not make a foreign relationship valid.
			epB1Exec(t, h, `UPDATE users SET role='admin' WHERE id=$1`, h.UUID("user-other"))
			for _, target := range []string{"user-home", "user-other", "missing-user", "unassigned", "restricted"} {
				for _, entry := range []string{"create", "update", "nested", "legacy-create", "legacy-update"} {
					t.Run(target+"/"+entry, func(t *testing.T) {
						action := stepActionOrganizationTarget("user", h.UUID(target))
						field := "actions:[" + action + "]"
						if strings.HasPrefix(entry, "legacy") {
							field = fmt.Sprintf(`targets:[{type:user,id:%q}]`, h.UUID(target))
						}
						var q string
						switch entry {
						case "create", "legacy-create":
							q = fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:4,%s}){id}}`, h.UUID("policy-a"), field)
						case "update", "legacy-update":
							q = fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:11,%s})}`, h.UUID("step-a1"), field)
						case "nested":
							q = fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"Relationship candidate",favorite:true,steps:[{delayMinutes:3,newSchedule:{name:"Rollback relationship schedule",timeZone:"Etc/UTC",favorite:true}},{delayMinutes:4,%s}]}){id}}`, field)
						}
						before := epB1Snapshot(t, h)
						response := epB1Call(t, h, target+"-"+entry, q, "", false)
						if target == "user-home" {
							require.Empty(t, response.Errors)
							switch entry {
							case "update", "legacy-update":
								// Repeating the same final list may be idempotent.
								require.Equal(t, []string{"user:" + h.UUID(target)}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
							case "create", "legacy-create":
								id := stepOrganizationCreateID(t, response)
								require.Equal(t, []string{"user:" + h.UUID(target)}, stepActionOrganizationRows(t, h, id))
							case "nested":
								var data struct{ CreateEscalationPolicy struct{ ID string } }
								require.NoError(t, json.Unmarshal(response.Data, &data))
								require.Equal(t, "1", epB1Scalar(t, h, `SELECT count(*)::text FROM escalation_policy_actions a JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id WHERE s.escalation_policy_id=$1 AND a.user_id=$2`, data.CreateEscalationPolicy.ID, h.UUID(target)))
							}
						} else {
							require.NotEmpty(t, response.Errors)
							require.Equal(t, before, epB1Snapshot(t, h))
						}
					})
				}
			}
			// Current-user expansion is a supported Create path, including legacy input.
			for _, field := range []string{`actions:[{type:"builtin-user",args:{user_id:"__current_user"}}]`, `targets:[{type:user,id:"__current_user"}]`} {
				response := epB1Call(t, h, "current_user_"+fmt.Sprint(len(field)), fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,%s}){id}}`, h.UUID("policy-a"), field), "", false)
				require.Empty(t, response.Errors)
				id := stepOrganizationCreateID(t, response)
				require.Equal(t, []string{"user:" + h.UUID("user-a")}, stepActionOrganizationRows(t, h, id))
			}
			// Seed a historical-invalid foreign User, without using the protected API.
			epB1Exec(t, h, `DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, h.UUID("step-a1"))
			epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, h.UUID("step-a1"), h.UUID("user-other"))
			response := epB1Call(t, h, "nil_actions_compatibility", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:23})}`, h.UUID("step-a1")), "", false)
			require.Empty(t, response.Errors)
			require.Equal(t, []string{"user:" + h.UUID("user-other")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
			for _, final := range []string{stepActionOrganizationTarget("user", h.UUID("user-other")), stepActionOrganizationTarget("user", h.UUID("user-home")) + "," + stepActionOrganizationTarget("user", h.UUID("user-other"))} {
				before := epB1Snapshot(t, h)
				response = epB1Call(t, h, "retain_invalid_"+fmt.Sprint(len(final)), fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:24,actions:[%s]})}`, h.UUID("step-a1"), final), "", false)
				require.NotEmpty(t, response.Errors)
				require.Equal(t, before, epB1Snapshot(t, h))
			}
			response = epB1Call(t, h, "remove_invalid", fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,actions:[%s]})}`, h.UUID("step-a1"), stepActionOrganizationTarget("user", h.UUID("user-home"))), "", false)
			require.Empty(t, response.Errors)
			require.Equal(t, []string{"user:" + h.UUID("user-home")}, stepActionOrganizationRows(t, h, h.UUID("step-a1")))
		})
	}
}

func TestEPB1IndirectDeletion(t *testing.T) {
	t.Parallel()
	for _, actor := range []struct {
		name, role string
		pa         bool
	}{{"OrgMember", "ORG_MEMBER", false}, {"OrgAdmin", "ORG_ADMIN", false}, {"PlatformAdminMember", "ORG_MEMBER", true}, {"PlatformAdminAdmin", "ORG_ADMIN", true}} {
		for _, kind := range []string{"schedule", "rotation"} {
			for _, referenced := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/referenced=%t", actor.name, kind, referenced), func(t *testing.T) {
					t.Parallel()
					h := epB1Harness(t)
					ikSetAuthority(t, h, actor.role, actor.pa)
					epB1Exec(t, h, `DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, h.UUID("step-a1"))
					if referenced {
						epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,`+kind+`_id) VALUES($1,$2)`, h.UUID("step-a1"), h.UUID(kind+"-a"))
					}
					epB1Exec(t, h, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id) VALUES($1,$2)`, h.UUID("step-a1"), h.UUID("user-a"))
					// Foreign/missing roots always deny; scope is also concrete for both PAs.
					for _, target := range []string{kind + "-b", kind + "-missing"} {
						before := epB1Snapshot(t, h)
						eligible := actor.pa || actor.role == "ORG_ADMIN"
						response := epB1Call(t, h, target, fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q}])}`, kind, h.UUID(target)), "", eligible)
						require.NotEmpty(t, response.Errors)
						require.Equal(t, before, epB1Snapshot(t, h))
					}
					before := epB1Snapshot(t, h)
					response := epB1Call(t, h, "home_delete", fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q}])}`, kind, h.UUID(kind+"-a")), "", false)
					if !actor.pa && actor.role == "ORG_MEMBER" {
						require.NotEmpty(t, response.Errors)
						require.Equal(t, before, epB1Snapshot(t, h))
					} else {
						require.Empty(t, response.Errors)
						table := "schedules"
						if kind == "rotation" {
							table = "rotations"
						}
						require.Equal(t, "0", epB1Count(t, h, table, h.UUID(kind+"-a")))
						require.Empty(t, stepActionOrganizationRows(t, h, h.UUID("step-a1")), "authorized FK action cascade preserved")
						require.Equal(t, "1", epB1Count(t, h, "escalation_policy_steps", h.UUID("step-a1")))
						require.Equal(t, "1", epB1Count(t, h, "escalation_policies", h.UUID("policy-a")))
					}
				})
			}
		}
	}
}
