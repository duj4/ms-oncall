package smoke

// Regression matrix for the 120 original D02-S1-A1 policy assertions.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/test/smoke/harness"
)

const f01SQL = scheduleRotationOrganizationSQL + `
INSERT INTO users(id,name,email,role) VALUES
 ({{uuid "user-a2"}},'Synthetic A Responder','','user'),
 ({{uuid "user-a3"}},'Synthetic A Second Responder','','user'),
 ({{uuid "user-b2"}},'Synthetic B Responder','','user');
INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
VALUES ({{uuid "user-b2"}},{{uuid "org-b"}},'NORMAL',{{uuid "org-b"}},'ORG_MEMBER','EXACTLY_ONE',now(),'d02-s1-f01',1);
INSERT INTO escalation_policies(id,organization_id,name,description,repeat) VALUES
 ({{uuid "policy-a"}},{{smokeOrganizationID}},'Synthetic A EP','original',1),
 ({{uuid "policy-b"}},{{uuid "org-b"}},'Synthetic B EP','original',1);
INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay,step_number) VALUES
 ({{uuid "step-a"}},{{uuid "policy-a"}},1,0),
 ({{uuid "step-b"}},{{uuid "policy-b"}},1,0);
INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
 ({{uuid "step-a"}},{{uuid "user-a2"}}),({{uuid "step-b"}},{{uuid "user-b"}});
INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES
 ({{uuid "rule-a"}},{{uuid "schedule-a"}},{{uuid "user-a2"}}),
 ({{uuid "rule-b"}},{{uuid "schedule-b"}},{{uuid "user-b"}});
INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES
 ({{uuid "part-a1"}},{{uuid "rotation-a"}},{{uuid "user-a2"}},0),
 ({{uuid "part-a2"}},{{uuid "rotation-a"}},{{uuid "user-a3"}},1),
 ({{uuid "part-b1"}},{{uuid "rotation-b"}},{{uuid "user-b"}},0),
 ({{uuid "part-b2"}},{{uuid "rotation-b"}},{{uuid "user-b2"}},1);
`

type f01Actor struct {
	name, role     string
	pa, restricted bool
}

var f01Actors = []f01Actor{{"PlatformAdminMember", "ORG_MEMBER", true, false}, {"PlatformAdminAdmin", "ORG_ADMIN", true, false}, {"OrgAdminA", "ORG_ADMIN", false, false}, {"OrgMemberA", "ORG_MEMBER", false, false}, {"DefaultRestricted", "ORG_MEMBER", false, true}}
var f01Tables = []string{"escalation_policies", "escalation_policy_steps", "escalation_policy_actions", "schedules", "schedule_rules", "schedule_data", "schedule_on_call_users", "rotations", "rotation_participants", "rotation_state", "user_favorites", "user_overrides", "services", "alerts", "alert_data", "alert_logs", "escalation_policy_state", "notification_policy_cycles", "ep_step_on_call_users", "outgoing_messages", "notification_channels", "labels", "user_contact_methods", "user_notification_rules", "integration_keys"}

func f01Save(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("D02_F01_EVIDENCE")
	if dir == "" {
		return
	}
	b, e := json.MarshalIndent(v, "", "  ")
	require.NoError(t, e)
	f, e := os.CreateTemp(dir, strings.ReplaceAll(t.Name()+"_"+name, "/", "_")+"-*.json")
	require.NoError(t, e)
	_, e = f.Write(append(b, '\n'))
	require.NoError(t, e)
	require.NoError(t, f.Close())
}
func f01Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, f01SQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	for _, s := range []string{"a", "b"} {
		epB1Exec(t, h, `INSERT INTO rotation_state(rotation_id,position,rotation_participant_id,shift_start) VALUES($1,0,$2,now()) ON CONFLICT(rotation_id) DO UPDATE SET position=0,rotation_participant_id=$2`, h.UUID("rotation-"+s), h.UUID("part-"+s+"1"))
	}
	// Obtain the signed session before snapshots; actual request admission remains production code.
	h.GraphQLToken(h.UUID("user-a"))
	h.GraphQLToken(h.UUID("user-b"))
	h.IgnoreErrorsWith("sql: no rows in result set")
	f01Save(t, "fixture-validity", map[string]any{"invalid_relationships": f01InvalidRelationships(t, h), "cluster": f01Scalar(t, h, `SELECT system_identifier::text FROM pg_control_system()`), "database": f01Scalar(t, h, `SELECT current_database()`), "database_owner": f01Scalar(t, h, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()`), "fixture_sql": "f01SQL; no nested root creation"})
	require.Equal(t, "0", f01InvalidRelationships(t, h))
	return h
}
func f01Scalar(t *testing.T, h *harness.Harness, q string, args ...any) string {
	return epB1Scalar(t, h, q, args...)
}
func f01InvalidRelationships(t *testing.T, h *harness.Harness) string {
	return f01Scalar(t, h, `SELECT (
 (SELECT count(*) FROM escalation_policy_actions a JOIN escalation_policy_steps st ON st.id=a.escalation_policy_step_id JOIN escalation_policies p ON p.id=st.escalation_policy_id LEFT JOIN user_organization_assignments u ON u.user_id=a.user_id LEFT JOIN schedules s ON s.id=a.schedule_id LEFT JOIN rotations r ON r.id=a.rotation_id WHERE (a.user_id IS NOT NULL AND u.effective_normal_organization_id IS DISTINCT FROM p.organization_id) OR (a.schedule_id IS NOT NULL AND s.organization_id<>p.organization_id) OR (a.rotation_id IS NOT NULL AND r.organization_id<>p.organization_id))+
 (SELECT count(*) FROM schedule_rules x JOIN schedules s ON s.id=x.schedule_id LEFT JOIN rotations r ON r.id=x.tgt_rotation_id LEFT JOIN user_organization_assignments u ON u.user_id=x.tgt_user_id WHERE (x.tgt_user_id IS NOT NULL AND u.effective_normal_organization_id IS DISTINCT FROM s.organization_id) OR (x.tgt_rotation_id IS NOT NULL AND r.organization_id<>s.organization_id))+
 (SELECT count(*) FROM rotation_participants x JOIN rotations r ON r.id=x.rotation_id LEFT JOIN user_organization_assignments u ON u.user_id=x.user_id WHERE u.effective_normal_organization_id IS DISTINCT FROM r.organization_id))::text`)
}
func f01Set(t *testing.T, h *harness.Harness, a f01Actor) {
	ikSetAuthority(t, h, a.role, a.pa)
	if a.restricted {
		epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
	}
}
func f01Identity(t *testing.T, h *harness.Harness, actor string) json.RawMessage {
	return json.RawMessage(f01Scalar(t, h, `SELECT json_build_object('user_id',u.id,'users_role',u.role,'home',a.effective_organization_id,'org_role',a.organization_role,'classification',a.effective_organization_classification,'database',current_database(),'system_identifier',(SELECT system_identifier::text FROM pg_control_system()))::text FROM users u JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=$1`, h.UUID(actor)))
}
func f01Snapshot(t *testing.T, h *harness.Harness) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}
	for _, table := range f01Tables {
		out[table] = json.RawMessage(f01Scalar(t, h, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+table+` r`))
	}
	return out
}
func f01OrgRows(t *testing.T, h *harness.Harness, org string) map[string]string {
	t.Helper()
	out := map[string]string{}
	queries := map[string]string{
		"escalation_policies":       "SELECT p.* FROM escalation_policies p WHERE p.organization_id=$1",
		"escalation_policy_steps":   "SELECT st.* FROM escalation_policy_steps st JOIN escalation_policies p ON p.id=st.escalation_policy_id WHERE p.organization_id=$1",
		"escalation_policy_actions": "SELECT x.* FROM escalation_policy_actions x JOIN escalation_policy_steps st ON st.id=x.escalation_policy_step_id JOIN escalation_policies p ON p.id=st.escalation_policy_id WHERE p.organization_id=$1",
		"schedules":                 "SELECT s.* FROM schedules s WHERE s.organization_id=$1",
		"schedule_rules":            "SELECT x.* FROM schedule_rules x JOIN schedules s ON s.id=x.schedule_id WHERE s.organization_id=$1",
		"rotations":                 "SELECT r.* FROM rotations r WHERE r.organization_id=$1",
		"rotation_participants":     "SELECT x.* FROM rotation_participants x JOIN rotations r ON r.id=x.rotation_id WHERE r.organization_id=$1",
		"rotation_state":            "SELECT x.* FROM rotation_state x JOIN rotations r ON r.id=x.rotation_id WHERE r.organization_id=$1",
	}
	for name, q := range queries {
		out[name] = f01Scalar(t, h, `SELECT coalesce(jsonb_agg(to_jsonb(z) ORDER BY to_jsonb(z)::text),'[]')::text FROM (`+q+`) z`, org)
	}
	return out
}
func f01Call(t *testing.T, h *harness.Harness, label, query, actor, token string) (*stepOrganizationResponse, map[string]any) {
	t.Helper()
	before := f01Snapshot(t, h)
	body, e := json.Marshal(map[string]any{"query": query})
	require.NoError(t, e)
	req, e := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, e)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	identity := f01Identity(t, h, actor)
	var authority map[string]any
	require.NoError(t, json.Unmarshal(identity, &authority))
	resp, e := http.DefaultClient.Do(req)
	require.NoError(t, e)
	defer resp.Body.Close()
	raw, e := io.ReadAll(resp.Body)
	require.NoError(t, e)
	after := f01Snapshot(t, h)
	var out stepOrganizationResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	record := map[string]any{"actor": identity, "home_organization": authority["home"], "method": "POST", "path": "/api/graphql", "authentication": "production signed Human session; credential omitted", "http_status": resp.StatusCode, "query": query, "response": json.RawMessage(raw), "before": before, "after": after, "actual_success": resp.StatusCode == 200 && len(out.Errors) == 0}
	f01Save(t, label, record)
	require.Equal(t, 200, resp.StatusCode)
	if len(out.Errors) > 0 {
		require.Equal(t, before, after, "denial must leave all selected business tables unchanged")
	}
	return &out, record
}
func f01Table(kind string) string {
	return map[string]string{"EP": "escalation_policies", "Schedule": "schedules", "Rotation": "rotations"}[kind]
}
func f01Root(kind string) string {
	return map[string]string{"EP": "policy", "Schedule": "schedule", "Rotation": "rotation"}[kind]
}
func f01Type(kind string) string {
	return map[string]string{"EP": "escalationPolicy", "Schedule": "schedule", "Rotation": "rotation"}[kind]
}
func f01RootQuery(h *harness.Harness, kind, op, s, label string) string {
	id := h.UUID(f01Root(kind) + "-" + s)
	if op == "delete" {
		return fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q}])}`, f01Type(kind), id)
	}
	return fmt.Sprintf(`mutation{update%s(input:{id:%q,description:%q})}`, map[string]string{"EP": "EscalationPolicy", "Schedule": "Schedule", "Rotation": "Rotation"}[kind], id, label)
}
func f01Org(h *harness.Harness, s string) string {
	if s == "a" {
		return harness.SmokeOrganizationID
	}
	return h.UUID("org-b")
}
func f01RootPersist(t *testing.T, h *harness.Harness, kind, op, s, label string, ok bool) {
	t.Helper()
	id := h.UUID(f01Root(kind) + "-" + s)
	table := f01Table(kind)
	count := f01Scalar(t, h, "SELECT count(*)::text FROM "+table+" WHERE id=$1", id)
	if op == "delete" && ok {
		require.Equal(t, "0", count)
	} else {
		require.Equal(t, "1", count)
	}
	if op == "update" && ok {
		require.Equal(t, label, f01Scalar(t, h, "SELECT description FROM "+table+" WHERE id=$1", id))
	}
	if op == "delete" && ok {
		switch kind {
		case "EP":
			require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM escalation_policy_steps WHERE escalation_policy_id=$1", id))
			require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1", h.UUID("step-"+s)))
		case "Schedule":
			require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM schedule_rules WHERE schedule_id=$1", id))
		case "Rotation":
			require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM rotation_participants WHERE rotation_id=$1", id))
			require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM rotation_state WHERE rotation_id=$1", id))
		}
	}
}
func TestExistingRootGlobalRootMatrix(t *testing.T) {
	for _, a := range f01Actors {
		t.Run(a.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, a)
			token := h.GraphQLToken(h.UUID("user-a"))
			require.Equal(t, "0", f01Scalar(t, h, `SELECT count(*)::text FROM user_organization_assignments WHERE user_id=$1 AND effective_organization_id=$2`, h.UUID("user-a"), h.UUID("org-b")))
			for _, kind := range []string{"EP", "Schedule", "Rotation"} {
				for _, op := range []string{"update", "delete"} {
					for _, s := range []string{"a", "b"} {
						label := a.name + "_" + kind + "_" + op + "_" + s
						query := f01RootQuery(h, kind, op, s, label)
						other := "b"
						if s == "b" {
							other = "a"
						}
						preserve := f01OrgRows(t, h, f01Org(h, other))
						r, rec := f01Call(t, h, label, query, "user-a", token)
						ok := len(r.Errors) == 0
						want := !a.restricted && (a.pa || (a.role == "ORG_ADMIN" && s == "a"))
						rec["expected_policy_allow"] = want
						rec["target_organization"] = f01Org(h, s)
						rec["persistence_verified"] = true
						f01RootPersist(t, h, kind, op, s, label, ok)
						require.Equal(t, preserve, f01OrgRows(t, h, f01Org(h, other)), "other Organization retained")
						if want && !ok && s == "b" {
							epB1Exec(t, h, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, h.UUID("user-b"))
							control, controlRec := f01Call(t, h, label+"_same_target_positive_control", query, "user-b", h.GraphQLToken(h.UUID("user-b")))
							require.Empty(t, control.Errors, "same target and query must work for actual target OrgAdmin")
							f01RootPersist(t, h, kind, op, s, label, true)
							rec["same_target_positive_control"] = controlRec
						}
						if ok && a.pa && s == "b" {
							f01SameTargetControl(t, h, query, kind, op, label, rec)
						}
						f01Save(t, label, rec)
						assert.Equal(t, want, ok, "D02 policy mismatch: "+label)
					}
				}
			}
		})
	}
}

func f01SecondUser(h *harness.Harness, s string) string {
	if s == "a" {
		return h.UUID("user-a3")
	}
	return h.UUID("user-b2")
}
func f01FirstUser(h *harness.Harness, s string) string {
	if s == "a" {
		return h.UUID("user-a2")
	}
	return h.UUID("user-b")
}
func f01NestedQuery(h *harness.Harness, op, s string) string {
	p, st, sch, rot, u, v := h.UUID("policy-"+s), h.UUID("step-"+s), h.UUID("schedule-"+s), h.UUID("rotation-"+s), f01FirstUser(h, s), f01SecondUser(h, s)
	switch op {
	case "step_update":
		return fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:17,actions:[{type:"builtin-user",args:{user_id:%q}},{type:"builtin-schedule",args:{schedule_id:%q}},{type:"builtin-rotation",args:{rotation_id:%q}}]})}`, st, u, sch, rot)
	case "step_create":
		return fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:7,actions:[{type:"builtin-user",args:{user_id:%q}},{type:"builtin-schedule",args:{schedule_id:%q}},{type:"builtin-rotation",args:{rotation_id:%q}}]}){id}}`, p, u, sch, rot)
	case "rule_user":
		return fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{start:"08:00",end:"12:00"}]})}`, sch, v)
	case "rule_rotation":
		return fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[{start:"08:00",end:"12:00"}]})}`, sch, rot)
	case "participants":
		return fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, rot, v, u)
	case "active_index":
		return fmt.Sprintf(`mutation{updateRotation(input:{id:%q,activeUserIndex:1})}`, rot)
	}
	panic(op)
}
func f01NestedPersist(t *testing.T, h *harness.Harness, op, s string) {
	t.Helper()
	switch op {
	case "step_update":
		require.Equal(t, "17", f01Scalar(t, h, "SELECT delay::text FROM escalation_policy_steps WHERE id=$1", h.UUID("step-"+s)))
		require.Equal(t, "3", f01Scalar(t, h, "SELECT count(*)::text FROM escalation_policy_actions WHERE escalation_policy_step_id=$1", h.UUID("step-"+s)))
	case "step_create":
		require.Equal(t, "1", f01Scalar(t, h, "SELECT count(*)::text FROM escalation_policy_steps WHERE escalation_policy_id=$1 AND delay=7", h.UUID("policy-"+s)))
	case "rule_user":
		require.Equal(t, "1", f01Scalar(t, h, "SELECT count(*)::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 AND start_time='08:00' AND end_time='12:00'", h.UUID("schedule-"+s), f01SecondUser(h, s)))
	case "rule_rotation":
		require.Equal(t, "1", f01Scalar(t, h, "SELECT count(*)::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_rotation_id=$2 AND start_time='08:00' AND end_time='12:00'", h.UUID("schedule-"+s), h.UUID("rotation-"+s)))
	case "participants":
		require.Equal(t, f01SecondUser(h, s), f01Scalar(t, h, "SELECT user_id::text FROM rotation_participants WHERE rotation_id=$1 AND position=0", h.UUID("rotation-"+s)))
	case "active_index":
		require.Equal(t, "1", f01Scalar(t, h, "SELECT position::text FROM rotation_state WHERE rotation_id=$1", h.UUID("rotation-"+s)))
	}
	require.Equal(t, "0", f01InvalidRelationships(t, h))
}
func TestExistingRootGlobalNestedMatrix(t *testing.T) {
	for _, a := range f01Actors {
		t.Run(a.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, a)
			token := h.GraphQLToken(h.UUID("user-a"))
			for _, op := range []string{"step_update", "step_create", "rule_user", "rule_rotation", "participants", "active_index"} {
				for _, s := range []string{"a", "b"} {
					label := a.name + "_" + op + "_" + s
					query := f01NestedQuery(h, op, s)
					other := "b"
					if s == "b" {
						other = "a"
					}
					preserve := f01OrgRows(t, h, f01Org(h, other))
					r, rec := f01Call(t, h, label, query, "user-a", token)
					ok := len(r.Errors) == 0
					want := !a.restricted && (a.pa || (a.role == "ORG_ADMIN" && s == "a"))
					rec["expected_policy_allow"] = want
					rec["target_organization"] = f01Org(h, s)
					rec["persistence_verified"] = true
					if ok {
						f01NestedPersist(t, h, op, s)
					}
					require.Equal(t, preserve, f01OrgRows(t, h, f01Org(h, other)))
					if want && !ok && s == "b" {
						epB1Exec(t, h, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, h.UUID("user-b"))
						control, controlRec := f01Call(t, h, label+"_same_target_positive_control", query, "user-b", h.GraphQLToken(h.UUID("user-b")))
						require.Empty(t, control.Errors)
						f01NestedPersist(t, h, op, s)
						rec["same_target_positive_control"] = controlRec
					}
					if ok && a.pa && s == "b" {
						f01SameTargetControl(t, h, query, "", op, label, rec)
					}
					f01Save(t, label, rec)
					assert.Equal(t, want, ok, "D02 policy mismatch: "+label)
				}
			}
		})
	}
}

func f01SameTargetControl(t *testing.T, h *harness.Harness, query, kind, op, label string, rec map[string]any) {
	t.Helper()
	epB1Exec(t, h, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, h.UUID("user-b"))
	if op == "delete" {
		before := rec["before"].(map[string]json.RawMessage)
		tables := map[string][]string{
			"EP":       {"escalation_policies", "escalation_policy_steps", "escalation_policy_actions"},
			"Schedule": {"schedules", "schedule_rules"},
			"Rotation": {"rotations", "rotation_participants", "rotation_state"},
		}[kind]
		for _, table := range tables {
			key := "id"
			if table == "rotation_state" {
				key = "rotation_id"
			}
			epB1Exec(t, h, "INSERT INTO "+table+" SELECT * FROM jsonb_populate_recordset(NULL::"+table+",$1::jsonb) ON CONFLICT("+key+") DO NOTHING", string(before[table]))
		}
	}
	result, control := f01Call(t, h, label+"_same_target_orgadmin_control", query, "user-b", h.GraphQLToken(h.UUID("user-b")))
	require.Empty(t, result.Errors, "the same actual target and mutation must succeed for its OrgAdmin")
	if kind != "" {
		f01RootPersist(t, h, kind, op, "b", label, true)
	} else if op == "step_create" {
		require.Equal(t, "2", f01Scalar(t, h, `SELECT count(*)::text FROM escalation_policy_steps WHERE escalation_policy_id=$1 AND delay=7`, h.UUID("policy-b")))
	} else {
		f01NestedPersist(t, h, op, "b")
	}
	control["persistence_verified"] = true
	control["target_organization"] = rec["target_organization"]
	rec["same_target_positive_control"] = control
}
