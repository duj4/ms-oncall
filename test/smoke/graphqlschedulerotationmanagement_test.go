package smoke

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
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/engine/schedulemanager"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func srB1Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := epB1Harness(t)
	epB1Exec(t, h, "INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0),($4,$2,$5,1)", h.UUID("part-1"), h.UUID("rotation-a"), h.UUID("user-a"), h.UUID("part-2"), h.UUID("user-home"))
	return h
}

func srB1Snapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	out := epB1Snapshot(t, h)
	for _, table := range []string{"schedule_data", "schedule_on_call_users", "user_overrides"} {
		out[table] = epB1Scalar(t, h, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM "+table+" r")
	}
	return out
}

func srB1Call(t *testing.T, h *harness.Harness, name, query, token string, denied bool) *stepOrganizationResponse {
	t.Helper()
	if token == "" {
		token = h.GraphQLToken(h.UUID("user-a"))
	}
	before := srB1Snapshot(t, h)
	body, err := json.Marshal(map[string]any{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	after := srB1Snapshot(t, h)
	var out stepOrganizationResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	if dir := os.Getenv("SR_B1_EVIDENCE"); dir != "" {
		record, err := json.MarshalIndent(map[string]any{"method": "POST", "path": "/api/graphql", "authentication": "actual signed Human session; cookie omitted", "request": json.RawMessage(body), "status": resp.StatusCode, "response": json.RawMessage(raw), "before": before, "after": after, "expected_denial": denied}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+"-"+name+".json"), append(record, '\n'), 0600))
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	if denied {
		require.NotEmpty(t, out.Errors, name)
		require.Equal(t, before, after, "rejected business mutation persisted state: "+name)
	} else {
		require.Empty(t, out.Errors, name)
	}
	return &out
}

func srB1ManagementQueries(h *harness.Harness) map[string]string {
	s, r, u, v := h.UUID("schedule-a"), h.UUID("rotation-a"), h.UUID("user-a"), h.UUID("user-home")
	return map[string]string{
		"schedule_create":      `mutation{created:createSchedule(input:{name:"SR management",timeZone:"Etc/UTC",favorite:true}){...Identity}} fragment Identity on Schedule{id}`,
		"schedule_update":      fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,name:"SR changed",description:"SR config",timeZone:"Asia/Shanghai"})}`, s),
		"rotation_create":      fmt.Sprintf(`mutation{createRotation(input:{name:"SR rotation",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",userIDs:[%q],favorite:true}){id}}`, u),
		"rotation_metadata":    fmt.Sprintf(`mutation{updateRotation(input:{id:%q,name:"SR rotation changed",description:"SR config",type:hourly,shiftLength:2,timeZone:"Asia/Shanghai",start:"2090-01-01T00:00:00Z"})}`, r),
		"participants_add":     fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q,%q]})}`, r, u, v, u),
		"participants_remove":  fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q]})}`, r, v),
		"participants_reorder": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, r, v, u),
		"participants_replace": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, r, v, v),
		"active_only":          fmt.Sprintf(`mutation{updateRotation(input:{id:%q,activeUserIndex:0})}`, r),
		"rule_add_replace":     fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{}, {start:"08:00",end:"12:00"}]})}`, s, v),
		"rule_remove":          fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[]})}`, s, v),
		"current_user_remove":  fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:"__current_user"},rules:[]})}`, s),
		"temporary_set":        fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z",shifts:[{userID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z"}]})}`, s, v),
		"temporary_clear_set":  fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z",clearStart:"2090-01-01T00:00:00Z",clearEnd:"2090-01-01T04:00:00Z",shifts:[]})}`, s),
		"temporary_clear":      fmt.Sprintf(`mutation{clearTemporarySchedules(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z"})}`, s),
		"notification_set":     fmt.Sprintf(`mutation{setScheduleOnCallNotificationRules(input:{scheduleID:%q,rules:[{dest:{type:"builtin-webhook",args:{webhook_url:%q}},time:"12:00",weekdayFilter:[true,true,true,true,true,true,true]}]})}`, s, h.URL()+"/sr-b1-synthetic"),
		"notification_clear":   fmt.Sprintf(`mutation{setScheduleOnCallNotificationRules(input:{scheduleID:%q,rules:[]})}`, s),
	}
}

func TestSRB1Roles(t *testing.T) {
	for _, actor := range []struct {
		name, role string
		pa         bool
	}{{"OrgMember", "ORG_MEMBER", false}, {"OrgAdmin", "ORG_ADMIN", false}, {"PlatformAdminMember", "ORG_MEMBER", true}, {"PlatformAdminAdmin", "ORG_ADMIN", true}} {
		t.Run(actor.name, func(t *testing.T) {
			h := srB1Harness(t)
			ikSetAuthority(t, h, actor.role, actor.pa)
			for name, q := range srB1ManagementQueries(h) {
				t.Run(name, func(t *testing.T) {
					srB1Call(t, h, "home", q, "", !actor.pa && actor.role == "ORG_MEMBER")
					foreign := strings.ReplaceAll(strings.ReplaceAll(q, h.UUID("schedule-a"), h.UUID("schedule-b")), h.UUID("rotation-a"), h.UUID("rotation-b"))
					if foreign != q {
						srB1Call(t, h, "foreign", foreign, "", true)
					}
				})
			}
		})
	}
}

func TestSRB1CurrentAuthority(t *testing.T) {
	h := srB1Harness(t)
	token := h.GraphQLToken(h.UUID("user-a"))
	assignment := epB1Scalar(t, h, "SELECT row_to_json(a)::text FROM user_organization_assignments a WHERE user_id=$1", h.UUID("user-a"))
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	srB1Call(t, h, "admin", srB1ManagementQueries(h)["schedule_update"], token, false)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	for name, q := range srB1ManagementQueries(h) {
		srB1Call(t, h, "downgrade_"+name, q, token, true)
	}
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	epB1Exec(t, h, "UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1", h.UUID("user-a"), h.UUID("org-b"))
	srB1Call(t, h, "reassigned_old_home", srB1ManagementQueries(h)["rotation_metadata"], token, true)
	q := strings.ReplaceAll(srB1ManagementQueries(h)["rotation_metadata"], h.UUID("rotation-a"), h.UUID("rotation-b"))
	srB1Call(t, h, "reassigned_new_home", q, token, false)
	for _, pa := range []bool{false, true} {
		epB1Exec(t, h, "DELETE FROM user_organization_assignments WHERE user_id=$1", h.UUID("user-a"))
		epB1Exec(t, h, "INSERT INTO user_organization_assignments SELECT * FROM json_populate_record(NULL::user_organization_assignments,$1::json)", assignment)
		ikSetAuthority(t, h, "ORG_ADMIN", pa)
		epB1Exec(t, h, "UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1", h.UUID("user-a"))
		for name, q := range srB1ManagementQueries(h) {
			srB1Call(t, h, fmt.Sprintf("default_%t_%s", pa, name), q, token, true)
		}
		epB1Exec(t, h, "DELETE FROM user_organization_assignments WHERE user_id=$1", h.UUID("user-a"))
		for name, q := range srB1ManagementQueries(h) {
			srB1Call(t, h, fmt.Sprintf("missing_%t_%s", pa, name), q, token, true)
		}
	}
}

func TestSRB1NestedTransactions(t *testing.T) {
	h := srB1Harness(t)
	rotation := fmt.Sprintf(`{name:"SR nested rotation",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",userIDs:[%q],favorite:true}`, h.UUID("user-home"))
	directRotation := strings.ReplaceAll(rotation, "SR nested rotation", "SR nested direct rotation")
	sched := fmt.Sprintf(`{name:"SR nested schedule",timeZone:"Etc/UTC",favorite:true,targets:[{newRotation:%s,rules:[{}]}],newUserOverrides:[{start:"2090-02-01T00:00:00Z",end:"2090-02-01T01:00:00Z",addUserID:%q}]}`, rotation, h.UUID("user-home"))
	queries := []string{
		fmt.Sprintf(`mutation{createSchedule(input:%s){id}}`, sched),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,newSchedule:%s}){id}}`, h.UUID("policy-a"), sched),
		fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:2,newRotation:%s}){id}}`, h.UUID("policy-a"), rotation),
		fmt.Sprintf(`mutation{created:createEscalationPolicy(input:{name:"SR nested EP",favorite:true,steps:[{delayMinutes:2,newSchedule:%s},{delayMinutes:3,newRotation:%s}]}){...Identity}} fragment Identity on EscalationPolicy{id}`, sched, directRotation),
		fmt.Sprintf(`mutation{createService(input:{name:"SR nested service",newEscalationPolicy:{name:"SR nested service EP",steps:[{delayMinutes:2,newSchedule:%s},{delayMinutes:3,newRotation:%s}]}}){id}}`, sched, directRotation),
	}
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		ikSetAuthority(t, h, role, false)
		for i, q := range queries {
			q = strings.ReplaceAll(q, "SR nested", fmt.Sprintf("SR case%d nested", i))
			srB1Call(t, h, fmt.Sprintf("%s_nested_%d", role, i), q, "", role == "ORG_MEMBER")
		}
	}
	for i, q := range []string{
		fmt.Sprintf(`mutation{createSchedule(input:{name:"SR rollback targets",timeZone:"Etc/UTC",favorite:true,targets:[{newRotation:%s,rules:[{}]},{target:{type:rotation,id:%q},rules:[{}]}]}){id}}`, rotation, h.UUID("rotation-b")),
		fmt.Sprintf(`mutation{createSchedule(input:%s,{start:"2090-02-01T00:00:00Z",end:"2090-02-01T01:00:00Z",addUserID:"bad"}]}){id}}`, strings.TrimSuffix(sched, "]}")),
		fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"SR rollback EP",steps:[{delayMinutes:2,newSchedule:%s},{delayMinutes:0}]}){id}}`, sched),
		fmt.Sprintf(`mutation{createService(input:{name:"SR rollback service",newEscalationPolicy:{name:"SR rollback service EP",steps:[{delayMinutes:2,newSchedule:%s},{delayMinutes:0}]}}){id}}`, sched),
	} {
		q = strings.ReplaceAll(q, "SR nested", fmt.Sprintf("SR rollback%d nested", i))
		srB1Call(t, h, fmt.Sprintf("later_child_failure_%d", i), q, "", true)
	}
	// Independent top-level fields keep their existing separate transactions.
	q := fmt.Sprintf(`mutation{first:createSchedule(input:{name:"SR separate field",timeZone:"Etc/UTC"}){id} second:updateSchedule(input:{id:%q,name:"SR denied separate field"})}`, h.UUID("schedule-b"))
	before := srB1Snapshot(t, h)
	r := epB1Call(t, h, "independent_top_level", q, "", false)
	require.NotEmpty(t, r.Errors)
	require.NotEqual(t, before, srB1Snapshot(t, h))
	require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM schedules WHERE name='SR separate field'"))
}

func TestSRB1MemberCompatibility(t *testing.T) {
	h := srB1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	r := srB1Call(t, h, "override_create", fmt.Sprintf(`mutation{createUserOverride(input:{scheduleID:%q,start:"2090-03-01T00:00:00Z",end:"2090-03-01T01:00:00Z",addUserID:%q}){id}}`, h.UUID("schedule-a"), h.UUID("user-a")), "", false)
	var data struct{ CreateUserOverride struct{ ID string } }
	require.NoError(t, json.Unmarshal(r.Data, &data))
	srB1Call(t, h, "override_update", fmt.Sprintf(`mutation{updateUserOverride(input:{id:%q,end:"2090-03-01T02:00:00Z"})}`, data.CreateUserOverride.ID), "", false)
	srB1Call(t, h, "override_delete", fmt.Sprintf(`mutation{deleteAll(input:[{type:userOverride,id:%q}])}`, data.CreateUserOverride.ID), "", false)
	for _, kind := range []string{"schedule", "rotation"} {
		for _, set := range []bool{true, false} {
			srB1Call(t, h, fmt.Sprintf("favorite_%s_%t", kind, set), fmt.Sprintf(`mutation{setFavorite(input:{target:{type:%s,id:%q},favorite:%t})}`, kind, h.UUID(kind+"-a"), set), "", false)
		}
	}
	srB1Call(t, h, "read", fmt.Sprintf(`query{schedule(id:%q){id name targets{target{id type}}} rotation(id:%q){id name userIDs activeUserIndex nextHandoffTimes(num:2)} schedules(input:{first:20}){nodes{id}} rotations(input:{first:20}){nodes{id}}}`, h.UUID("schedule-a"), h.UUID("rotation-a")), "", false)
	srB1Call(t, h, "disabled_labels", fmt.Sprintf(`mutation{setLabel(input:{target:{type:rotation,id:%q},key:"SR",value:"probe"})}`, h.UUID("rotation-a")), "", true)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	srB1Call(t, h, "foreign_rotation_nonempty", fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[{}]})}`, h.UUID("schedule-a"), h.UUID("rotation-b")), "", true)
	srB1Call(t, h, "foreign_rotation_historical_removal", fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[]})}`, h.UUID("schedule-a"), h.UUID("rotation-b")), "", false)
	// SR-A0-F02 remains open: this task changes management eligibility only.
	srB1Call(t, h, "f02_admin_foreign_user_unchanged", fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{}]})}`, h.UUID("schedule-a"), h.UUID("user-other")), "", false)
	ctx, cancel := context.WithTimeout(permission.SystemContext(context.Background(), "Smoketest"), 20*time.Second)
	defer cancel()
	manager, err := schedulemanager.NewDB(ctx, h.App().DB())
	require.NoError(t, err)
	require.NoError(t, manager.UpdateAll(ctx))
}
