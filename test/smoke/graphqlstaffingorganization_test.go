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

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/engine/schedulemanager"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
)

// Every call uses actual signed Human admission. Store/System fixtures below
// are explicitly separate and never stand in for a Human request.
func srB2Call(t *testing.T, h *harness.Harness, name, query string, variables any, denied bool) *stepOrganizationResponse {
	t.Helper()
	token := h.GraphQLToken(h.UUID("user-a")) // same session across authority changes
	before := srB1Snapshot(t, h)
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
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
	if dir := os.Getenv("SR_B2_EVIDENCE"); dir != "" {
		record, err := json.MarshalIndent(map[string]any{"method": "POST", "path": "/api/graphql", "authentication": "real signed Human session; cookie omitted", "request": json.RawMessage(body), "http_status": resp.StatusCode, "graphql_response": json.RawMessage(raw), "expected_denial": denied, "before": before, "after": after}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "_")+"-"+name+".json"), append(record, '\n'), 0600))
	}
	var out stepOrganizationResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	if denied {
		require.NotEmpty(t, out.Errors, name)
		require.Equal(t, before, after, "rejected business mutation changed durable state: "+name)
	} else {
		require.Empty(t, out.Errors, name)
		var data map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(out.Data, &data))
		for field, value := range data {
			require.NotContains(t, []string{"null", "false"}, string(value), "positive control must succeed")
			table := map[string]string{"createSchedule": "schedules", "createRotation": "rotations", "createUserOverride": "user_overrides", "createEscalationPolicy": "escalation_policies", "createService": "services"}[field]
			if table != "" {
				var created struct{ ID string }
				require.NoError(t, json.Unmarshal(value, &created))
				require.NotEmpty(t, created.ID)
				require.Equal(t, "1", epB1Count(t, h, table, created.ID), "positive create must persist")
			}
		}
	}
	return &out
}

func srB2Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := srB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	return h
}

func srB2Rule(h *harness.Harness, parent, user, rules string) string {
	return fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:%s})}`, parent, user, rules)
}

func TestSRB2RulesAndParents(t *testing.T) {
	h := srB2Harness(t)
	s, u, f := h.UUID("schedule-a"), h.UUID("user-home"), h.UUID("user-other")
	srB2Call(t, h, "B2-01-home", srB2Rule(h, s, u, `[{}]`), nil, false)
	require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2", s, u))
	foreign := srB2Call(t, h, "B2-02-foreign", srB2Rule(h, s, f, `[{}]`), nil, true)
	missing := srB2Call(t, h, "B2-03-missing", srB2Rule(h, s, h.UUID("missing"), `[{}]`), nil, true)
	require.Equal(t, foreign.Errors, missing.Errors)
	for _, parent := range []string{h.UUID("schedule-b"), h.UUID("missing")} {
		for _, target := range []string{u, f, h.UUID("missing"), "bad"} {
			r := srB2Call(t, h, "B2-03-parent-"+parent+"-"+target, srB2Rule(h, parent, target, `[{}]`), nil, true)
			require.Equal(t, "schedule not found", r.Errors[0].Message)
		}
	}
	// Historical relationships are fixtures, not newly authorized writes.
	epB1Exec(t, h, "INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)", h.UUID("legacy-rule"), s, f)
	srB2Call(t, h, "B2-04-retain-denied", srB2Rule(h, s, f, `[{},{}]`), nil, true)
	srB2Call(t, h, "B2-04-remove", srB2Rule(h, s, f, `[]`), nil, false)
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_rules WHERE tgt_user_id=$1", f))
	srB2Call(t, h, "current-user", srB2Rule(h, s, "__current_user", `[{}]`), nil, false)
	for _, target := range []string{"bad", uuid.Nil.String()} {
		srB2Call(t, h, "B2-17-"+target, srB2Rule(h, s, target, `[{}]`), nil, true)
	}
	for _, target := range []string{f, h.UUID("missing")} {
		srB2Call(t, h, "missing-cleanup-"+target, srB2Rule(h, s, target, `[]`), nil, false)
	}
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	srB2Call(t, h, "B2-19-member", srB2Rule(h, s, u, `[{}]`), nil, true)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	epB1Exec(t, h, "UPDATE users SET role='admin' WHERE id=$1", f)
	srB2Call(t, h, "B2-18-platform-target", srB2Rule(h, s, f, `[{}]`), nil, true)
	srB2Call(t, h, "B2-18-platform-home", srB2Rule(h, s, u, `[{}]`), nil, false)
	for i, query := range []string{
		fmt.Sprintf(`mutation{createRotation(input:{name:"B2 PA foreign",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",userIDs:[%q]}){id}}`, f),
		srB2Temp(s, f, ""),
		fmt.Sprintf(`mutation{createUserOverride(input:{scheduleID:%q,start:"2090-04-01T00:00:00Z",end:"2090-04-01T01:00:00Z",addUserID:%q}){id}}`, s, f),
	} {
		srB2Call(t, h, fmt.Sprintf("B2-18-other-family-%d", i), query, nil, true)
	}
}

func TestSRB2RotationLists(t *testing.T) {
	h := srB2Harness(t)
	r, u, v, f := h.UUID("rotation-a"), h.UUID("user-a"), h.UUID("user-home"), h.UUID("user-other")
	create := func(user string) string {
		return fmt.Sprintf(`mutation{createRotation(input:{name:%q,type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",favorite:true,userIDs:[%q]}){id userIDs}}`, "B2 rotation "+user, user)
	}
	srB2Call(t, h, "B2-05-home", create(v), nil, false)
	require.Equal(t, "1", epB1Scalar(t, h, `SELECT count(*)::text FROM rotations r JOIN rotation_participants p ON p.rotation_id=r.id WHERE r.name=$2 AND p.user_id=$1`, v, "B2 rotation "+v))
	for _, target := range []string{f, h.UUID("missing"), "bad"} {
		srB2Call(t, h, "B2-05-reject-"+target, create(target), nil, true)
	}
	update := func(fields string) string {
		return fmt.Sprintf(`mutation{updateRotation(input:{id:%q,%s})}`, r, fields)
	}
	srB2Call(t, h, "B2-06-home-duplicates", update(fmt.Sprintf(`userIDs:[%q,%q,%q]`, v, u, v)), nil, false)
	require.JSONEq(t, fmt.Sprintf(`[%q,%q,%q]`, v, u, v), epB1Scalar(t, h, `SELECT jsonb_agg(user_id ORDER BY position)::text FROM rotation_participants WHERE rotation_id=$1`, r))
	epB1Exec(t, h, "UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=2", r, f)
	for i, fields := range []string{
		fmt.Sprintf(`userIDs:[%q,%q,%q]`, v, u, f),
		fmt.Sprintf(`name:"B2 must roll back",userIDs:[%q,%q,%q],activeUserIndex:0`, f, u, v),
		fmt.Sprintf(`userIDs:[%q]`, h.UUID("missing")),
	} {
		srB2Call(t, h, fmt.Sprintf("B2-06-07-retained-%d", i), update(fields), nil, true)
	}
	// No submitted list means no membership rewrite, including active-only.
	for i, fields := range []string{`description:"B2 nil list"`, `description:"B2 null list",userIDs:null`, `activeUserIndex:0`} {
		srB2Call(t, h, fmt.Sprintf("B2-09-nil-%d", i), update(fields), nil, false)
		require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM rotation_participants WHERE rotation_id=$1 AND user_id=$2", r, f))
	}
	srB2Call(t, h, "B2-08-remove-foreign", update(fmt.Sprintf(`userIDs:[%q,%q]`, v, u)), nil, false)
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM rotation_participants WHERE rotation_id=$1 AND user_id=$2", r, f))
	srB2Call(t, h, "B2-09-empty", update(`userIDs:[]`), nil, false)
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM rotation_participants WHERE rotation_id=$1", r))
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM rotation_state WHERE rotation_id=$1", r))
}

func srB2Temp(parent, user, clear string) string {
	return fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z",shifts:[{userID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z"}]%s})}`, parent, user, clear)
}

func TestSRB2TemporarySchedules(t *testing.T) {
	h := srB2Harness(t)
	s, u, f := h.UUID("schedule-a"), h.UUID("user-home"), h.UUID("user-other")
	epB1Exec(t, h, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"FutureVersion":{"sentinel":17},"V1":{"Unknown":"keep"}}')`, s)
	srB2Call(t, h, "B2-10-home", srB2Temp(s, u, ""), nil, false)
	raw := func() string { return epB1Scalar(t, h, "SELECT data::text FROM schedule_data WHERE schedule_id=$1", s) }
	require.Contains(t, raw(), u)
	require.Contains(t, raw(), `"sentinel": 17`)
	require.Contains(t, raw(), `"Unknown": "keep"`)
	for i, extra := range []string{"", `,clearStart:"2090-01-01T00:00:00Z",clearEnd:"2090-01-02T00:00:00Z"`} {
		foreign := srB2Call(t, h, fmt.Sprintf("B2-10-11-foreign-%d", i), srB2Temp(s, f, extra), nil, true)
		missing := srB2Call(t, h, fmt.Sprintf("B2-10-11-missing-%d", i), srB2Temp(s, h.UUID("missing"), extra), nil, true)
		require.Equal(t, foreign.Errors, missing.Errors)
	}
	for _, target := range []string{f, h.UUID("missing")} {
		r := srB2Call(t, h, "temp-parent-"+target, srB2Temp(h.UUID("schedule-b"), target, ""), nil, true)
		require.Equal(t, "schedule does not exist", r.Errors[0].Message)
	}
	// Introduce a historical foreign shift without going through Human admission.
	epB1Exec(t, h, "UPDATE schedule_data SET data=replace(data::text,$2,$3)::jsonb WHERE schedule_id=$1", s, u, f)
	srB2Call(t, h, "B2-11-clear-only", fmt.Sprintf(`mutation{clearTemporarySchedules(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-02T00:00:00Z"})}`, s), nil, false)
	require.NotContains(t, raw(), f)
	srB2Call(t, h, "B2-11-clear-set-home", srB2Temp(s, u, `,clearStart:"2090-01-01T00:00:00Z",clearEnd:"2090-01-02T00:00:00Z"`), nil, false)
	srB2Call(t, h, "empty-shifts", fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z",shifts:[]})}`, s), nil, false)
	require.NotContains(t, raw(), u)
	// Elapsed foreign shifts disappear during existing Normalize/TrimStart;
	// they cannot become new persisted relationships and are not reauthorized.
	pastStart, pastEnd := time.Now().Add(-2*time.Hour).Format(time.RFC3339), time.Now().Add(-time.Hour).Format(time.RFC3339)
	srB2Call(t, h, "normalized-elapsed-foreign", fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:%q,end:"2090-01-01T04:00:00Z",shifts:[{userID:%q,start:%q,end:%q}]})}`, s, pastStart, f, pastStart, pastEnd), nil, false)
	require.NotContains(t, raw(), f)
}

func TestSRB2MemberOverrides(t *testing.T) {
	h := srB2Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	s, u, v, f := h.UUID("schedule-a"), h.UUID("user-home"), h.UUID("user-a"), h.UUID("user-other")
	create := func(add, remove string) string {
		return fmt.Sprintf(`mutation{createUserOverride(input:{scheduleID:%q,start:"2090-04-01T00:00:00Z",end:"2090-04-01T01:00:00Z",addUserID:%q,removeUserID:%q}){id}}`, s, add, remove)
	}
	srB2Call(t, h, "B2-12-home-add-remove", create(u, v), nil, false)
	id := epB1Scalar(t, h, "SELECT id::text FROM user_overrides WHERE tgt_schedule_id=$1 AND add_user_id=$2", s, u)
	for _, ids := range [][2]string{{f, ""}, {"", f}, {h.UUID("missing"), ""}, {"", h.UUID("missing")}} {
		srB2Call(t, h, "B2-13-"+ids[0]+"-"+ids[1], create(ids[0], ids[1]), nil, true)
	}
	update := func(fields string) string {
		return fmt.Sprintf(`mutation{updateUserOverride(input:{id:%q,%s})}`, id, fields)
	}
	srB2Call(t, h, "B2-13-update", update(fmt.Sprintf(`addUserID:%q`, f)), nil, true)
	epB1Exec(t, h, "UPDATE user_overrides SET add_user_id=$2 WHERE id=$1", id, f)
	srB2Call(t, h, "B2-14-retained-time-only", update(`end:"2090-04-01T02:00:00Z"`), nil, true)
	srB2Call(t, h, "B2-14-replace", update(fmt.Sprintf(`addUserID:%q,end:"2090-04-01T02:00:00Z"`, u)), nil, false)
	require.Equal(t, u, epB1Scalar(t, h, "SELECT add_user_id::text FROM user_overrides WHERE id=$1", id))
	epB1Exec(t, h, "UPDATE user_overrides SET remove_user_id=$2 WHERE id=$1", id, f)
	srB2Call(t, h, "B2-14-retained-remove", update(`end:"2090-04-01T03:00:00Z"`), nil, true)
	srB2Call(t, h, "B2-14-remove-reference", update(`removeUserID:""`), nil, false)
	require.Equal(t, "true", epB1Scalar(t, h, "SELECT (remove_user_id IS NULL)::text FROM user_overrides WHERE id=$1", id))
	epB1Exec(t, h, "UPDATE user_overrides SET add_user_id=$2 WHERE id=$1", id, f)
	srB2Call(t, h, "B2-14-delete-invalid", fmt.Sprintf(`mutation{deleteAll(input:[{type:userOverride,id:%q}])}`, id), nil, false)
	require.Equal(t, "0", epB1Count(t, h, "user_overrides", id))
}

func TestSRB2NestedAndVariables(t *testing.T) {
	h := srB2Harness(t)
	u, f := h.UUID("user-home"), h.UUID("user-other")
	rot := fmt.Sprintf(`{name:"B2 child",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",favorite:true,userIDs:[%q]}`, u)
	for _, target := range []string{u, f} {
		// The later invalid target follows an earlier Favorite, Rotation,
		// Participants and Rule. Each is in the enclosing business transaction.
		sched := fmt.Sprintf(`{name:"B2 nested",timeZone:"Etc/UTC",favorite:true,targets:[{newRotation:%s,rules:[{}]},{target:{type:user,id:%q},rules:[{}]}]}`, rot, target)
		for i, query := range []string{
			`mutation{createSchedule(input:` + sched + `){id}}`,
			`mutation{createEscalationPolicy(input:{name:"B2 EP",steps:[{delayMinutes:2,newSchedule:` + sched + `}]}){id}}`,
			`mutation{createService(input:{name:"B2 Service",newEscalationPolicy:{name:"B2 service EP",steps:[{delayMinutes:2,newSchedule:` + sched + `}]}}){id}}`,
			fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"B2 rotation EP",steps:[{delayMinutes:2,newRotation:{name:"B2 direct rotation",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",userIDs:[%q]}}]}){id}}`, target),
		} {
			query = strings.ReplaceAll(query, "B2 ", fmt.Sprintf("B2-%d-%s ", i, target))
			result := srB2Call(t, h, fmt.Sprintf("B2-15-parent-%d-%s", i, target), query, nil, target == f)
			if target == f {
				if i == 3 {
					require.Equal(t, "user does not exist", result.Errors[0].Message)
				} else {
					require.Equal(t, "does not exist", result.Errors[0].Message)
				}
			}
		}
		query := fmt.Sprintf(`mutation{createSchedule(input:{name:"B2 nested overrides %s",timeZone:"Etc/UTC",favorite:true,targets:[{newRotation:%s,rules:[{}]}],newUserOverrides:[{start:"2090-05-01T00:00:00Z",end:"2090-05-01T01:00:00Z",addUserID:%q},{start:"2090-05-02T00:00:00Z",end:"2090-05-02T01:00:00Z",addUserID:%q}]}){id}}`, target, strings.ReplaceAll(rot, "B2 child", "B2 override child "+target), u, target)
		result := srB2Call(t, h, "B2-15-later-override-"+target, query, nil, target == f)
		if target == f {
			require.Equal(t, "user does not exist", result.Errors[0].Message)
		}
	}
	foreignRotation := fmt.Sprintf(`{name:"B2 later foreign rotation",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",favorite:true,userIDs:[%q]}`, f)
	srB2Call(t, h, "B2-15-later-rotation", fmt.Sprintf(`mutation{createSchedule(input:{name:"B2 later rotation rollback",timeZone:"Etc/UTC",favorite:true,targets:[{newRotation:%s,rules:[{}]},{newRotation:%s,rules:[{}]}]}){id}}`, strings.ReplaceAll(rot, "B2 child", "B2 earlier rotation"), foreignRotation), nil, true)
	variables := map[string]any{"input": map[string]any{"name": "B2 variables", "timeZone": "Etc/UTC", "favorite": true, "targets": []any{map[string]any{"newRotation": map[string]any{"name": "B2 variable rotation", "type": "daily", "timeZone": "Etc/UTC", "start": "2090-01-01T00:00:00Z", "userIDs": []string{f}}, "rules": []any{map[string]any{}}}}}}
	query := `mutation($input:CreateScheduleInput!){aliased:createSchedule(input:$input){...B2Identity}} fragment B2Identity on Schedule{id}`
	srB2Call(t, h, "B2-15-variable-alias-fragment", query, variables, true)
}

func TestSRB2CurrentAssignment(t *testing.T) {
	h := srB2Harness(t)
	s, u := h.UUID("schedule-a"), h.UUID("user-home")
	for _, state := range []string{"home", "foreign", "default", "ambiguous-default", "missing", "home-again", "disabled-user"} {
		switch state {
		case "foreign":
			epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, u, h.UUID("org-b"))
		case "default":
			epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, u)
		case "missing":
			epB1Exec(t, h, `DELETE FROM user_organization_assignments WHERE user_id=$1`, u)
		case "ambiguous-default":
			epB1Exec(t, h, `UPDATE user_organization_assignments SET mapping_outcome='MULTIPLE',matched_count=2 WHERE user_id=$1`, u)
		case "home-again":
			epB1Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'b2-current',1)`, u, harness.SmokeOrganizationID)
		case "disabled-user":
			epB1Exec(t, h, `UPDATE users SET role='unknown' WHERE id=$1`, u)
		}
		denied := state != "home" && state != "home-again"
		for i, query := range []string{
			srB2Rule(h, s, u, `[{}]`),
			fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q]})}`, h.UUID("rotation-a"), u),
			srB2Temp(s, u, ""),
			fmt.Sprintf(`mutation{createUserOverride(input:{scheduleID:%q,start:"2090-06-%02dT00:00:00Z",end:"2090-06-%02dT01:00:00Z",addUserID:%q}){id}}`, s, 1+len(state), 1+len(state), u),
		} {
			srB2Call(t, h, fmt.Sprintf("B2-16-17-%s-%d", state, i), query, nil, denied)
		}
	}
}

func TestSRB2EngineAndTrustedStore(t *testing.T) {
	h := srB2Harness(t)
	s, u, f := h.UUID("schedule-a"), h.UUID("user-home"), h.UUID("user-other")
	srB2Call(t, h, "B2-20-deny-foreign", srB2Rule(h, s, f, `[{}]`), nil, true)
	srB2Call(t, h, "B2-20-home", srB2Rule(h, s, u, `[{}]`), nil, false)
	ctx, cancel := context.WithTimeout(permission.SystemContext(context.Background(), "Smoketest"), 20*time.Second)
	defer cancel()
	manager, err := schedulemanager.NewDB(ctx, h.App().DB())
	require.NoError(t, err)
	require.NoError(t, manager.UpdateAll(ctx))
	require.Equal(t, "1", epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2", s, u))
	require.Equal(t, "0", epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2", s, f))
	// Explicit nil-scope Store compatibility remains trusted internal behavior.
	start := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
	temp := schedule.TemporarySchedule{Start: start, End: start.Add(time.Hour), Shifts: []schedule.FixedShift{{UserID: f, Start: start, End: start.Add(time.Hour)}}}
	require.NoError(t, h.App().ScheduleStore.SetTemporarySchedule(ctx, nil, uuid.MustParse(s), temp))
	require.Contains(t, epB1Scalar(t, h, "SELECT data::text FROM schedule_data WHERE schedule_id=$1", s), f)
	if dir := os.Getenv("SR_B2_EVIDENCE"); dir != "" {
		record, err := json.MarshalIndent(map[string]any{"caller": "trusted System manager and nil-scope Store; distinct from preceding signed Human HTTP", "home_on_call": epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2", s, u), "foreign_on_call": epB1Scalar(t, h, "SELECT count(*)::text FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2", s, f), "state": srB1Snapshot(t, h)}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "B2-20-22-engine-system.json"), record, 0600))
	}
}
