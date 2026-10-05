package app

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
)

// Reuse the accepted API-only Calendar test harness: each invocation migrates a
// uniquely named disposable DB through the canonical manifest and drops it.
type dormantLabelTarget struct{ kind, field, id, column string }

func seedDormantLabelTargets(t *testing.T, h *calendarPolicyRuntime) []dormantLabelTarget {
	t.Helper()
	ctx := context.Background()
	var targets []dormantLabelTarget
	for i, userID := range h.users {
		var org string
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT effective_normal_organization_id FROM user_organization_assignments WHERE user_id=$1`, userID).Scan(&org))
		ep, svc, rot := uuid.NewString(), uuid.NewString(), uuid.NewString()
		_, err := h.pool.Exec(ctx, `INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,$2,$3)`, ep, fmt.Sprintf("Label Policy %d", i), org)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES($1,$2,$3,$4)`, svc, fmt.Sprintf("Label Service %d", i), ep, org)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `INSERT INTO rotations(id,name,type,time_zone,organization_id) VALUES($1,$2,'daily','Etc/UTC',$3)`, rot, fmt.Sprintf("Label Rotation %d", i), org)
		require.NoError(t, err)
		group := []dormantLabelTarget{{"service", "service", svc, "tgt_service_id"}, {"schedule", "schedule", h.schedules[i], "tgt_schedule_id"}, {"rotation", "rotation", rot, "tgt_rotation_id"}, {"escalationPolicy", "escalationPolicy", ep, "tgt_ep_id"}}
		for _, tgt := range group {
			_, err = h.pool.Exec(ctx, `INSERT INTO labels(`+tgt.column+`,key,value) VALUES($1,'policy/key','dormant')`, tgt.id)
			require.NoError(t, err)
		}
		targets = append(targets, group...)
	}
	return targets
}

func labelDisabledResult(t *testing.T, r calendarGraphQLResult) {
	t.Helper()
	require.Len(t, r.Errors, 1)
	require.Equal(t, "labels are disabled", r.Errors[0].Message)
}

func TestLabelProductPolicyConfigPersistence(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	check := func(name string) {
		t.Helper()
		cfg := h.app.ConfigStore.Config()
		require.True(t, cfg.General.DisableLabelCreation, name)
		require.Empty(t, cfg.Services.RequiredLabels, name)
		require.True(t, cfg.General.DisableCalendarSubscriptions)
		for _, who := range []string{h.users[0], h.admin} {
			r := h.query(who, fmt.Sprintf(`{config(all:%t){id value}}`, who == h.admin))
			require.Empty(t, r.Errors)
			var values []struct{ ID, Value string }
			require.NoError(t, json.Unmarshal(r.Data["config"], &values))
			var disabled, required bool
			for _, v := range values {
				if v.ID == "General.DisableLabelCreation" {
					require.Equal(t, "true", v.Value, name)
					disabled = true
				}
				if v.ID == "Services.RequiredLabels" {
					require.Empty(t, v.Value, name)
					required = true
				}
			}
			require.True(t, disabled)
			require.True(t, required)
			labelDisabledResult(t, h.query(who, `{labelKeys{nodes}}`))
		}
		for i, suffix := range []string{"", ",labels:[]"} {
			r := h.query(h.users[0], fmt.Sprintf(`mutation{createService(input:{name:%q,newEscalationPolicy:{name:%q}%s}){id labels{key value}}}`, name+fmt.Sprint(i), name+fmt.Sprint(i)+" Policy", suffix))
			require.Empty(t, r.Errors, "normal create must ignore dormant RequiredLabels")
		}
		t.Logf("LABEL_CONFIG_CONTROL %s: runtime/public disabled=true required=[]; ordinary create succeeds", name)
	}
	check("default")
	ctx := permission.UserContext(context.Background(), h.admin, permission.RoleAdmin)
	raw := []byte(`{"General":{"DisableLabelCreation":false,"ApplicationName":"Label neighbor"},"Services":{"RequiredLabels":["foo"]}}`)
	_, err := h.app.ConfigStore.SetConfigData(ctx, nil, raw)
	require.NoError(t, err)
	require.NoError(t, h.app.ConfigStore.Reload(ctx))
	check("persisted-false")
	require.Equal(t, "Label neighbor", h.app.ConfigStore.Config().ApplicationName())
	r := h.query(h.admin, `mutation{setConfig(input:[{id:"General.DisableLabelCreation",value:"false"},{id:"Services.RequiredLabels",value:"foo"}])}`)
	require.Empty(t, r.Errors)
	check("admin-setConfig")
	code, _ := h.request(h.admin, "PUT", "/api/v2/config", "application/json", raw)
	require.Equal(t, 204, code)
	check("http-import")
	_, _, stored, err := h.app.ConfigStore.ConfigData(ctx, nil)
	require.NoError(t, err)
	var compatibility config.Config
	require.NoError(t, json.Unmarshal(stored, &compatibility))
	require.False(t, compatibility.General.DisableLabelCreation)
	require.Equal(t, []string{"foo"}, compatibility.Services.RequiredLabels)
	h.stop()
	h.start()
	check("restart")
	h.stop()
	h.cfg.InitialConfig = &compatibility
	h.start()
	check("InitialConfig")
}

func TestLabelProductPolicyDormantRowsAndCreateMatrix(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	targets := seedDormantLabelTargets(t, h)
	count := func(table string) int {
		t.Helper()
		var n int
		require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n))
		return n
	}
	require.Equal(t, 8, count("labels"))
	for i, who := range []string{h.users[0], h.admin, h.users[1]} {
		offset := 0
		if i == 2 {
			offset = 4
		}
		for _, tgt := range targets[offset : offset+4] {
			r := h.query(who, fmt.Sprintf(`{%s(id:%q){id name labels{key value}}}`, tgt.field, tgt.id))
			require.Empty(t, r.Errors)
			var obj struct {
				ID, Name string
				Labels   []any
			}
			require.NoError(t, json.Unmarshal(r.Data[tgt.field], &obj))
			require.Equal(t, tgt.id, obj.ID)
			require.NotEmpty(t, obj.Name)
			require.NotNil(t, obj.Labels)
			require.Empty(t, obj.Labels)
		}
		for _, query := range []string{`{labelKeys{nodes}}`, `{labelValues(input:{key:"policy/key"}){nodes}}`, `{labels{nodes{key}}}`} {
			labelDisabledResult(t, h.query(who, query))
		}
		for _, tgt := range append(append([]dormantLabelTarget{}, targets...), dormantLabelTarget{kind: "service", id: uuid.NewString()}) {
			for _, value := range []string{"create", "update", "dormant", ""} {
				labelDisabledResult(t, h.query(who, fmt.Sprintf(`mutation{setLabel(input:{target:{type:%s,id:%q},key:"policy/key",value:%q})}`, tgt.kind, tgt.id, value)))
			}
		}
	}
	require.Equal(t, 8, count("labels"))
	for _, resource := range []struct{ mutation, table, extra string }{{"createService", "services", fmt.Sprintf(",escalationPolicyID:%q", targets[3].id)}, {"createSchedule", "schedules", `,timeZone:"Etc/UTC"`}, {"createRotation", "rotations", `,description:"Normal rotation",timeZone:"Etc/UTC",type:daily,start:"2026-10-05T00:00:00Z"`}, {"createEscalationPolicy", "escalation_policies", ""}} {
		for _, labels := range []string{"", ",labels:null", ",labels:[]", `,labels:[{key:"policy/key",value:"value"}]`} {
			name := "C5 " + resource.mutation + " " + uuid.NewString()
			before := count(resource.table)
			extra := resource.extra
			if resource.mutation == "createService" {
				extra = fmt.Sprintf(",newEscalationPolicy:{name:%q}", name+" Policy")
			}
			r := h.query(h.users[0], fmt.Sprintf(`mutation{%s(input:{name:%q%s%s}){id name labels{key value}}}`, resource.mutation, name, extra, labels))
			if labels == `,labels:[{key:"policy/key",value:"value"}]` {
				labelDisabledResult(t, r)
				require.Equal(t, before, count(resource.table))
			} else {
				require.Empty(t, r.Errors)
				require.Equal(t, before+1, count(resource.table))
			}
			require.Equal(t, 8, count("labels"))
			t.Logf("LABEL_CREATE_CONTROL %s labels=%q durable-parent-delta=%d", resource.mutation, labels, count(resource.table)-before)
		}
	}
	for _, tgt := range targets[:4] {
		r := h.query(h.users[0], fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q}])}`, tgt.kind, tgt.id))
		require.Empty(t, r.Errors)
		var n int
		require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT count(*) FROM labels WHERE `+tgt.column+`=$1`, tgt.id).Scan(&n))
		require.Zero(t, n, "authorized parent deletion preserves FK cascade cleanup")
	}
	require.Equal(t, 4, count("labels"), "foreign dormant rows remain unchanged")
}

func TestLabelProductPolicySearchAndPostgresLocks(t *testing.T) {
	h := newCalendarPolicyRuntime(t)
	targets := seedDormantLabelTargets(t, h)
	token := uuid.NewString()
	_, err := h.pool.Exec(context.Background(), `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'C5 Key','generic')`, token, targets[0].id)
	require.NoError(t, err)
	// Holding ACCESS EXCLUSIVE independently proves that supported paths do not
	// read or mutate labels: any such SQL would wait until the HTTP timeout.
	tx, err := h.pool.Begin(context.Background())
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(context.Background(), `LOCK TABLE labels IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	for _, query := range []string{`{labelKeys{nodes}}`, `{labelValues(input:{key:"policy/key"}){nodes}}`, `{labels{nodes{key}}}`, fmt.Sprintf(`mutation{setLabel(input:{target:{type:service,id:%q},key:"policy/key",value:""})}`, targets[0].id)} {
		labelDisabledResult(t, h.query(h.users[0], query))
	}
	for _, tgt := range targets[:4] {
		r := h.query(h.users[0], fmt.Sprintf(`{%s(id:%q){id name labels{key value}}}`, tgt.field, tgt.id))
		require.Empty(t, r.Errors)
	}
	for _, predicate := range []string{"policy/key=dormant", "policy/key!=dormant", "policy/key=*", "policy/key!=*", "policy/key=", "policy/key!=", "token=" + token + " policy/key=dormant", "token=" + token + " policy/key!=*"} {
		labelDisabledResult(t, h.query(h.users[0], fmt.Sprintf(`{services(input:{search:%q}){nodes{id}}}`, predicate)))
		for _, state := range []any{service.SearchOptions{Search: predicate, After: service.SearchCursor{Name: "old"}}, map[string]any{"s": predicate, "a": map[string]any{"n": "forged", "f": false}}} {
			cursor, err := search.Cursor(state)
			require.NoError(t, err)
			labelDisabledResult(t, h.query(h.users[0], fmt.Sprintf(`{services(input:{after:%q}){nodes{id}}}`, cursor)))
		}
	}
	r := h.query(h.users[0], fmt.Sprintf(`{services(input:{search:%q}){nodes{id}}}`, "token="+token))
	require.Empty(t, r.Errors)
	require.Contains(t, string(r.Data["services"]), targets[0].id)
	// Put a second authorized Service after the first to require pagination.
	r = h.query(h.users[0], `mutation{createService(input:{name:"ZZ C5 Normal",newEscalationPolicy:{name:"ZZ C5 Normal Policy"}}){id}}`)
	require.Empty(t, r.Errors)
	r = h.query(h.users[0], `{services(input:{first:1}){nodes{id} pageInfo{hasNextPage endCursor}}}`)
	require.Empty(t, r.Errors)
	var conn struct {
		PageInfo struct {
			HasNextPage bool
			EndCursor   string
		}
	}
	require.NoError(t, json.Unmarshal(r.Data["services"], &conn))
	require.True(t, conn.PageInfo.HasNextPage)
	r = h.query(h.users[0], fmt.Sprintf(`{services(input:{after:%q}){nodes{id}}}`, conn.PageInfo.EndCursor))
	require.Empty(t, r.Errors)
	require.Contains(t, string(r.Data["services"]), "id")
	for _, resource := range []string{"createService", "createSchedule", "createRotation", "createEscalationPolicy"} {
		extra := ""
		switch resource {
		case "createSchedule":
			extra = `,timeZone:"Etc/UTC"`
		case "createRotation":
			extra = `,timeZone:"Etc/UTC",type:daily,start:"2026-10-05T00:00:00Z"`
		}
		labelDisabledResult(t, h.query(h.users[0], fmt.Sprintf(`mutation{%s(input:{name:"Locked rejected"%s,labels:[{key:"policy/key",value:"x"}]}){id}}`, resource, extra)))
	}
	require.NoError(t, tx.Rollback(context.Background()))
	t.Log("LABEL_LOCK_CONTROL dedicated/nested/write/create/search/restored/forged/mixed paths completed while labels ACCESS EXCLUSIVE remained held; normal and Integration-Key-only cursors passed")
}
