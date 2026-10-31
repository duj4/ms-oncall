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
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

// These tests use production signed-Session HTTP admission and real PostgreSQL.
// Direct resolver/Store compatibility controls are explicitly separated below.
func serviceManagementSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	r := ikDeleteSnapshot(t, h)
	for _, table := range []string{"alerts", "alert_data", "alert_feedback", "alert_metrics", "alert_logs", "alert_status_subscriptions", "escalation_policy_state", "notification_policy_cycles", "outgoing_messages", "heartbeat_monitors", "labels", "pending_signals"} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+table+` r`).Scan(&rows))
		r[table] = rows
	}
	return r
}

func serviceManagementEvidence(t *testing.T, name string, result any) {
	t.Helper()
	if dir := os.Getenv("SERVICE_MANAGEMENT_EVIDENCE"); dir != "" {
		b, err := json.MarshalIndent(result, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+".json"), append(b, '\n'), 0600))
	}
}

func serviceManagementCount(t *testing.T, h *harness.Harness, table, id string) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM `+table+` WHERE id=$1`, id).Scan(&n))
	return n
}

func serviceManagementDelete(h *harness.Harness, names ...string) string {
	var targets []string
	for _, name := range names {
		targets = append(targets, fmt.Sprintf(`{type:service,id:%q}`, h.UUID(name)))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}

func serviceManagementRejected(t *testing.T, h *harness.Harness, query string, noRows bool) *stepOrganizationResponse {
	t.Helper()
	before := serviceManagementSnapshot(t, h)
	var wait func()
	if noRows {
		wait = h.ExpectBackendError("sql: no rows in result set")
	}
	r := stepOrganizationQuery(t, h, query)
	if wait != nil {
		wait()
	}
	require.NotEmpty(t, r.Errors)
	after := serviceManagementSnapshot(t, h)
	require.Equal(t, before, after, "all selected persisted business rows must match")
	return r
}

func TestGraphQLServiceManagementRoles(t *testing.T) {
	for _, actor := range []struct {
		name, role string
		pa, allow  bool
	}{
		{"OrgMember", "ORG_MEMBER", false, false},
		{"OrgAdmin", "ORG_ADMIN", false, true},
		{"PlatformAdminMember", "ORG_MEMBER", true, true},
		{"PlatformAdminAdmin", "ORG_ADMIN", true, true},
	} {
		t.Run(actor.name, func(t *testing.T) {
			h := integrationKeyOrganizationHarness(t)
			ikSetAuthority(t, h, actor.role, actor.pa)
			results := map[string]any{}
			create := fmt.Sprintf(`mutation{createService(input:{name:%q,escalationPolicyID:%q}){id}}`, "Created "+actor.name, h.UUID("policy-a"))
			update := fmt.Sprintf(`mutation{updateService(input:{id:%q,name:%q,description:"changed",maintenanceExpiresAt:%q})}`, h.UUID("service-a"), "Updated "+actor.name, h.Now().Add(30*time.Minute).Format(time.RFC3339))
			if actor.allow {
				r := stepOrganizationQuery(t, h, create)
				require.Empty(t, r.Errors)
				var d struct{ CreateService struct{ ID string } }
				require.NoError(t, json.Unmarshal(r.Data, &d))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", d.CreateService.ID))
				results["home_create"] = r
				r = stepOrganizationQuery(t, h, update)
				require.Empty(t, r.Errors)
				var name, description string
				var expires time.Time
				require.NoError(t, h.App().DB().QueryRow(`SELECT name,description,maintenance_expires_at FROM services WHERE id=$1`, h.UUID("service-a")).Scan(&name, &description, &expires))
				require.Equal(t, "Updated "+actor.name, name)
				require.Equal(t, "changed", description)
				require.Equal(t, h.Now().Add(30*time.Minute).Unix(), expires.Unix())
				results["home_update"] = r
			} else {
				results["home_create"] = serviceManagementRejected(t, h, create, false)
				results["home_update"] = serviceManagementRejected(t, h, update, false)
			}
			// Create has no Organization input: foreign creation is tested via EP reference.
			results["foreign_create_reference"] = serviceManagementRejected(t, h, fmt.Sprintf(`mutation{createService(input:{name:"Foreign reference",escalationPolicyID:%q}){id}}`, h.UUID("policy-b")), false)
			results["foreign_update"] = serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"foreign"})}`, h.UUID("service-b")), actor.allow)
			results["foreign_delete"] = serviceManagementRejected(t, h, serviceManagementDelete(h, "service-b"), actor.allow)
			if actor.allow {
				r := stepOrganizationQuery(t, h, serviceManagementDelete(h, "service-a"))
				require.Empty(t, r.Errors)
				require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("service-a")))
				results["home_delete"] = r
			} else {
				results["home_delete"] = serviceManagementRejected(t, h, serviceManagementDelete(h, "service-a"), false)
			}
			serviceManagementEvidence(t, "roles-"+actor.name, results)
		})
	}
}

func TestGraphQLServiceManagementMemberNestedAndFields(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	results := map[string]any{}
	initial := serviceManagementSnapshot(t, h)
	for _, c := range []struct{ name, fields string }{
		{"plain", fmt.Sprintf(`escalationPolicyID:%q`, h.UUID("policy-a"))},
		{"policy", `newEscalationPolicy:{name:"Denied EP",steps:[{delayMinutes:1}]}`},
		{"favorite", fmt.Sprintf(`escalationPolicyID:%q,favorite:true`, h.UUID("policy-a"))},
		{"heartbeat", fmt.Sprintf(`escalationPolicyID:%q,newHeartbeatMonitors:[{name:"Denied heartbeat",timeoutMinutes:15}]`, h.UUID("policy-a"))},
		{"traditional_key", fmt.Sprintf(`escalationPolicyID:%q,newIntegrationKeys:[{name:"Denied key",type:generic}]`, h.UUID("policy-a"))},
		{"universal_key", fmt.Sprintf(`escalationPolicyID:%q,newIntegrationKeys:[{name:"Denied UIK",type:universal}]`, h.UUID("policy-a"))},
		{"mixed", `newEscalationPolicy:{name:"Denied mixed EP",favorite:true,steps:[{delayMinutes:1}]},favorite:true,newHeartbeatMonitors:[{name:"Denied heartbeat",timeoutMinutes:15}],newIntegrationKeys:[{name:"Denied key",type:generic}]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			results["create_"+c.name] = serviceManagementRejected(t, h, `mutation{createService(input:{name:"Denied service",`+c.fields+`}){id}}`, false)
		})
	}
	for _, c := range []struct{ name, fields string }{
		{"name", `name:"Denied name"`}, {"description", `description:"Denied description"`},
		{"policy", fmt.Sprintf(`escalationPolicyID:%q`, h.UUID("policy-a"))},
		{"foreign_policy", fmt.Sprintf(`escalationPolicyID:%q`, h.UUID("policy-b"))},
		{"maintenance", fmt.Sprintf(`maintenanceExpiresAt:%q`, h.Now().Add(time.Hour).Format(time.RFC3339))},
	} {
		results["update_"+c.name] = serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,%s})}`, h.UUID("service-a"), c.fields), false)
	}
	require.Equal(t, initial, serviceManagementSnapshot(t, h))
	results["nested_before"] = initial
	results["nested_after"] = serviceManagementSnapshot(t, h)
	roots := ikDeleteRoots(t, h)
	_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'Second Home Service')`, h.UUID("second-home"), harness.SmokeOrganizationID, h.UUID("policy-a"))
	require.NoError(t, err)
	for _, q := range []string{
		serviceManagementDelete(h, "service-a", "second-home"),
		serviceManagementDelete(h, "service-a", "service-b"),
		serviceManagementDelete(h, "service-a", "service-a"),
		serviceManagementDelete(h, "missing"),
		`mutation{deleteAll(input:[` + roots + fmt.Sprintf(`,{type:service,id:%q}])}`, h.UUID("service-a")),
		fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:integrationKey,id:%q}])}`, h.UUID("service-a"), h.UUID("generic-a")),
	} {
		serviceManagementRejected(t, h, q, false)
	}
	serviceManagementEvidence(t, "member-nested-and-fields", results)
}

func TestGraphQLServiceManagementUpdateValidationAndTrigger(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	for _, c := range []struct {
		name, q string
		noRows  bool
	}{
		{"foreign_EP", fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Rejected",escalationPolicyID:%q})}`, h.UUID("service-a"), h.UUID("policy-b")), false},
		{"missing_EP", fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Rejected",escalationPolicyID:%q})}`, h.UUID("service-a"), h.UUID("missing")), false},
		{"missing_Service", fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Rejected"})}`, h.UUID("missing")), true},
		{"invalid_Service", `mutation{updateService(input:{id:"invalid",description:"Rejected"})}`, false},
		{"invalid_name", fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"x"})}`, h.UUID("service-a")), false},
	} {
		t.Run(c.name, func(t *testing.T) { serviceManagementRejected(t, h, c.q, c.noRows) })
	}
	_, err := h.App().DB().Exec(`INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'Replacement')`, h.UUID("replacement"), harness.SmokeOrganizationID)
	require.NoError(t, err)
	var alertID int
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic EP trigger','svcb1-trigger') RETURNING id`, h.UUID("service-a")).Scan(&alertID))
	_, err = h.App().DB().Exec(`INSERT INTO escalation_policy_state(alert_id,escalation_policy_id,service_id,loop_count,force_escalation,escalation_policy_step_number,last_escalation,next_escalation) VALUES($1,$2,$3,7,true,3,now(),now())`, alertID, h.UUID("policy-a"), h.UUID("service-a"))
	require.NoError(t, err)
	// Member cannot invoke the EP-change trigger or persist any partial fields.
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	q := fmt.Sprintf(`mutation{updateService(input:{id:%q,escalationPolicyID:%q,name:"Replacement name",description:"replacement"})}`, h.UUID("service-a"), h.UUID("replacement"))
	serviceManagementRejected(t, h, q, false)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	r := stepOrganizationQuery(t, h, q)
	require.Empty(t, r.Errors)
	var loopCount int
	var force, cleared bool
	var policy string
	require.NoError(t, h.App().DB().QueryRow(`SELECT escalation_policy_id,loop_count,force_escalation,
		escalation_policy_step_id IS NULL AND last_escalation IS NULL AND next_escalation IS NULL AND escalation_policy_step_number=0
		FROM escalation_policy_state WHERE alert_id=$1`, alertID).Scan(&policy, &loopCount, &force, &cleared))
	require.Equal(t, h.UUID("replacement"), policy)
	require.Zero(t, loopCount)
	require.False(t, force)
	require.True(t, cleared, "authorized EP replacement resets the existing state row")
	require.NoError(t, h.App().DB().QueryRow(`SELECT escalation_policy_id FROM services WHERE id=$1`, h.UUID("service-a")).Scan(&policy))
	require.Equal(t, h.UUID("replacement"), policy)
}

func serviceManagementIncoming(t *testing.T, h *harness.Harness) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/v2/generic/incoming", bytes.NewBufferString(`{"summary":"SVC-B1 synthetic alert","details":"isolated security regression"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.UUID("generic-a"))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode
}

func TestGraphQLServiceManagementCascade(t *testing.T) {
	for _, actor := range []struct {
		name, role string
		pa, allow  bool
	}{{"Member", "ORG_MEMBER", false, false}, {"OrgAdmin", "ORG_ADMIN", false, true}, {"PlatformAdmin", "ORG_MEMBER", true, true}} {
		t.Run(actor.name, func(t *testing.T) {
			h := integrationKeyOrganizationHarness(t)
			ikSetAuthority(t, h, actor.role, actor.pa)
			require.Equal(t, http.StatusNoContent, serviceManagementIncoming(t, h))
			_, err := h.App().DB().Exec(`INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'Synthetic heartbeat',interval '5 minutes')`, h.UUID("heartbeat"), h.UUID("service-a"))
			require.NoError(t, err)
			_, err = h.App().DB().Exec(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2)`, h.UUID("user-a"), h.UUID("service-a"))
			require.NoError(t, err)
			before := serviceManagementSnapshot(t, h)
			if !actor.allow {
				serviceManagementRejected(t, h, ikDeleteQuery(h, "generic-a"), false)
				serviceManagementRejected(t, h, serviceManagementDelete(h, "service-a"), false)
			} else {
				r := stepOrganizationQuery(t, h, serviceManagementDelete(h, "service-a"))
				require.Empty(t, r.Errors)
			}
			after := serviceManagementSnapshot(t, h)
			for _, c := range []struct{ table, name string }{{"services", "service-a"}, {"integration_keys", "generic-a"}, {"uik_config", "universal-a"}, {"heartbeat_monitors", "heartbeat"}} {
				want := 1
				if actor.allow {
					want = 0
				}
				require.Equal(t, want, serviceManagementCount(t, h, c.table, h.UUID(c.name)), c.table)
			}
			if !actor.allow {
				require.Equal(t, before, after, "denial retains active Alert/data, UIK, Key, Heartbeat and Favorite")
			} else {
				for _, table := range []string{"alerts", "alert_data", "user_favorites"} {
					require.JSONEq(t, `[]`, after[table], table)
				}
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
			require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", h.UUID("generic-b")))
			status := serviceManagementIncoming(t, h)
			want := http.StatusNoContent
			if actor.allow {
				want = http.StatusUnauthorized
			}
			require.Equal(t, want, status)
			serviceManagementEvidence(t, "cascade-"+actor.name, map[string]any{"before": before, "after": after, "http_before": 204, "http_after": status})
		})
	}
}

func TestGraphQLServiceManagementDeleteTransactions(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	roots := ikDeleteRoots(t, h)
	_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'Shared policy survivor')`, h.UUID("survivor"), harness.SmokeOrganizationID, h.UUID("policy-a"))
	require.NoError(t, err)
	for _, c := range []struct {
		name, targets string
		noRows        bool
	}{
		{"foreign_batch", fmt.Sprintf(`{type:service,id:%q},{type:service,id:%q}`, h.UUID("service-a"), h.UUID("service-b")), true},
		{"missing_batch", fmt.Sprintf(`{type:service,id:%q},{type:service,id:%q}`, h.UUID("service-a"), h.UUID("missing")), true},
		{"earlier_roots_later_service", roots + fmt.Sprintf(`,{type:service,id:%q}`, h.UUID("service-b")), true},
		{"earlier_key_later_service", fmt.Sprintf(`{type:service,id:%q},{type:integrationKey,id:%q}`, h.UUID("service-b"), h.UUID("generic-a")), true},
		{"earlier_rotation_failure", fmt.Sprintf(`{type:rotation,id:%q},{type:service,id:%q}`, h.UUID("missing"), h.UUID("service-a")), true},
		{"earlier_schedule_failure", fmt.Sprintf(`{type:rotation,id:%q},{type:schedule,id:%q},{type:service,id:%q}`, h.UUID("delete-rotation"), h.UUID("missing"), h.UUID("service-a")), true},
		{"earlier_key_failure", roots + fmt.Sprintf(`,{type:integrationKey,id:%q},{type:service,id:%q}`, h.UUID("generic-b"), h.UUID("service-a")), false},
		{"later_policy_FK_failure", fmt.Sprintf(`{type:integrationKey,id:%q},{type:service,id:%q},{type:escalationPolicy,id:%q}`, h.UUID("generic-a"), h.UUID("service-a"), h.UUID("policy-a")), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := serviceManagementSnapshot(t, h)
			r := serviceManagementRejected(t, h, `mutation{deleteAll(input:[`+c.targets+`])}`, c.noRows)
			serviceManagementEvidence(t, "transaction-"+c.name, map[string]any{"before": before, "after": serviceManagementSnapshot(t, h), "response": r})
		})
	}
	var targets []string
	for range 51 {
		targets = append(targets, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-a")))
	}
	serviceManagementRejected(t, h, `mutation{deleteAll(input:[`+strings.Join(targets, ",")+`])}`, false)
	// Duplicate targets retain complete-set deduplication and mixed-group success.
	r := stepOrganizationQuery(t, h, `mutation{deleteAll(input:[`+roots+fmt.Sprintf(`,{type:integrationKey,id:%q},{type:service,id:%q},{type:service,id:%q}])}`, h.UUID("generic-a"), h.UUID("service-a"), h.UUID("service-a")))
	require.Empty(t, r.Errors)
	for _, c := range []struct{ table, name string }{{"services", "service-a"}, {"rotations", "delete-rotation"}, {"schedules", "delete-schedule"}, {"integration_keys", "generic-a"}} {
		require.Zero(t, serviceManagementCount(t, h, c.table, h.UUID(c.name)), c.table)
	}
}

func TestGraphQLServiceManagementCurrentAuthority(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	token := h.GraphQLToken(h.UUID("user-a"))
	for _, c := range []struct {
		name, role string
		pa, allow  bool
	}{{"OrgAdmin", "ORG_ADMIN", false, true}, {"downgraded", "ORG_MEMBER", false, false}, {"PlatformAdmin", "ORG_MEMBER", true, true}, {"PA_revoked", "ORG_MEMBER", false, false}} {
		ikSetAuthority(t, h, c.role, c.pa)
		before := serviceManagementSnapshot(t, h)
		q := fmt.Sprintf(`mutation{updateService(input:{id:%q,description:%q})}`, h.UUID("service-a"), c.name)
		r := stepOrganizationPost(t, h, map[string]any{"query": q}, token, false)
		if c.allow {
			require.Empty(t, r.Errors)
		} else {
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, serviceManagementSnapshot(t, h))
			for _, q := range []string{serviceManagementDelete(h, "service-a"), fmt.Sprintf(`mutation{createService(input:{name:"After revocation",escalationPolicyID:%q}){id}}`, h.UUID("policy-a"))} {
				r = stepOrganizationPost(t, h, map[string]any{"query": q}, token, false)
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, serviceManagementSnapshot(t, h))
			}
		}
	}
	// Revoke the Normal Home assignment; PA alone must not repair missing Home.
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	_, err := h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	for _, q := range []string{serviceManagementDelete(h, "service-a"), fmt.Sprintf(`mutation{updateService(input:{id:%q})}`, h.UUID("service-a")), fmt.Sprintf(`mutation{createService(input:{name:"Missing Home",escalationPolicyID:%q}){id}}`, h.UUID("policy-a"))} {
		r := stepOrganizationPost(t, h, map[string]any{"query": q}, token, false)
		require.NotEmpty(t, r.Errors)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
	}
}

func TestServiceManagementInternalAndHTTPIdentity(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	a := &graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore}
	valid := integrationKeyOrganizationContext(t, h)
	other, err := auth.NewRequester(h.UUID("user-a"), uuid.NewString())
	require.NoError(t, err)
	for name, ctx := range map[string]context.Context{
		"missing":              context.Background(),
		"legacy_User":          permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleUser),
		"legacy_Admin":         permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin),
		"mismatched_Requester": auth.WithRequester(valid, other),
		"Machine":              permission.ServiceContext(context.Background(), h.UUID("service-a")),
	} {
		t.Run(name, func(t *testing.T) {
			before := serviceManagementSnapshot(t, h)
			_, err := a.Mutation().CreateService(ctx, graphql2.CreateServiceInput{Name: "Denied"})
			require.True(t, permission.IsPermissionError(err))
			_, err = a.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: h.UUID("service-a")})
			require.True(t, permission.IsPermissionError(err))
			_, err = a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: h.UUID("service-a")}})
			require.True(t, permission.IsPermissionError(err))
			require.Equal(t, before, serviceManagementSnapshot(t, h))
		})
	}
	// Direct Store trust is intentionally unchanged and is not HTTP RBAC evidence.
	legacy := permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleUser)
	svc, err := h.App().ServiceStore.CreateServiceTx(legacy, nil, &service.Service{OrganizationID: uuid.MustParse(h.UUID("org-b")), Name: "Internal legacy", EscalationPolicyID: h.UUID("policy-b")})
	require.NoError(t, err)
	require.NoError(t, h.App().ServiceStore.DeleteManyTx(legacy, nil, []string{svc.ID}, nil))
	sys := permission.SystemContext(context.Background(), "Engine")
	svc, err = h.App().ServiceStore.CreateServiceTx(sys, nil, &service.Service{OrganizationID: uuid.MustParse(h.UUID("org-b")), Name: "Internal System", EscalationPolicyID: h.UUID("policy-b")})
	require.NoError(t, err)
	_, err = a.Mutation().UpdateService(sys, graphql2.UpdateServiceInput{ID: svc.ID})
	require.NoError(t, err)
	ok, err := a.Mutation().DeleteAll(sys, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: svc.ID}})
	require.NoError(t, err)
	require.True(t, ok)
	_, err = a.Mutation().CreateService(sys, graphql2.CreateServiceInput{Name: "System resolver"})
	require.True(t, permission.IsPermissionError(err))
	for _, credential := range []string{"", "Bearer ey.synthetic.invalid", "Bearer " + h.UUID("generic-a")} {
		before := serviceManagementSnapshot(t, h)
		body, err := json.Marshal(map[string]string{"query": serviceManagementDelete(h, "service-a")})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", credential)
		req.Header.Set("X-Role", "PlatformAdmin")
		req.Header.Set("X-Organization-ID", h.UUID("org-b"))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
	}
}
