package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

const servicePlatformAdminSQL = `
INSERT INTO organizations(id,classification,display_name,canonical_name) VALUES
 ({{uuid "org-b"}},'NORMAL','Service B','service.b'),
 ({{uuid "org-c"}},'NORMAL','Service C','service.c');
INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone) VALUES
 ({{uuid "org-b"}},'NORMAL','service:b','Etc/UTC'),
 ({{uuid "org-c"}},'NORMAL','service:c','Etc/UTC');
INSERT INTO users(id,name,email,role) VALUES ({{uuid "user-a"}},'Service Admin','','user');
INSERT INTO escalation_policies(id,organization_id,name) VALUES
 ({{uuid "policy-a"}},{{smokeOrganizationID}},'Policy A'),
 ({{uuid "policy-b"}},{{uuid "org-b"}},'Policy B'),
 ({{uuid "replacement"}},{{uuid "org-b"}},'Replacement B'),
 ({{uuid "policy-c"}},{{uuid "org-c"}},'Policy C');
INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES
 ({{uuid "service-a"}},{{smokeOrganizationID}},{{uuid "policy-a"}},'Service A'),
 ({{uuid "service-b"}},{{uuid "org-b"}},{{uuid "policy-b"}},'Service B'),
 ({{uuid "service-c"}},{{uuid "org-c"}},{{uuid "policy-c"}},'Service C');
INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone)
 VALUES ({{uuid "oncall-rotation"}},{{smokeOrganizationID}},'Home OnCall','daily',now(),1,'Etc/UTC');
INSERT INTO rotation_participants(id,rotation_id,user_id,position)
 VALUES ({{uuid "oncall-participant"}},{{uuid "oncall-rotation"}},{{uuid "user-a"}},0);
`

func servicePlatformAdminHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, servicePlatformAdminSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	for _, suffix := range []string{"b", "c"} {
		var alertID int
		require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic Service state',$2) RETURNING id`, h.UUID("service-"+suffix), "service-pa-"+suffix).Scan(&alertID))
		_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_state(alert_id,escalation_policy_id,service_id,loop_count,force_escalation,escalation_policy_step_number,last_escalation,next_escalation) VALUES($1,$2,$3,7,true,3,now(),now())`, alertID, h.UUID("policy-"+suffix), h.UUID("service-"+suffix))
		require.NoError(t, err)
	}
	return h
}

func servicePlatformAdminContext(t *testing.T, h *harness.Harness) context.Context {
	t.Helper()
	session := uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(h.UUID("user-a"), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	c, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(h.App().DB()))
	require.NoError(t, err)
	ec, err := c.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, ec)
}

// Compare every selected table and every non-target Service/state row. This also
// preserves Home, OrgRole, global User identity and actual OnCall participation.
func servicePlatformAdminOnlyTarget(t *testing.T, before, after map[string]string, serviceID string, stateChanged bool) {
	t.Helper()
	for table, old := range before {
		if table != "services" && (table != "escalation_policy_state" || !stateChanged) {
			require.JSONEq(t, old, after[table], table)
			continue
		}
		rows := func(raw string) []map[string]any {
			var result, all []map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &all))
			key := "id"
			if table == "escalation_policy_state" {
				key = "service_id"
			}
			for _, row := range all {
				if row[key] != serviceID {
					result = append(result, row)
				}
			}
			return result
		}
		require.Equal(t, rows(old), rows(after[table]), table)
	}
}

func TestGraphQLServicePlatformAdminForeignUpdate(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			h := servicePlatformAdminHarness(t)
			ikSetAuthority(t, h, role, true)
			before := serviceManagementSnapshot(t, h)
			expires := h.Now().Add(45 * time.Minute).Truncate(time.Second)
			q := fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Updated foreign Service",description:"Foreign update",maintenanceExpiresAt:%q})}`, h.UUID("service-b"), expires.Format(time.RFC3339))
			r := stepOrganizationQuery(t, h, q)
			require.Empty(t, r.Errors)
			require.JSONEq(t, `{"updateService":true}`, string(r.Data))
			var name, description, org, policy string
			var actual time.Time
			read := func() {
				require.NoError(t, h.App().DB().QueryRow(`SELECT name,description,organization_id,escalation_policy_id,maintenance_expires_at FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&name, &description, &org, &policy, &actual))
			}
			read()
			require.Equal(t, "Updated foreign Service", name)
			require.Equal(t, "Foreign update", description)
			require.Equal(t, h.UUID("org-b"), org)
			require.Equal(t, h.UUID("policy-b"), policy)
			require.Equal(t, expires.Unix(), actual.Unix())
			// An omitted maintenance field must retain the locked persisted value.
			r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Partial update"})}`, h.UUID("service-b")))
			require.Empty(t, r.Errors)
			read()
			require.Equal(t, "Partial update", description)
			require.Equal(t, "Updated foreign Service", name)
			require.Equal(t, h.UUID("org-b"), org)
			require.Equal(t, h.UUID("policy-b"), policy)
			require.Equal(t, expires.Unix(), actual.Unix())
			after := serviceManagementSnapshot(t, h)
			servicePlatformAdminOnlyTarget(t, before, after, h.UUID("service-b"), false)
			// This bounded mutation does not open foreign Query/Search/List access.
			r = stepOrganizationQuery(t, h, fmt.Sprintf(`query{service(id:%q){id name}}`, h.UUID("service-b")))
			require.JSONEq(t, `{"service":null}`, string(r.Data))
			r = stepOrganizationQuery(t, h, `query{services{nodes{id}}}`)
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Data), h.UUID("service-b"))
			require.NotContains(t, string(r.Data), h.UUID("service-c"))
			serviceManagementEvidence(t, "pa-update-"+role, map[string]any{"before": before, "after": after})
		})
	}
}

func TestGraphQLServicePlatformAdminPolicyAndRollback(t *testing.T) {
	h := servicePlatformAdminHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	for _, policy := range []string{h.UUID("policy-a"), h.UUID("policy-c"), h.UUID("missing"), "invalid"} {
		serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Rejected fields",description:"Rejected",escalationPolicyID:%q})}`, h.UUID("service-b"), policy), false)
	}
	for _, c := range []struct {
		id, fields string
		noRows     bool
	}{
		{h.UUID("missing"), `description:"Rejected"`, true},
		{uuid.Nil.String(), `description:"Rejected"`, true},
		{"invalid", `description:"Rejected"`, false},
		{h.UUID("service-b"), `name:"x"`, false},
	} {
		serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,%s})}`, c.id, c.fields), c.noRows)
	}
	q := fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Policy replacement",escalationPolicyID:%q})}`, h.UUID("service-b"), h.UUID("replacement"))
	// Force a failure at COMMIT, after the real EP-change trigger has run.
	_, err := h.App().DB().Exec(`CREATE FUNCTION service_pa_fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'service-pa synthetic commit rejection'; END $$;
	 CREATE CONSTRAINT TRIGGER service_pa_fail_commit AFTER UPDATE ON services DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION service_pa_fail_commit()`)
	require.NoError(t, err)
	wait := h.ExpectBackendError("service-pa synthetic commit rejection")
	serviceManagementRejected(t, h, q, false)
	wait()
	_, err = h.App().DB().Exec(`DROP TRIGGER service_pa_fail_commit ON services; DROP FUNCTION service_pa_fail_commit()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	r := stepOrganizationQuery(t, h, q)
	require.Empty(t, r.Errors)
	var org, policy string
	var loop int
	var force, cleared bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT organization_id,escalation_policy_id FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&org, &policy))
	require.Equal(t, h.UUID("org-b"), org)
	require.Equal(t, h.UUID("replacement"), policy)
	require.NoError(t, h.App().DB().QueryRow(`SELECT escalation_policy_id,loop_count,force_escalation,
	 escalation_policy_step_id IS NULL AND last_escalation IS NULL AND next_escalation IS NULL AND escalation_policy_step_number=0
	 FROM escalation_policy_state WHERE service_id=$1`, h.UUID("service-b")).Scan(&policy, &loop, &force, &cleared))
	require.Equal(t, h.UUID("replacement"), policy)
	require.Zero(t, loop)
	require.False(t, force)
	require.True(t, cleared)
	after := serviceManagementSnapshot(t, h)
	servicePlatformAdminOnlyTarget(t, before, after, h.UUID("service-b"), true)
	serviceManagementEvidence(t, "pa-policy", map[string]any{"before": before, "after": after})
}

func TestGraphQLServicePlatformAdminMaintenancePreservation(t *testing.T) {
	h := servicePlatformAdminHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	expires := h.Now().Add(30 * time.Minute).Truncate(time.Second)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,maintenanceExpiresAt:%q})}`, h.UUID("service-a"), expires.Format(time.RFC3339)))
	require.Empty(t, r.Errors)
	for _, system := range []bool{false, true} {
		before := serviceManagementSnapshot(t, h)
		if system {
			a := &graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore}
			name := "Internal maintenance preserved"
			ok, err := a.Mutation().UpdateService(permission.SystemContext(context.Background(), "Engine"), graphql2.UpdateServiceInput{ID: h.UUID("service-a"), Name: &name})
			require.NoError(t, err)
			require.True(t, ok)
		} else {
			r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Home maintenance preserved"})}`, h.UUID("service-a")))
			require.Empty(t, r.Errors)
		}
		var org string
		var actual time.Time
		require.NoError(t, h.App().DB().QueryRow(`SELECT organization_id,maintenance_expires_at FROM services WHERE id=$1`, h.UUID("service-a")).Scan(&org, &actual))
		require.Equal(t, harness.SmokeOrganizationID, org)
		require.Equal(t, expires.Unix(), actual.Unix())
		servicePlatformAdminOnlyTarget(t, before, serviceManagementSnapshot(t, h), h.UUID("service-a"), false)
	}
}

func TestGraphQLServicePlatformAdminCurrentAndInvalidAuthority(t *testing.T) {
	h := servicePlatformAdminHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	token := h.GraphQLToken(h.UUID("user-a"))
	for _, c := range []struct {
		role string
		pa   bool
	}{{"ORG_MEMBER", true}, {"ORG_MEMBER", false}, {"ORG_ADMIN", false}} {
		ikSetAuthority(t, h, c.role, c.pa)
		before := serviceManagementSnapshot(t, h)
		var wait func()
		if !c.pa && c.role == "ORG_ADMIN" {
			wait = h.ExpectBackendError("sql: no rows in result set")
		}
		r := stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Request-current authority"})}`, h.UUID("service-b"))}, token, false)
		if wait != nil {
			wait()
		}
		if c.pa {
			require.Empty(t, r.Errors)
			var description string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&description))
			require.Equal(t, "Request-current authority", description)
		} else {
			require.NotEmpty(t, r.Errors)
			after := serviceManagementSnapshot(t, h)
			require.Equal(t, before, after, "same signed Session loses PA on the next request")
			serviceManagementEvidence(t, "pa-revoked-"+c.role, map[string]any{"before": before, "after": after, "response": r})
		}
	}
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	valid := servicePlatformAdminContext(t, h)
	r, err := auth.NewRequester(h.UUID("user-a"), uuid.NewString())
	require.NoError(t, err)
	missingEC := auth.WithRequester(permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin, permission.Source(valid)), *auth.RequesterFromContext(valid))
	missingRequester := executioncontext.WithExecutionContext(permission.UserSourceContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin, permission.Source(valid)), *executioncontext.ExecutionContextFromContext(valid))
	a := &graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore, PolicyStore: h.App().EscalationStore}
	for name, ctx := range map[string]context.Context{
		"missing":           context.Background(),
		"bare Admin":        permission.UserContext(context.Background(), h.UUID("user-a"), permission.RoleAdmin),
		"missing EC":        missingEC,
		"invalid EC":        executioncontext.WithExecutionContext(missingEC, executioncontext.ExecutionContext{}),
		"missing Requester": missingRequester,
		"session mismatch":  auth.WithRequester(valid, r),
		"user mismatch":     permission.UserContext(valid, uuid.NewString(), permission.RoleAdmin),
		"PA mismatch":       permission.UserContext(valid, h.UUID("user-a"), permission.RoleUser),
		"Machine":           permission.ServiceContext(valid, h.UUID("service-b")),
		"System over Human": permission.SystemContext(valid, "Test"),
	} {
		t.Run(name, func(t *testing.T) {
			before := serviceManagementSnapshot(t, h)
			description := "Denied"
			ok, err := a.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: h.UUID("service-b"), Description: &description})
			require.False(t, ok)
			require.True(t, permission.IsPermissionError(err))
			after := serviceManagementSnapshot(t, h)
			require.Equal(t, before, after)
			serviceManagementEvidence(t, "pa-identity-"+name, map[string]any{"before": before, "after": after})
		})
	}
	_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	response := stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Missing Home"})}`, h.UUID("service-b"))}, token, false)
	require.NotEmpty(t, response.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
}

func TestGraphQLServicePlatformAdminInconsistentTarget(t *testing.T) {
	h := servicePlatformAdminHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	// Legacy mismatched EP ownership is possible without a same-Org DB FK.
	_, err := h.App().DB().Exec(`UPDATE services SET escalation_policy_id=$2 WHERE id=$1`, h.UUID("service-b"), h.UUID("policy-a"))
	require.NoError(t, err)
	for _, fields := range []string{`description:"Do not preserve corruption"`, fmt.Sprintf(`escalationPolicyID:%q`, h.UUID("replacement"))} {
		serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,%s})}`, h.UUID("service-b"), fields), true)
	}
	// Deliberately corrupt only this disposable test DB to exercise fail-closed
	// classification/missing-Normal controls otherwise prevented by the real FK.
	_, err = h.App().DB().Exec(`ALTER TABLE services DROP CONSTRAINT services_organization_id_fkey;
	 ALTER TABLE escalation_policies DROP CONSTRAINT escalation_policies_organization_id_fkey`)
	require.NoError(t, err)
	for _, org := range []string{organization.DefaultOrganizationID, h.UUID("missing-org"), uuid.Nil.String()} {
		_, err = h.App().DB().Exec(`UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`, h.UUID("policy-b"), org)
		require.NoError(t, err)
		_, err = h.App().DB().Exec(`UPDATE services SET organization_id=$2,escalation_policy_id=$3 WHERE id=$1`, h.UUID("service-b"), org, h.UUID("policy-b"))
		require.NoError(t, err)
		serviceManagementRejected(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Invalid Organization"})}`, h.UUID("service-b")), true)
	}
}

// A real transaction retains both target ownership and the linked policy lock;
// another DB session cannot move either relationship while authorization is used.
func TestServicePlatformAdminTargetLocks(t *testing.T) {
	h := servicePlatformAdminHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	before := serviceManagementSnapshot(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	var blocker int
	var policy string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("replacement")).Scan(&policy))
	done := make(chan struct{})
	var response *stepOrganizationResponse
	defer func() {
		_ = tx.Rollback()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("signed update did not finish after releasing the test blocker")
		}
	}()
	go func() {
		defer close(done)
		response = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"Locked update",escalationPolicyID:%q})}`, h.UUID("service-b"), h.UUID("replacement")))
	}()
	require.Eventually(t, func() bool {
		var n int
		err := h.App().DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&n)
		return err == nil && n == 1
	}, 10*time.Second, 10*time.Millisecond, "update must reach the locked replacement EP after resolving its target")
	for _, probeQuery := range []struct {
		query string
		args  []any
	}{
		{`UPDATE services SET name='Concurrent mutation' WHERE id=$1`, []any{h.UUID("service-b")}},
		{`UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`, []any{h.UUID("policy-b"), harness.SmokeOrganizationID}},
		{`UPDATE organizations SET display_name='Concurrent mutation' WHERE id=$1`, []any{h.UUID("org-b")}},
		{`UPDATE normal_organizations SET iana_time_zone='Etc/UTC' WHERE organization_id=$1`, []any{h.UUID("org-b")}},
	} {
		probe, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = probe.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`)
		require.NoError(t, err)
		_, err = probe.ExecContext(ctx, probeQuery.query, probeQuery.args...)
		rollbackErr := probe.Rollback()
		require.NoError(t, rollbackErr)
		var state interface{ SQLState() string }
		require.ErrorAs(t, err, &state)
		require.Equal(t, "55P03", state.SQLState(), "target relationship must stay locked until update completes")
	}
	require.NoError(t, tx.Rollback())
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("update timed out")
	}
	require.NotNil(t, response)
	require.Empty(t, response.Errors)
	var org, ep, description string
	require.NoError(t, h.App().DB().QueryRow(`SELECT organization_id,escalation_policy_id,description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&org, &ep, &description))
	require.Equal(t, h.UUID("org-b"), org)
	require.Equal(t, h.UUID("replacement"), ep)
	require.Equal(t, "Locked update", description)
	after := serviceManagementSnapshot(t, h)
	servicePlatformAdminOnlyTarget(t, before, after, h.UUID("service-b"), true)
	serviceManagementEvidence(t, "pa-target-locks", map[string]any{"before": before, "after": after, "contended_relationships": 4, "expected_sqlstate": "55P03"})
}
