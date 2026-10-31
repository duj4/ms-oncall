package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func ikDeleteQuery(h *harness.Harness, keys ...string) string {
	var targets []string
	for _, key := range keys {
		targets = append(targets, fmt.Sprintf(`{type:integrationKey,id:%q}`, h.UUID(key)))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}

func ikDeleteSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := ikAuthorizationSnapshot(t, h)
	for table, rows := range stepOrganizationSnapshot(t, h) {
		result[table] = rows
	}
	for _, table := range []string{"organizations", "normal_organizations", "users", "user_organization_assignments"} {
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+table+` r`).Scan(&rows))
		result[table] = rows
	}
	return result
}

func ikDeleteRoots(t *testing.T, h *harness.Harness) string {
	t.Helper()
	_, err := h.App().DB().Exec(`INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'Delete schedule','Etc/UTC')`, h.UUID("delete-schedule"), harness.SmokeOrganizationID)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone) VALUES($1,$2,'Delete rotation','daily',now(),1,'Etc/UTC')`, h.UUID("delete-rotation"), harness.SmokeOrganizationID)
	require.NoError(t, err)
	return fmt.Sprintf(`{type:rotation,id:%q},{type:schedule,id:%q}`, h.UUID("delete-rotation"), h.UUID("delete-schedule"))
}

func ikDeleteDeniedUnchanged(t *testing.T, h *harness.Harness, query string) *stepOrganizationResponse {
	t.Helper()
	before := ikDeleteSnapshot(t, h)
	response := stepOrganizationQuery(t, h, query)
	require.NotEmpty(t, response.Errors)
	require.Contains(t, response.Errors[0].Message, "access denied")
	require.Equal(t, before, ikDeleteSnapshot(t, h), "exact persisted business rows must remain unchanged")
	for _, key := range []string{"generic-a", "generic-b", "universal-a", "universal-b"} {
		require.NotContains(t, response.Errors[0].Message, h.UUID(key))
	}
	return response
}

func TestGraphQLIntegrationKeyDeleteMember(t *testing.T) {
	h := ikAuthorizationHarness(t)
	roots := ikDeleteRoots(t, h)
	var first *stepOrganizationResponse
	for _, key := range []string{"generic-a", "generic-b", "missing", "universal-a", "universal-b"} {
		t.Run(key, func(t *testing.T) {
			response := ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, key))
			if first == nil {
				first = response
			} else {
				require.Equal(t, first, response, "no target existence or type disclosure")
			}
		})
	}
	for _, query := range []string{
		ikDeleteQuery(h, "generic-a", "generic-b"),
		fmt.Sprintf(`mutation{deleteAll(input:[%s,{type:integrationKey,id:%q}])}`, roots, h.UUID("generic-a")),
		fmt.Sprintf(`mutation{alias:deleteAll(input:[{type:integrationKey,id:%q}])}`, h.UUID("generic-a")),
		`mutation{deleteAll(input:[{type:integrationKey,id:"invalid"}])}`,
		`mutation{deleteAll(input:[{type:integrationKey,id:"00000000-0000-0000-0000-000000000000"}])}`,
	} {
		ikDeleteDeniedUnchanged(t, h, query)
	}
	before := ikDeleteSnapshot(t, h)
	response := stepOrganizationPost(t, h, map[string]any{
		"query":     `mutation($targets:[TargetInput!]!){alias:deleteAll(input:$targets)}`,
		"variables": map[string]any{"targets": []map[string]string{{"type": "integrationKey", "id": h.UUID("generic-a")}}},
	}, h.GraphQLToken(h.UUID("user-a")), false)
	require.NotEmpty(t, response.Errors)
	require.Contains(t, response.Errors[0].Message, "access denied")
	require.Equal(t, before, ikDeleteSnapshot(t, h))
}

func TestGraphQLIntegrationKeyDeleteOrgAdmin(t *testing.T) {
	h := ikAuthorizationHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	roots := ikDeleteRoots(t, h)
	for _, keys := range [][]string{{"generic-b"}, {"missing"}, {"generic-a", "generic-b"}, {"generic-a", "missing"}, {"universal-a", "universal-b"}} {
		ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, keys...))
	}
	ikDeleteDeniedUnchanged(t, h, fmt.Sprintf(`mutation{deleteAll(input:[%s,{type:integrationKey,id:%q}])}`, roots, h.UUID("generic-b")))
	keys := []string{"generic-a", "generic-a", "grafana-a", "site24x7-a", "prometheusAlertmanager-a", "email-a", "universal-a"}
	response := stepOrganizationQuery(t, h, ikDeleteQuery(h, keys...))
	require.Empty(t, response.Errors)
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys WHERE service_id=$1`, h.UUID("service-a")).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM uik_config WHERE id=$1`, h.UUID("universal-a")).Scan(&count))
	require.Zero(t, count, "existing UIK config cascade retained")
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys WHERE service_id=$1`, h.UUID("service-b")).Scan(&count))
	require.Equal(t, 6, count)
	// Missing and already deleted Human targets continue to fail closed.
	ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-a"))
}

func TestGraphQLIntegrationKeyDeletePlatformAdmin(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			h := ikAuthorizationHarness(t)
			ikSetAuthority(t, h, role, true)
			var memberships int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM user_organization_assignments WHERE user_id=$1 AND effective_organization_id=$2`, h.UUID("user-a"), h.UUID("org-b")).Scan(&memberships))
			require.Zero(t, memberships)
			for _, keys := range [][]string{{"generic-b", "missing"}, {"generic-a", "universal-b"}, {"generic-b", "universal-b"}} {
				ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, keys...))
			}
			for _, invalid := range []string{"invalid", "00000000-0000-0000-0000-000000000000"} {
				before := ikDeleteSnapshot(t, h)
				response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{deleteAll(input:[{type:integrationKey,id:%q},{type:integrationKey,id:%q}])}`, h.UUID("generic-b"), invalid))
				require.NotEmpty(t, response.Errors)
				require.Equal(t, before, ikDeleteSnapshot(t, h))
			}
			roots := ikDeleteRoots(t, h)
			ikDeleteDeniedUnchanged(t, h, fmt.Sprintf(`mutation{deleteAll(input:[%s,{type:integrationKey,id:%q},{type:integrationKey,id:%q}])}`, roots, h.UUID("generic-b"), h.UUID("missing")))
			keys := []string{"generic-b", "generic-b", "universal-a"}
			for _, kind := range ikCredentialTypes {
				keys = append(keys, kind+"-a", kind+"-b")
			}
			response := stepOrganizationQuery(t, h, ikDeleteQuery(h, keys...))
			require.Empty(t, response.Errors)
			var remaining int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys`).Scan(&remaining))
			require.Equal(t, 1, remaining)
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys WHERE id=$1`, h.UUID("universal-b")).Scan(&remaining))
			require.Equal(t, 1, remaining)
		})
	}
}

func TestGraphQLIntegrationKeyDeleteInvalidRelationships(t *testing.T) {
	h := ikAuthorizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	// Intentionally corrupt fixtures only in this Harness-owned disposable DB.
	// No production schema or migration changes are needed or made.
	_, err := h.App().DB().Exec(`ALTER TABLE services DROP CONSTRAINT services_organization_id_fkey`)
	require.NoError(t, err)
	for _, org := range []string{organization.DefaultOrganizationID, h.UUID("absent-org"), "00000000-0000-0000-0000-000000000000"} {
		_, err = h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,$4)`, h.UUID("service-"+org), org, h.UUID("policy-a"), "Invalid parent "+org)
		require.NoError(t, err)
		_, err = h.App().DB().Exec(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'Invalid key','generic')`, h.UUID("key-"+org), h.UUID("service-"+org))
		require.NoError(t, err)
		ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-b", "key-"+org))
	}
	// A Key ID cannot substitute for a Service or Organization ID.
	for _, key := range []string{"service-a", "org-b"} {
		ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-b", key))
	}
	// The owning Service decides scope, even when its Policy belongs elsewhere.
	_, err = h.App().DB().Exec(`UPDATE services SET escalation_policy_id=$1 WHERE id=$2`, h.UUID("policy-a"), h.UUID("service-b"))
	require.NoError(t, err)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-b"))
}

func TestGraphQLIntegrationKeyDeleteCurrentAuthority(t *testing.T) {
	h := ikAuthorizationHarness(t)
	token := h.GraphQLToken(h.UUID("user-a"))
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	response := stepOrganizationPost(t, h, map[string]any{"query": ikDeleteQuery(h, "grafana-b")}, token, false)
	require.Empty(t, response.Errors)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-b"))
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	response = stepOrganizationPost(t, h, map[string]any{"query": ikDeleteQuery(h, "grafana-a")}, token, false)
	require.Empty(t, response.Errors)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	ikDeleteDeniedUnchanged(t, h, ikDeleteQuery(h, "generic-a"))
}

func TestGraphQLIntegrationKeyDeleteRollbackAfterKeyGroups(t *testing.T) {
	h := ikAuthorizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	roots := ikDeleteRoots(t, h)
	before := ikDeleteSnapshot(t, h)
	// Service is a later DeleteAll group and retains its existing Home scope.
	// Its failure must roll back both earlier root groups and both Key groups.
	wait := h.ExpectBackendError("sql: no rows in result set")
	response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{deleteAll(input:[%s,{type:integrationKey,id:%q},{type:integrationKey,id:%q},{type:service,id:%q}])}`, roots, h.UUID("generic-a"), h.UUID("generic-b"), h.UUID("service-b")))
	wait()
	require.NotEmpty(t, response.Errors)
	require.Equal(t, before, ikDeleteSnapshot(t, h))
	// The same earlier groups and multi-Org Keys succeed together when the
	// unrelated later unauthorized Service is absent.
	response = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{deleteAll(input:[%s,{type:integrationKey,id:%q},{type:integrationKey,id:%q}])}`, roots, h.UUID("generic-a"), h.UUID("generic-b")))
	require.Empty(t, response.Errors)
	var remaining int
	require.NoError(t, h.App().DB().QueryRow(`SELECT (SELECT count(*) FROM schedules WHERE id=$1)+(SELECT count(*) FROM rotations WHERE id=$2)+(SELECT count(*) FROM integration_keys WHERE id IN ($3,$4))`, h.UUID("delete-schedule"), h.UUID("delete-rotation"), h.UUID("generic-a"), h.UUID("generic-b")).Scan(&remaining))
	require.Zero(t, remaining)
}

func TestGraphQLIntegrationKeyDeleteConcurrentTypeChange(t *testing.T) {
	h := ikAuthorizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	locker, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = locker.Rollback() }()
	var pid int
	require.NoError(t, locker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	_, err = locker.ExecContext(ctx, `UPDATE integration_keys SET type='universal' WHERE id=$1`, h.UUID("generic-b"))
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"query": ikDeleteQuery(h, "generic-b")})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(h.UUID("user-a"))})
	type result struct {
		response stepOrganizationResponse
		err      error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		var r result
		r.err = json.NewDecoder(resp.Body).Decode(&r.response)
		done <- r
	}()
	// Observe a real PostgreSQL row-lock wait, rather than assuming that a
	// goroutine start barrier demonstrates the intended execution interleaving.
	require.Eventually(t, func() bool {
		var blocked bool
		err := h.App().DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, locker.Commit())
	var outcome result
	select {
	case outcome = <-done:
	case <-ctx.Done():
		t.Fatal("concurrent delete did not finish")
	}
	require.NoError(t, outcome.err)
	require.NotEmpty(t, outcome.response.Errors)
	require.Contains(t, outcome.response.Errors[0].Message, "access denied")
	var kind string
	require.NoError(t, h.App().DB().QueryRow(`SELECT type FROM integration_keys WHERE id=$1`, h.UUID("generic-b")).Scan(&kind))
	require.Equal(t, "universal", kind, "concurrently changed foreign UIK must survive")
}

func TestGraphQLIntegrationKeyDeleteCompatibility(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	roots := ikDeleteRoots(t, h)
	response := stepOrganizationQuery(t, h, `mutation{deleteAll(input:[`+roots+`])}`)
	require.Empty(t, response.Errors, "authorized non-Key DeleteAll remains unchanged")
	// Only this previously verified System context keeps nil-scope compatibility,
	// including duplicates, missing IDs and an existing foreign UIK.
	ctx := permission.SystemContext(context.Background(), "Engine")
	app := integrationKeyOrganizationApp(h)
	ok, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{
		{Type: assignment.TargetTypeIntegrationKey, ID: h.UUID("generic-a")},
		{Type: assignment.TargetTypeIntegrationKey, ID: h.UUID("universal-b")},
		{Type: assignment.TargetTypeIntegrationKey, ID: h.UUID("generic-a")},
		{Type: assignment.TargetTypeIntegrationKey, ID: h.UUID("missing")},
	})
	require.NoError(t, err)
	require.True(t, ok)
	var remaining int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys WHERE id IN ($1,$2)`, h.UUID("generic-a"), h.UUID("universal-b")).Scan(&remaining))
	require.Zero(t, remaining)
}

// SVC-B1 closes the Member parent-Service bypass independently of explicit IK-D1.
// Eligible Home management still has the existing database cascade consequences.
func TestGraphQLIntegrationKeyDeleteParentCascadeDependency(t *testing.T) {
	h := integrationKeyOrganizationHarness(t)
	before := ikDeleteSnapshot(t, h)
	response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q}])}`, h.UUID("service-a")))
	require.NotEmpty(t, response.Errors)
	require.Equal(t, before, ikDeleteSnapshot(t, h))
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	response = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q}])}`, h.UUID("service-a")))
	require.Empty(t, response.Errors)
	var remaining int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_keys WHERE service_id=$1`, h.UUID("service-a")).Scan(&remaining))
	require.Zero(t, remaining, "authorized Home Service deletion retains database cascades")
}
