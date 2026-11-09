package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
)

// Use a separate signed Session to reach the database concurrently without
// changing the production per-auth-source concurrency limiter.
func serviceDeleteF1SecondRequest(t *testing.T, ctx context.Context, h *harness.Harness, wg *sync.WaitGroup, query string) <-chan lc1HTTPResult {
	t.Helper()
	token, err := h.App().AuthHandler.CreateSession(ctx, "F1 second Human session", h.UUID("user-a"))
	require.NoError(t, err)
	encoded, err := token.Encode(h.App().SessionKeyring.Sign)
	require.NoError(t, err)
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: encoded})
	done := make(chan lc1HTTPResult, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var result lc1HTTPResult
		resp, err := http.DefaultClient.Do(req)
		result.err = err
		if err == nil {
			defer resp.Body.Close()
			result.status = resp.StatusCode
			result.err = json.NewDecoder(resp.Body).Decode(&result.response)
		}
		done <- result
	}()
	return done
}

// Evidence failures are diagnostic only: keep the original require failure and
// print a second copy even when the optional artifact destination cannot write.
func serviceDeleteF1SaveEvidence(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Logf("F1 EVIDENCE FAILURE (%s): %v", name, err)
		return
	}
	t.Logf("F1 EVIDENCE %s: %s", name, data)
	if dir := os.Getenv("SERVICE_MANAGEMENT_EVIDENCE"); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), append(data, '\n'), 0600); err != nil {
			t.Logf("F1 EVIDENCE FAILURE (%s): %v", name, err)
		}
	}
}

func serviceDeleteF1HTTPReceipt(result lc1HTTPResult) map[string]any {
	receipt := map[string]any{"http_status": result.status, "http_response_observed": result.status != 0,
		"graphql": result.response, "transport_error": nil, "decode_error": nil}
	if result.err != nil {
		field := "decode_error"
		if result.status == 0 {
			field = "transport_error"
		}
		receipt[field] = result.err.Error()
	}
	return receipt
}

// Each read has its own bounded, read-only transaction and does not share the
// request context, connections or business transaction. No fatal assertions.
func serviceDeleteF1ReadEvidence(db *sql.DB, query string) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := map[string]any{"status": "NOT VERIFIED"}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			result["rollback_error"] = err.Error()
		}
	}()
	// A Base database must not fail merely because the SD1 table is absent.
	if query == "audit" {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass('service_delete_audit_events') IS NOT NULL`).Scan(&exists); err != nil {
			result["error"] = err.Error()
			return result
		}
		if !exists {
			result["status"] = "N/A — Base has no SD1 table"
			return result
		}
		query = `SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id),'[]'::jsonb)::text FROM service_delete_audit_events e`
	}
	var rows string
	if err := tx.QueryRowContext(ctx, query).Scan(&rows); err != nil {
		result["error"] = err.Error()
		return result
	}
	result["status"], result["rows"] = "CAPTURED", json.RawMessage(rows)
	return result
}

func serviceDeleteF1TerminalEvidence(t *testing.T, h *harness.Harness, before map[string]string, t3Reached bool, insertedEvidence <-chan error) {
	t.Helper()
	t3 := map[string]any{"status": "NOT VERIFIED", "reason": "original T3 receive/assertion point was not reached"}
	if t3Reached {
		select {
		case err := <-insertedEvidence:
			t3 = map[string]any{"status": "CAPTURED", "error": nil, "sqlstate": nil}
			if err != nil {
				t3["error"] = err.Error()
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					t3["sqlstate"], t3["constraint"] = pgErr.Code, pgErr.ConstraintName
				}
			}
		default:
			t3["reason"] = "T3 result copy unavailable; no additional wait or receive"
		}
	}
	// Use exactly the existing business snapshot's table set. These names come
	// from test helpers, never HTTP input; quote both SQL literals and identifiers.
	tables := make([]string, 0, len(before))
	for table := range before {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var fields []string
	for _, table := range tables {
		fields = append(fields, "'"+strings.ReplaceAll(table, "'", "''")+"', (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM \""+strings.ReplaceAll(table, `"`, `""`)+"\" r)")
	}
	fields = append(fields, `'service_fk_constraints', (SELECT coalesce(jsonb_agg(jsonb_build_object('name',conname,'validated',convalidated,'definition',pg_get_constraintdef(oid)) ORDER BY conname),'[]'::jsonb) FROM pg_constraint WHERE contype='f' AND (conrelid='services'::regclass OR confrelid='services'::regclass))`)
	serviceDeleteF1SaveEvidence(t, "f1-concurrent-terminal", map[string]any{
		"test": t.Name(), "test_failed_at_capture": t.Failed(), "before": before,
		"business": serviceDeleteF1ReadEvidence(h.App().DB(), "SELECT jsonb_build_object("+strings.Join(fields, ",")+")::text"),
		"audit":    serviceDeleteF1ReadEvidence(h.App().DB(), "audit"), "T3": t3,
		"fixture_ids": map[string]string{"service_a": h.UUID("service-a"), "service_b": h.UUID("service-b"), "late_heartbeat": h.UUID("late-heartbeat")},
	})
}

// F1 exercises signed Human sessions through the real HTTP admission and
// GraphQL handler. Persisted rows, rather than HTTP status alone, are the oracle.
func TestGraphQLServiceDeleteF1Roles(t *testing.T) {
	t.Parallel()
	for _, actor := range []struct {
		name, role        string
		pa, home, foreign bool
	}{
		{"PAHomeMember", "ORG_MEMBER", true, true, true},
		{"PAHomeAdmin", "ORG_ADMIN", true, true, true},
		{"OrgAdmin", "ORG_ADMIN", false, true, false},
		{"OrgMember", "ORG_MEMBER", false, false, false},
		{"Default", "", false, false, false},
		{"DefaultPA", "", true, false, false},
	} {
		for _, target := range []string{"service-a", "service-b"} {
			t.Run(actor.name+"/"+target, func(t *testing.T) {
				t.Parallel()
				h := integrationKeyOrganizationHarness(t)
				role := actor.role
				if role == "" {
					role = "ORG_MEMBER"
				}
				ikSetAuthority(t, h, role, actor.pa)
				if actor.role == "" {
					_, err := h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
					require.NoError(t, err)
				}
				allow := actor.home
				if target == "service-b" {
					allow = actor.foreign
				}
				if !allow {
					serviceManagementRejected(t, h, serviceManagementDelete(h, target), actor.name == "OrgAdmin")
					return
				}
				// Exercise real cascades, including active Alert state and UIK.
				_, err := h.App().DB().Exec(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'F1 synthetic cascade','f1-cascade')`, h.UUID(target))
				require.NoError(t, err)
				_, err = h.App().DB().Exec(`INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'F1 heartbeat',interval '5 minutes')`, h.UUID("f1-heartbeat"), h.UUID(target))
				require.NoError(t, err)
				before := serviceManagementSnapshot(t, h)
				r := stepOrganizationQuery(t, h, serviceManagementDelete(h, target))
				require.Empty(t, r.Errors)
				after := serviceManagementSnapshot(t, h)
				require.Zero(t, serviceManagementCount(t, h, "services", h.UUID(target)))
				require.JSONEq(t, `[]`, after["alerts"])
				require.JSONEq(t, `[]`, after["heartbeat_monitors"])
				suffix, other := "a", "b"
				if target == "service-b" {
					suffix, other = "b", "a"
				}
				for _, table := range []string{"integration_keys", "uik_config"} {
					require.Zero(t, serviceManagementCount(t, h, table, h.UUID("universal-"+suffix)))
					require.Equal(t, 1, serviceManagementCount(t, h, table, h.UUID("universal-"+other)))
				}
				require.Zero(t, serviceManagementCount(t, h, "integration_keys", h.UUID("generic-"+suffix)))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-"+other)))
				for table := range before {
					switch table {
					case "services", "integration_keys", "uik_config", "alerts", "alert_logs", "alert_metrics", "heartbeat_monitors":
					default:
						require.Equal(t, before[table], after[table], table)
					}
				}
				serviceManagementEvidence(t, "f1-role-"+actor.name+"-"+target, map[string]any{"before": before, "after": after, "response": r})
			})
		}
	}
}

func TestGraphQLServiceDeleteF1CompleteSet(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	for _, c := range []struct {
		name, query string
		noRows      bool
	}{
		{"home_foreign", serviceManagementDelete(h, "service-a", "service-b"), true},
		{"foreign_missing", serviceManagementDelete(h, "service-b", "missing"), true},
		{"missing", serviceManagementDelete(h, "missing"), true},
		{"invalid", fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:service,id:"invalid"}])}`, h.UUID("service-b")), false},
		{"wrong_type", serviceManagementDelete(h, "generic-b"), true},
		{"nil", `mutation{deleteAll(input:[{type:service,id:"00000000-0000-0000-0000-000000000000"}])}`, true},
	} {
		t.Run(c.name, func(t *testing.T) { serviceManagementRejected(t, h, c.query, c.noRows) })
	}
	var targets []string
	for range 51 {
		targets = append(targets, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-b")))
	}
	serviceManagementRejected(t, h, `mutation{deleteAll(input:[`+strings.Join(targets, ",")+`])}`, false)
	_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'F1 second foreign')`, h.UUID("second-b"), h.UUID("org-b"), h.UUID("policy-b"))
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	r := stepOrganizationQuery(t, h, serviceManagementDelete(h, "service-b", "second-b", "service-b"))
	require.Empty(t, r.Errors, "same-Org sets and duplicate semantics are retained")
	for _, id := range []string{"service-b", "second-b"} {
		require.Zero(t, serviceManagementCount(t, h, "services", h.UUID(id)))
	}
	require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-a")))
	serviceManagementEvidence(t, "f1-complete-set", map[string]any{"before": before, "after": serviceManagementSnapshot(t, h), "response": r})
	_, err = h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'F1 second home')`, h.UUID("second-a"), harness.SmokeOrganizationID, h.UUID("policy-a"))
	require.NoError(t, err)
	r = stepOrganizationQuery(t, h, serviceManagementDelete(h, "service-a", "second-a"))
	require.Empty(t, r.Errors)
	for _, id := range []string{"service-a", "second-a"} {
		require.Zero(t, serviceManagementCount(t, h, "services", h.UUID(id)))
	}
}

func TestGraphQLServiceDeleteF1InvalidRelationships(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	// Corruption is confined to this disposable test database; production FK
	// and schema definitions remain unchanged.
	_, err := h.App().DB().Exec(`ALTER TABLE services DROP CONSTRAINT services_organization_id_fkey`)
	require.NoError(t, err)
	for _, org := range []string{organization.DefaultOrganizationID, h.UUID("absent-org"), "00000000-0000-0000-0000-000000000000"} {
		_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,$4)`, h.UUID("invalid-"+org), org, h.UUID("policy-b"), "F1 invalid org "+org)
		require.NoError(t, err)
		serviceManagementRejected(t, h, serviceManagementDelete(h, "service-b", "invalid-"+org), true)
	}
	_, err = h.App().DB().Exec(`UPDATE services SET escalation_policy_id=$1 WHERE id=$2`, h.UUID("policy-a"), h.UUID("service-b"))
	require.NoError(t, err)
	serviceManagementRejected(t, h, serviceManagementDelete(h, "service-b"), true)
	_, err = h.App().DB().Exec(`UPDATE services SET escalation_policy_id=$1 WHERE id=$2`, h.UUID("policy-b"), h.UUID("service-b"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`ALTER TABLE escalation_policies DROP CONSTRAINT escalation_policies_organization_id_fkey`)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`DELETE FROM normal_organizations WHERE organization_id=$1`, h.UUID("org-b"))
	require.NoError(t, err)
	serviceManagementRejected(t, h, serviceManagementDelete(h, "service-b"), true)
}

func TestGraphQLServiceDeleteF1MixedIsolation(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, typ, target string
		allow, noRows     bool
	}{
		{"home_key", "integrationKey", "generic-a", true, false},
		{"foreign_key", "integrationKey", "generic-b", true, false},
		{"missing_key", "integrationKey", "missing", false, false},
		{"home_unused_EP", "escalationPolicy", "unused-a", true, false},
		{"foreign_EP", "escalationPolicy", "policy-b", true, false},
		{"home_EP_FK", "escalationPolicy", "policy-a", false, false},
		{"home_schedule", "schedule", "delete-schedule", true, false},
		{"foreign_schedule", "schedule", "foreign-schedule", true, false},
		{"home_rotation", "rotation", "delete-rotation", true, false},
		{"foreign_rotation", "rotation", "foreign-rotation", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := integrationKeyOrganizationHarness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			ikDeleteRoots(t, h)
			_, err := h.App().DB().Exec(`INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'F1 unused EP')`, h.UUID("unused-a"), harness.SmokeOrganizationID)
			require.NoError(t, err)
			_, err = h.App().DB().Exec(`INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'F1 foreign schedule','Etc/UTC')`, h.UUID("foreign-schedule"), h.UUID("org-b"))
			require.NoError(t, err)
			_, err = h.App().DB().Exec(`INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone) VALUES($1,$2,'F1 foreign rotation','daily',now(),1,'Etc/UTC')`, h.UUID("foreign-rotation"), h.UUID("org-b"))
			require.NoError(t, err)
			q := fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:%s,id:%q}])}`, h.UUID("service-b"), c.typ, h.UUID(c.target))
			if !c.allow {
				serviceManagementRejected(t, h, q, c.noRows)
				return
			}
			before := serviceManagementSnapshot(t, h)
			r := stepOrganizationQuery(t, h, q)
			require.Empty(t, r.Errors)
			require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("service-b")))
			table := map[string]string{"integrationKey": "integration_keys", "escalationPolicy": "escalation_policies", "schedule": "schedules", "rotation": "rotations"}[c.typ]
			require.Zero(t, serviceManagementCount(t, h, table, h.UUID(c.target)))
			require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-a")))
			serviceManagementEvidence(t, "f1-mixed-"+c.name, map[string]any{"before": before, "after": serviceManagementSnapshot(t, h), "response": r})
		})
	}
}

func TestGraphQLServiceDeleteF1CurrentAuthority(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	token := h.GraphQLToken(h.UUID("user-a"))
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		ikSetAuthority(t, h, role, true)
		_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'F1 current authority')`, h.UUID("current-"+role), h.UUID("org-b"), h.UUID("policy-b"))
		require.NoError(t, err)
		r := stepOrganizationPost(t, h, map[string]any{"query": serviceManagementDelete(h, "current-"+role)}, token, false)
		require.Empty(t, r.Errors)
		require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("current-"+role)))
		ikSetAuthority(t, h, role, false)
		before := serviceManagementSnapshot(t, h)
		var wait func()
		if role == "ORG_ADMIN" {
			wait = h.ExpectBackendError("sql: no rows in result set")
		}
		r = stepOrganizationPost(t, h, map[string]any{"query": serviceManagementDelete(h, "service-b")}, token, false)
		if wait != nil {
			wait()
		}
		require.NotEmpty(t, r.Errors)
		require.Equal(t, before, serviceManagementSnapshot(t, h), "same Session cannot retain revoked PA ability")
		serviceManagementEvidence(t, "f1-current-"+role, map[string]any{"before": before, "after": serviceManagementSnapshot(t, h), "response": r})
	}
}

func TestGraphQLServiceDeleteF1OtherGroups(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	ikDeleteRoots(t, h)
	_, err := h.App().DB().Exec(`INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time)
		VALUES($1,$2,$3,'2090-01-01Z','2090-01-02Z')`, h.UUID("override-a"), h.UUID("delete-schedule"), h.UUID("user-a"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO users(id,name,email,role) VALUES($1,'F1 restricted owner','','user')`, h.UUID("restricted-owner"))
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("restricted-owner"))
	require.NoError(t, err)
	for _, owner := range []string{"user-a", "restricted-owner"} {
		_, err = h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value)
			VALUES($1,$2,'F1 synthetic CM','EMAIL',$3)`, h.UUID("cm-"+owner), h.UUID(owner), "f1-"+owner+"@example.invalid")
		require.NoError(t, err)
		_, err = h.App().DB().Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes)
			VALUES($1,$2,$3,0)`, h.UUID("nr-"+owner), h.UUID(owner), h.UUID("cm-"+owner))
		require.NoError(t, err)
	}
	for _, typ := range []string{"contactMethod", "notificationRule"} {
		name := "cm-restricted-owner"
		if typ == "notificationRule" {
			name = "nr-restricted-owner"
		}
		q := fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:%s,id:%q}])}`, h.UUID("service-b"), typ, h.UUID(name))
		serviceManagementRejected(t, h, q, false)
	}
	// Service scope must not replace the Home scope used for User Overrides,
	// nor the independently derived owner/Organization authority for CM/NR.
	before := serviceManagementSnapshot(t, h)
	q := fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:userOverride,id:%q},{type:notificationRule,id:%q},{type:contactMethod,id:%q}])}`, h.UUID("service-b"), h.UUID("override-a"), h.UUID("nr-user-a"), h.UUID("cm-user-a"))
	r := stepOrganizationQuery(t, h, q)
	require.Empty(t, r.Errors)
	for _, row := range []struct{ table, id string }{{"services", "service-b"}, {"user_overrides", "override-a"}, {"user_contact_methods", "cm-user-a"}, {"user_notification_rules", "nr-user-a"}} {
		require.Zero(t, serviceManagementCount(t, h, row.table, h.UUID(row.id)))
	}
	require.Equal(t, 1, serviceManagementCount(t, h, "user_contact_methods", h.UUID("cm-restricted-owner")))
	serviceManagementEvidence(t, "f1-other-groups", map[string]any{"before": before, "after": serviceManagementSnapshot(t, h), "response": r})
}

func TestGraphQLServiceDeleteF1CascadeBoundary(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"schedule", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			h := lc1Harness(t, kind, true)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			_, err := h.App().DB().Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'F1 foreign mixed cascade')`, h.UUID("f1-service"), h.UUID("org-b"), h.UUID("policy-b"))
			require.NoError(t, err)
			q := fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:%s,id:%q}])}`, h.UUID("f1-service"), kind, h.UUID(kind+"-a"))
			serviceManagementRejected(t, h, q, true)
		})
	}
}

func TestGraphQLServiceDeleteF1ConcurrentRelationship(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
	gate, err := writer.Begin(ctx)
	require.NoError(t, err)
	var requests sync.WaitGroup
	defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
	_, err = gate.Exec(ctx, `UPDATE services SET escalation_policy_id=$1 WHERE id=$2`, h.UUID("policy-a"), h.UUID("service-b"))
	require.NoError(t, err)
	wait := h.ExpectBackendError("sql: no rows in result set")
	request := lc1Request(t, ctx, h, &requests, serviceManagementDelete(h, "service-b"))
	pid := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
	require.NoError(t, gate.Commit(ctx))
	before := serviceManagementSnapshot(t, h)
	result := <-request
	require.NoError(t, result.err)
	require.Equal(t, http.StatusOK, result.status)
	require.NotEmpty(t, result.response.Errors)
	wait()
	require.Equal(t, before, serviceManagementSnapshot(t, h), "committed new parent must be revalidated after lock wait")
	serviceManagementEvidence(t, "f1-concurrent-relationship", map[string]any{"blocked_pid": pid, "before": before, "after": serviceManagementSnapshot(t, h), "response": result.response})
}

func TestGraphQLServiceDeleteF1ConcurrentDeleteAndCascade(t *testing.T) {
	t.Parallel()
	h := integrationKeyOrganizationHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
	gate, err := writer.Begin(ctx)
	require.NoError(t, err)
	var requests sync.WaitGroup
	defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
	_, err = gate.Exec(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("policy-b"))
	require.NoError(t, err)
	first := lc1Request(t, ctx, h, &requests, serviceManagementDelete(h, "service-b"))
	firstPID := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
	_, err = observer.Exec(ctx, `SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("service-b"))
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "55P03", pgErr.Code, "Service relationship changes are fenced")
	wait := h.ExpectBackendError("sql: no rows in result set")
	second := serviceDeleteF1SecondRequest(t, ctx, h, &requests, serviceManagementDelete(h, "service-b"))
	secondPID := lc1BlockedBy(t, ctx, observer, firstPID)
	var activity string
	require.NoError(t, observer.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('pid',pid,'query',query,'state',state,'wait',wait_event,'blockers',pg_blocking_pids(pid))),'[]'::jsonb)::text FROM pg_stat_activity WHERE datname=current_database()`).Scan(&activity))
	serviceManagementEvidence(t, "f1-concurrency-waits", map[string]any{"first_pid": firstPID, "gate_pid": writer.PgConn().PID(), "activity": activity})
	inserter := lc1Connection(t, ctx, h)
	inserterPID := int(inserter.PgConn().PID())
	heartbeatID, serviceID := h.UUID("late-heartbeat"), h.UUID("service-b")
	inserted := make(chan error, 1)
	insertedEvidence := make(chan error, 1)
	requests.Add(1)
	go func() {
		defer requests.Done()
		_, e := inserter.Exec(ctx, `INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'F1 concurrent FK',interval '5 minutes')`, heartbeatID, serviceID)
		// One buffered copy cannot block the original T3 result delivery.
		insertedEvidence <- e
		inserted <- e
	}()
	// The FK writer can queue behind either the first transaction or the
	// second root-lock waiter. Observe that writer's actual blocking graph.
	var blocked bool
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		require.NoError(t, observer.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, inserterPID).Scan(&blocked))
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, blocked, "late FK writer must wait for the root deletion")
	require.NoError(t, observer.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('pid',pid,'query',query,'wait',wait_event,'blockers',pg_blocking_pids(pid))),'[]'::jsonb)::text FROM pg_stat_activity WHERE datname=current_database()`).Scan(&activity))
	serviceManagementEvidence(t, "f1-concurrency-FK-waits", map[string]any{"first_pid": firstPID, "second_pid": secondPID, "inserter_pid": inserterPID, "activity": activity})
	before := serviceManagementSnapshot(t, h)
	require.NoError(t, gate.Rollback(ctx))
	r1, r2 := <-first, <-second
	t3Reached := false
	// Runs on FailNow too, before the original request cleanup and h cleanup.
	defer func() { serviceDeleteF1TerminalEvidence(t, h, before, t3Reached, insertedEvidence) }()
	serviceDeleteF1SaveEvidence(t, "f1-concurrent-http", map[string]any{
		"T1": serviceDeleteF1HTTPReceipt(r1), "T2": serviceDeleteF1HTTPReceipt(r2),
		"first_pid": firstPID, "second_pid": secondPID, "inserter_pid": inserterPID, "gate_pid": writer.PgConn().PID(),
	})
	require.NoError(t, r1.err)
	require.NoError(t, r2.err)
	require.Empty(t, r1.response.Errors)
	require.NotEmpty(t, r2.response.Errors)
	wait()
	t3Reached = true
	require.ErrorAs(t, <-inserted, &pgErr)
	require.Equal(t, "23503", pgErr.Code, "late cascade dependent cannot enter after deletion")
	require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("service-b")))
	require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-a")))
	serviceManagementEvidence(t, "f1-concurrent-delete-cascade", map[string]any{"first_pid": firstPID, "second_pid": secondPID, "late_FK_SQLSTATE": pgErr.Code, "before": before, "after": serviceManagementSnapshot(t, h), "first": r1.response, "second": r2.response})
}
