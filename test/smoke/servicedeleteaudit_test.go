package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
)

func sd1Harness(t *testing.T) *harness.Harness {
	t.Helper()
	h := serviceAuditHarness(t)
	epB1Exec(t, h, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'SD1 Home Schedule','UTC')`, h.UUID("schedule-a"), harness.SmokeOrganizationID)
	return h
}

func sd1Rows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var rows string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id),'[]')::text FROM service_delete_audit_events e`).Scan(&rows))
	return rows
}
func sd1Save(t *testing.T, value any) {
	t.Helper()
	if dir := os.Getenv("SERVICE_DELETE_AUDIT_EVIDENCE"); dir != "" {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		file, err := os.CreateTemp(dir, strings.ReplaceAll(t.Name(), "/", "_")+"-*.json")
		require.NoError(t, err)
		_, err = file.Write(append(data, '\n'))
		require.NoError(t, err)
		require.NoError(t, file.Close())
	}
}
func sd1Count(t *testing.T, h *harness.Harness, outcome string) int {
	t.Helper()
	var count int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM service_delete_audit_events WHERE outcome=$1`, outcome).Scan(&count))
	return count
}

// Capture actual HTTP status/body and durable before/after state, omitting the
// real signed Session credential and all headers from evidence.
func sd1HTTP(t *testing.T, h *harness.Harness, query, token string) *stepOrganizationResponse {
	t.Helper()
	if token == "" {
		token = h.GraphQLToken(h.UUID("user-a"))
	}
	before := serviceManagementSnapshot(t, h)
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var result stepOrganizationResponse
	require.NoError(t, json.Unmarshal(raw, &result))
	after := serviceManagementSnapshot(t, h)
	sd1Save(t, map[string]any{"transport": "actual production signed Human Session HTTP", "status": response.StatusCode, "query": query, "response": json.RawMessage(raw), "before": before, "after": after, "audit": json.RawMessage(sd1Rows(t, h))})
	if len(result.Errors) > 0 {
		require.Equal(t, before, after, "denial/failure preserves all selected business tables")
	}
	return &result
}

func TestServiceDeleteAuditSignedHTTPRoles(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, role, target, outcome           string
		pa, defaultHome, missingHome, allowed bool
	}{
		{"OrgAdminHome", "ORG_ADMIN", "service-a", "committed", false, false, false, true},
		{"OrgAdminForeign", "ORG_ADMIN", "service-b", "validation_failed", false, false, false, false},
		{"OrgMember", "ORG_MEMBER", "service-a", "denied", false, false, false, false},
		{"NormalPA", "ORG_MEMBER", "service-b", "committed", true, false, false, true},
		{"DefaultPA", "ORG_MEMBER", "service-b", "committed", true, true, false, true},
		{"OrdinaryDefault", "ORG_MEMBER", "service-b", "", false, true, false, false},
		{"MissingAuthority", "ORG_ADMIN", "service-a", "", true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			h.IgnoreErrorsWith("sql: no rows in result set")
			ikSetAuthority(t, h, tc.role, tc.pa)
			if tc.defaultHome {
				epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
			}
			if tc.missingHome {
				epB1Exec(t, h, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
			}
			otherOrg := serviceManagementCount(t, h, "services", h.UUID("service-c"))
			r := sd1HTTP(t, h, serviceManagementDelete(h, tc.target), "")
			if tc.allowed {
				require.Empty(t, r.Errors)
				require.Zero(t, serviceManagementCount(t, h, "services", h.UUID(tc.target)))
			} else {
				require.NotEmpty(t, r.Errors)
			}
			require.Equal(t, otherOrg, serviceManagementCount(t, h, "services", h.UUID("service-c")))
			if tc.outcome == "" {
				require.JSONEq(t, `[]`, sd1Rows(t, h), "pre-resolver admission does not invent an audit actor")
				return
			}
			require.Equal(t, 1, sd1Count(t, h, tc.outcome))
			var actor, home, role, authority, operation string
			var target, serviceID sql.NullString
			require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,home_organization_id,organization_role,authority_role,operation,target_organization_id,service_id FROM service_delete_audit_events`).Scan(&actor, &home, &role, &authority, &operation, &target, &serviceID))
			require.Equal(t, h.UUID("user-a"), actor)
			require.Equal(t, "service.delete", operation)
			wantHome := harness.SmokeOrganizationID
			if tc.defaultHome {
				wantHome = organization.DefaultOrganizationID
				require.Equal(t, "NONE", role)
			} else {
				require.Equal(t, tc.role, role)
			}
			require.Equal(t, wantHome, home)
			if tc.pa {
				require.Equal(t, "platform_admin", authority)
			}
			if tc.allowed {
				require.True(t, target.Valid)
				require.Equal(t, h.UUID(tc.target), serviceID.String)
				wantTarget := harness.SmokeOrganizationID
				if tc.target == "service-b" {
					wantTarget = h.UUID("org-b")
				}
				require.Equal(t, wantTarget, target.String)
			} else {
				require.Zero(t, sd1Count(t, h, "committed"))
				require.False(t, target.Valid)
				require.False(t, serviceID.Valid)
			}
		})
	}
}

func TestServiceDeleteAuditSignedHTTPTargetsAndMixedAtomicity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		targets   []string
		allowed   bool
		committed int
	}{
		{"sameOrgMulti", []string{"service-a", "sd1-second-a"}, true, 2},
		{"duplicate", []string{"service-b", "service-b"}, true, 1},
		{"crossOrg", []string{"service-a", "service-b"}, false, 0},
		{"missing", []string{"service-missing"}, false, 0},
		{"existingAndMissing", []string{"service-b", "service-missing"}, false, 0},
		{"mixed", []string{"service-b", "escalationPolicy-b"}, true, 1},
		{"mixedReversed", []string{"escalationPolicy-b", "service-b"}, true, 1},
		{"lateGroupFailure", []string{"service-b", "escalationPolicy-missing"}, false, 0},
		{"mixedReferencedHomeEP", []string{"service-b", "escalationPolicy-a"}, false, 0},
		{"earlyGroupRollback", []string{"schedule-a", "service-missing"}, false, 0},
		{"independentGroupScopes", []string{"schedule-a", "service-b"}, true, 1},
		{"badRelationship", []string{"service-b"}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			h.IgnoreErrorsWith("sql: no rows in result set")
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			epB1Exec(t, h, `INSERT INTO services(id,name,organization_id,escalation_policy_id) VALUES($1,'SD1 second A',$2,$3)`, h.UUID("sd1-second-a"), harness.SmokeOrganizationID, h.UUID("policy-a"))
			if tc.name == "badRelationship" {
				epB1Exec(t, h, `UPDATE services SET escalation_policy_id=$2 WHERE id=$1`, h.UUID("service-b"), h.UUID("policy-a"))
			}
			input := make([]string, 0, len(tc.targets))
			for _, key := range tc.targets {
				typ, _, _ := strings.Cut(key, "-")
				id := h.UUID(key)
				if typ == "escalationPolicy" {
					id = h.UUID("policy-" + strings.TrimPrefix(key, "escalationPolicy-"))
				}
				if key == "sd1-second-a" {
					typ = "service"
				}
				input = append(input, fmt.Sprintf(`{type:%s,id:%q}`, typ, id))
			}
			r := sd1HTTP(t, h, `mutation{deleteAll(input:[`+strings.Join(input, ",")+`])}`, "")
			if tc.allowed {
				require.Empty(t, r.Errors)
			} else {
				require.NotEmpty(t, r.Errors)
			}
			require.Equal(t, tc.committed, sd1Count(t, h, "committed"))
			if !tc.allowed {
				require.Equal(t, 1, sd1Count(t, h, "validation_failed"))
				if tc.name == "mixedReferencedHomeEP" {
					require.Equal(t, "EscalationPolicyID", r.Errors[0].Extensions["fieldName"])
					require.Equal(t, "is currently in use", r.Errors[0].Message)
				}
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-c")))
			if tc.allowed {
				var attempts, requests, services int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT request_id),count(DISTINCT service_id) FROM service_delete_audit_events WHERE outcome='committed'`).Scan(&attempts, &requests, &services))
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, requests)
				require.Equal(t, tc.committed, services)
			}
		})
	}
}

func TestServiceDeleteAuditInputValidationAndNoServiceBoundary(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	for _, q := range []string{`mutation{deleteAll(input:[{type:service,id:"not-a-uuid"}])}`, func() string {
		var ids []string
		for range 51 {
			ids = append(ids, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-b")))
		}
		return `mutation{deleteAll(input:[` + strings.Join(ids, ",") + `])}`
	}()} {
		require.NotEmpty(t, sd1HTTP(t, h, q, "").Errors)
	}
	require.Equal(t, 2, sd1Count(t, h, "validation_failed"))
	require.Zero(t, sd1Count(t, h, "committed"))
	rows := sd1Rows(t, h)
	require.Empty(t, sd1HTTP(t, h, fmt.Sprintf(`mutation{deleteAll(input:[{type:schedule,id:%q}])}`, h.UUID("schedule-a")), "").Errors)
	require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
	require.Equal(t, rows, sd1Rows(t, h), "no explicit Service means no service.delete event")
}

func TestServiceDeleteAuditRevocationAndHistoricalAttribution(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	token := h.GraphQLToken(h.UUID("user-a"))
	require.Empty(t, sd1HTTP(t, h, serviceManagementDelete(h, "service-b"), token).Errors)
	first := sd1Rows(t, h)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	require.NotEmpty(t, sd1HTTP(t, h, serviceManagementDelete(h, "service-a"), token).Errors)
	require.Equal(t, 1, sd1Count(t, h, "denied"))
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	epB1Exec(t, h, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("user-a"), h.UUID("org-c"))
	var historical string
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id)::text FROM service_delete_audit_events e WHERE outcome='committed'`).Scan(&historical))
	require.JSONEq(t, first, historical)
	epB1Exec(t, h, `DELETE FROM users WHERE id=$1`, h.UUID("user-a"))
	require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id)::text FROM service_delete_audit_events e WHERE outcome='committed'`).Scan(&historical))
	require.JSONEq(t, first, historical)
	sd1Save(t, map[string]any{"original": json.RawMessage(first), "afterActorDeletion": json.RawMessage(historical)})
}

func TestServiceDeleteAuditCascadeAndWitnessVisibility(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	for _, target := range []string{"service-a", "service-b"} {
		epB1Exec(t, h, `INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'SD1 synthetic sentinel','sd1-sentinel')`, h.UUID(target))
	}
	epB1Exec(t, h, `INSERT INTO heartbeat_monitors(id,service_id,name,heartbeat_interval) VALUES($1,$2,'SD1 heartbeat',interval '5 minutes')`, h.UUID("sd1-hb"), h.UUID("service-b"))
	conn, err := h.App().DB().Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_lock(990091)`)
	require.NoError(t, err)
	epB1Exec(t, h, `CREATE FUNCTION sd1_visibility() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(990091); RETURN NEW; END $$;
CREATE TRIGGER sd1_visibility BEFORE INSERT ON service_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd1_visibility()`)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	defer func() {
		_, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990091)`)
		require.NoError(t, err)
		wg.Wait()
	}()
	done := serviceDeleteF1SecondRequest(t, ctx, h, &wg, serviceManagementDelete(h, "service-b"))
	require.Eventually(t, func() bool {
		var n int
		err := h.App().DB().QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%INSERT INTO service_delete_audit_events%'`).Scan(&n)
		return err == nil && n > 0
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")), "uncommitted deletion is invisible")
	require.Zero(t, sd1Count(t, h, "committed"), "staged witness is also invisible")
	_, err = conn.ExecContext(t.Context(), `SELECT pg_advisory_unlock(990091)`)
	require.NoError(t, err)
	r := <-done
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.status)
	require.Empty(t, r.response.Errors)
	require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("service-b")))
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	var homeAlerts, foreignAlerts, hbs int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE service_id=$1),count(*) FILTER(WHERE service_id=$2) FROM alerts`, h.UUID("service-a"), h.UUID("service-b")).Scan(&homeAlerts, &foreignAlerts))
	require.Equal(t, 1, homeAlerts)
	require.Zero(t, foreignAlerts)
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM heartbeat_monitors WHERE service_id=$1`, h.UUID("service-b")).Scan(&hbs))
	require.Zero(t, hbs)
	sd1Save(t, map[string]any{"actualSignedHTTP": r.response, "audit": json.RawMessage(sd1Rows(t, h)), "homeSentinelAlerts": homeAlerts, "deletedForeignAlerts": foreignAlerts, "deletedHeartbeat": hbs})
}

func TestServiceDeleteAuditRealPostgresFailuresAndRetry(t *testing.T) {
	for _, mode := range []string{"audit_committed_only", "audit_all", "denied_audit_all", "commit_rejected", "retry_then_success", "retry_exhausted"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			if mode == "denied_audit_all" {
				ikSetAuthority(t, h, "ORG_MEMBER", false)
			}
			h.IgnoreErrorsWith("service.delete")
			switch mode {
			case "audit_committed_only", "audit_all", "denied_audit_all":
				condition := "TRUE"
				if mode == "audit_committed_only" {
					condition = "NEW.outcome='committed'"
				}
				epB1Exec(t, h, `CREATE FUNCTION sd1_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'SYNTHETIC_AUDIT_DESTINATION_SECRET'; END IF; RETURN NEW; END $$;
CREATE TRIGGER sd1_audit_fault BEFORE INSERT ON service_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd1_audit_fault()`)
			case "commit_rejected":
				epB1Exec(t, h, `CREATE FUNCTION sd1_commit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_COMMIT_SECRET'; END $$;
CREATE CONSTRAINT TRIGGER sd1_commit_reject AFTER DELETE ON services DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sd1_commit_reject()`)
			default:
				limit := "2"
				if mode == "retry_exhausted" {
					limit = "100"
				}
				epB1Exec(t, h, `CREATE SEQUENCE sd1_attempt_counter;
CREATE FUNCTION sd1_retry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF nextval('sd1_attempt_counter')<=`+limit+` THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='SYNTHETIC_RETRY_SECRET'; END IF; RETURN OLD; END $$;
CREATE TRIGGER sd1_retry BEFORE DELETE ON services FOR EACH ROW EXECUTE FUNCTION sd1_retry()`)
			}
			r := sd1HTTP(t, h, serviceManagementDelete(h, "service-b"), "")
			require.NotContains(t, fmt.Sprint(r), "SYNTHETIC_")
			require.NotContains(t, sd1Rows(t, h), "SYNTHETIC_")
			if mode == "retry_then_success" {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, sd1Count(t, h, "committed"))
				require.Equal(t, 2, sd1Count(t, h, "tx_failed"))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Zero(t, sd1Count(t, h, "committed"))
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				want := 1
				if mode == "audit_all" || mode == "denied_audit_all" {
					want = 0
				}
				if mode == "retry_exhausted" {
					want = 5
				}
				require.Equal(t, want, sd1Count(t, h, "tx_failed"))
			}
			if strings.HasPrefix(mode, "retry_") {
				var attempts, requests, sequence int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT request_id) FROM service_delete_audit_events`).Scan(&attempts, &requests))
				require.NoError(t, h.App().DB().QueryRow(`SELECT last_value FROM sd1_attempt_counter`).Scan(&sequence))
				want := 3
				if mode == "retry_exhausted" {
					want = 5
				}
				require.Equal(t, want, sequence)
				require.Equal(t, want, attempts)
				require.Equal(t, 1, requests)
			}
			if mode == "audit_committed_only" || mode == "commit_rejected" {
				var reason string
				require.NoError(t, h.App().DB().QueryRow(`SELECT reason_code FROM service_delete_audit_events`).Scan(&reason))
				want := "audit_write_failed"
				if mode == "commit_rejected" {
					want = "commit_rejected"
				}
				require.Equal(t, want, reason)
			}
		})
	}
}

func TestServiceDeleteAuditSimulatedAcknowledgementsOverRealPostgres(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "completion_unknown", "rollback_then_error", "begin_failed", "rollback_unconfirmed"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			var database string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			db := sql.OpenDB(connector)
			defer db.Close()
			db.SetMaxOpenConns(1)
			store, err := service.NewStore(t.Context(), db)
			require.NoError(t, err)
			a := graphqlapp.App{DB: db, ServiceStore: store}
			id := h.UUID("service-b")
			if mode == "rollback_unconfirmed" {
				id = h.UUID("missing")
			}
			_, safe := sd3Key(t, h, h.UUID("service-b"))
			ok, err := a.Mutation().DeleteAll(servicePlatformAdminContext(t, h), []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: id}})
			require.Error(t, err)
			require.False(t, ok)
			require.NotContains(t, err.Error(), "SYNTHETIC_")
			committed := mode == "commit_then_error" || mode == "completion_unknown"
			if committed {
				require.Zero(t, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				require.Equal(t, 1, sd1Count(t, h, "committed"))
				effects := sd3Effects(t, h, h.UUID("service-b"))
				require.Len(t, effects, 1)
				require.Equal(t, safe, *effects[0].ResourceUUID)
			} else {
				require.Equal(t, 1, serviceManagementCount(t, h, "services", h.UUID("service-b")))
				require.Zero(t, sd1Count(t, h, "committed"))
			}
			outcome := "commit_unknown"
			if mode == "begin_failed" {
				outcome = "tx_failed"
			}
			if mode == "rollback_unconfirmed" {
				outcome = "rollback_unconfirmed"
			}
			require.Equal(t, 1, sd1Count(t, h, outcome))
			require.EqualValues(t, 2, connector.begins.Load(), "one business attempt and one failure append; no unknown replay")
			var attempts, requests int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT request_id) FROM service_delete_audit_events`).Scan(&attempts, &requests))
			require.Equal(t, 1, attempts)
			require.Equal(t, 1, requests)
			sd1Save(t, map[string]any{"evidenceKind": "controlled driver acknowledgement around real PostgreSQL; direct resolver, not signed HTTP or native PG transport failure", "mode": mode, "audit": json.RawMessage(sd1Rows(t, h))})
		})
	}
}

func TestServiceDeleteAuditInternalAndForgedIdentity(t *testing.T) {
	h := sd1Harness(t)
	a := graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore}
	valid := integrationKeyOrganizationContext(t, h)
	other, err := auth.NewRequester(h.UUID("user-a"), uuid.NewString())
	require.NoError(t, err)
	for _, ctx := range []context.Context{permission.ServiceContext(context.Background(), h.UUID("service-a")), auth.WithRequester(valid, other)} {
		before := serviceManagementSnapshot(t, h)
		ok, err := a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: h.UUID("service-b")}})
		require.False(t, ok)
		require.True(t, permission.IsPermissionError(err))
		require.Equal(t, before, serviceManagementSnapshot(t, h))
	}
	require.Equal(t, 2, sd1Count(t, h, "denied"))
	require.Zero(t, sd1Count(t, h, "committed"))
	sys := permission.SystemContext(context.Background(), "Engine")
	ok, err := a.Mutation().DeleteAll(sys, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: h.UUID("service-b")}, {Type: assignment.TargetTypeService, ID: h.UUID("service-b")}, {Type: assignment.TargetTypeService, ID: uuid.NewString()}})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	var actor, home sql.NullString
	var kind, source string
	require.NoError(t, h.App().DB().QueryRow(`SELECT actor_kind,actor_id,home_organization_id,authority_source FROM service_delete_audit_events WHERE outcome='committed'`).Scan(&kind, &actor, &home, &source))
	require.Equal(t, "internal_system", kind)
	require.Equal(t, "trusted_internal_system", source)
	require.False(t, actor.Valid)
	require.False(t, home.Valid)
	sd1Save(t, map[string]any{"evidenceKind": "direct resolver compatibility control; not an HTTP Human identity", "audit": json.RawMessage(sd1Rows(t, h))})
}
