package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/service/updateaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func serviceAuditHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, servicePlatformAdminSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	return h
}

func serviceAuditRows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var rows string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY occurred_at,event_id),'[]')::text FROM service_update_audit_events e`).Scan(&rows))
	var parsed any
	require.NoError(t, json.Unmarshal([]byte(rows), &parsed))
	if dir := os.Getenv("SERVICE_UPDATE_AUDIT_EVIDENCE"); dir != "" {
		data, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+".json"), append(data, '\n'), 0600))
	}
	return rows
}

// This same test must first fail on exact S1 after proving the business update
// succeeded. Authentication is the canonical production signed-session HTTP path.
func TestServiceUpdateAuditSignedHTTP(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	q := fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"synthetic-audit-description"})}`, h.UUID("service-b"))
	r := stepOrganizationQuery(t, h, q)
	require.Empty(t, r.Errors)
	var description string
	require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&description))
	require.Equal(t, "synthetic-audit-description", description)
	t.Log("signed-session foreign update and independently read business row confirmed")
	var relation sql.NullString
	require.NoError(t, h.App().DB().QueryRow(`SELECT to_regclass('public.service_update_audit_events')::text`).Scan(&relation))
	require.True(t, relation.Valid, "RED oracle: successful S1 update has no persistent product audit storage")
	var actor, home, target, service, role, outcome, operation, source string
	var mask int
	require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,home_organization_id,target_organization_id,service_id,authority_role,outcome,operation,authority_source,requested_fields FROM service_update_audit_events`).Scan(&actor, &home, &target, &service, &role, &outcome, &operation, &source, &mask))
	require.Equal(t, h.UUID("user-a"), actor)
	require.NotEqual(t, home, target)
	require.Equal(t, harness.SmokeOrganizationID, home)
	require.Equal(t, h.UUID("org-b"), target)
	require.Equal(t, h.UUID("service-b"), service)
	require.Equal(t, "platform_admin", role)
	require.Equal(t, "committed", outcome)
	require.Equal(t, "service.update", operation)
	require.Equal(t, "current_local_user_organization_at_admission", source)
	require.Equal(t, 2, mask)
	var alerts int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM alerts WHERE service_id=$1`, service).Scan(&alerts))
	require.Zero(t, alerts, "audit must not depend on Alert existence")
	require.NotContains(t, serviceAuditRows(t, h), description)
}

func serviceAuditCount(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM service_update_audit_events`).Scan(&n))
	return n
}

func TestServiceUpdateAuditRolesAndAttempts(t *testing.T) {
	h := serviceAuditHarness(t)
	for _, tc := range []struct {
		role                 string
		pa, foreign, allowed bool
		outcome              string
	}{
		{"ORG_MEMBER", true, false, true, "committed"},
		{"ORG_MEMBER", true, true, true, "committed"},
		{"ORG_ADMIN", true, false, true, "committed"},
		{"ORG_ADMIN", true, true, true, "committed"},
		{"ORG_ADMIN", false, false, true, "committed"},
		{"ORG_ADMIN", false, true, false, "validation_failed"},
		{"ORG_MEMBER", false, false, false, "denied"},
		{"ORG_MEMBER", false, true, false, "denied"},
	} {
		ikSetAuthority(t, h, tc.role, tc.pa)
		id := h.UUID("service-a")
		if tc.foreign {
			id = h.UUID("service-b")
		}
		before := serviceAuditCount(t, h)
		var wait func()
		if !tc.allowed && tc.role == "ORG_ADMIN" {
			wait = h.ExpectBackendError("sql: no rows in result set")
		}
		r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"safe synthetic update"})}`, id))
		if wait != nil {
			wait()
		}
		if tc.allowed {
			require.Empty(t, r.Errors)
		} else {
			require.NotEmpty(t, r.Errors)
		}
		require.Equal(t, before+1, serviceAuditCount(t, h))
		var outcome, actor, home, orgRole string
		var target sql.NullString
		require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,actor_id,home_organization_id,organization_role,target_organization_id FROM service_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&outcome, &actor, &home, &orgRole, &target))
		require.Equal(t, tc.outcome, outcome)
		require.Equal(t, h.UUID("user-a"), actor)
		require.Equal(t, harness.SmokeOrganizationID, home)
		require.Equal(t, tc.role, orgRole)
		if tc.allowed {
			require.True(t, target.Valid)
			if tc.foreign {
				require.Equal(t, h.UUID("org-b"), target.String)
			} else {
				require.Equal(t, home, target.String)
			}
		} else {
			require.False(t, target.Valid, "denied lookup must not fabricate target from Home/input")
		}
	}
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	before := serviceAuditCount(t, h)
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{first:updateService(input:{id:%q,description:"first committed"}) second:updateService(input:{id:%q,name:""})}`, h.UUID("service-b"), h.UUID("service-b")))
	require.NotEmpty(t, r.Errors)
	// The later non-null field error can null the GraphQL response. The earlier
	// mutation's independent database commit must nevertheless remain durable.
	require.Equal(t, before+2, serviceAuditCount(t, h))
	var attempts, requests int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id),count(DISTINCT request_id) FROM (SELECT * FROM service_update_audit_events ORDER BY occurred_at DESC LIMIT 2) e`).Scan(&attempts, &requests))
	require.Equal(t, 2, attempts)
	require.Equal(t, 1, requests)
	// Repeating an HTTP invocation is a fresh attempt, not mutation idempotency.
	r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"first committed"})}`, h.UUID("service-b")))
	require.Empty(t, r.Errors)
	var description string
	require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&description))
	require.Equal(t, "first committed", description)
	duplicate := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Service A"})}`, h.UUID("service-b")))
	require.NotEmpty(t, duplicate.Errors)
	require.Contains(t, fmt.Sprint(duplicate.Errors), "already in use", "existing duplicate-name field behavior is retained")
	noop := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q})}`, h.UUID("service-b")))
	require.Empty(t, noop.Errors)
	var mask int
	require.NoError(t, h.App().DB().QueryRow(`SELECT requested_fields FROM service_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&mask))
	require.Zero(t, mask)
	expires := h.Now().Add(45 * time.Minute)
	combined := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Combined Fields",description:"combined update",maintenanceExpiresAt:%q,escalationPolicyID:%q})}`, h.UUID("service-b"), expires.Format(time.RFC3339), h.UUID("replacement")))
	require.Empty(t, combined.Errors)
	require.NoError(t, h.App().DB().QueryRow(`SELECT requested_fields FROM service_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&mask))
	require.Equal(t, 15, mask)
	serviceAuditRows(t, h)
}

func TestServiceUpdateAuditAdmissionChanges(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	token := h.GraphQLToken(h.UUID("user-a"))
	query := func(id string) *stepOrganizationResponse {
		return stepOrganizationPost(t, h, map[string]any{"query": fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"request-current audit"})}`, id)}, token, false)
	}
	require.Empty(t, query(h.UUID("service-b")).Errors)
	_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("user-a"), h.UUID("org-c"))
	require.NoError(t, err)
	require.Empty(t, query(h.UUID("service-b")).Errors)
	var home, target string
	require.NoError(t, h.App().DB().QueryRow(`SELECT home_organization_id,target_organization_id FROM service_update_audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&home, &target))
	require.Equal(t, h.UUID("org-c"), home)
	require.Equal(t, h.UUID("org-b"), target)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	require.Empty(t, query(h.UUID("service-c")).Errors)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	require.NotEmpty(t, query(h.UUID("service-c")).Errors)
	_, err = h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id=(SELECT id FROM organizations WHERE classification='DEFAULT'),effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	require.NotEmpty(t, query(h.UUID("service-c")).Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	_, err = h.App().DB().Exec(`DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
	require.NoError(t, err)
	require.NotEmpty(t, query(h.UUID("service-c")).Errors)
	var unknown, oldHome int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE actor_kind='unknown' AND home_organization_id IS NULL),count(*) FILTER(WHERE home_organization_id=$1) FROM service_update_audit_events`, harness.SmokeOrganizationID).Scan(&unknown, &oldHome))
	require.Equal(t, 2, unknown)
	require.Equal(t, 1, oldHome, "historical Home attribution must not follow later assignment changes")
	serviceAuditRows(t, h)
}

func TestServiceUpdateAuditHistoricalRelationship(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	_, err := h.App().DB().Exec(`UPDATE services SET escalation_policy_id=$2 WHERE id=$1`, h.UUID("service-b"), h.UUID("policy-a"))
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	wait := h.ExpectBackendError("sql: no rows in result set")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"must not repair legacy relation"})}`, h.UUID("service-b")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var outcome, reason string
	var target, service sql.NullString
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code,target_organization_id,service_id FROM service_update_audit_events`).Scan(&outcome, &reason, &target, &service))
	require.Equal(t, "validation_failed", outcome)
	require.Equal(t, "target_unavailable", reason)
	require.False(t, target.Valid)
	require.False(t, service.Valid)
	serviceAuditRows(t, h)
}

func TestServiceUpdateAuditFailureAtomicity(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'SYNTHETIC_SQL_SECRET_RAW_DESTINATION'; END IF; RETURN NEW; END $$;
CREATE TRIGGER audit_test_fail BEFORE INSERT ON service_update_audit_events FOR EACH ROW EXECUTE FUNCTION audit_test_fail()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	wait := h.ExpectBackendError("service.update transaction failed")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"must rollback"})}`, h.UUID("service-b")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var outcome, reason string
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code FROM service_update_audit_events`).Scan(&outcome, &reason))
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "audit_write_failed", reason)
	require.NotContains(t, serviceAuditRows(t, h), "SYNTHETIC_SQL_SECRET_RAW_DESTINATION")
	b, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(b), "SYNTHETIC_SQL_SECRET_RAW_DESTINATION")
	_, err = h.App().DB().Exec(`DROP TRIGGER audit_test_fail ON service_update_audit_events`)
	require.NoError(t, err)
	r = stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"recovered"})}`, h.UUID("service-b")))
	require.Empty(t, r.Errors)
	require.Equal(t, 2, serviceAuditCount(t, h))
}

func TestServiceUpdateAuditVisibilityAndLocks(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tx, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	var blocker int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blocker))
	_, err = tx.ExecContext(ctx, `LOCK TABLE service_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	done := make(chan *stepOrganizationResponse, 1)
	defer func() {
		_ = tx.Rollback()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("update did not finish after blocker release")
		}
	}()
	go func() {
		done <- stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"atomic visible",escalationPolicyID:%q})}`, h.UUID("service-b"), h.UUID("replacement")))
	}()
	require.Eventually(t, func() bool {
		var n int
		err := h.App().DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&n)
		return err == nil && n == 1
	}, 10*time.Second, 10*time.Millisecond)
	var old string
	require.NoError(t, h.App().DB().QueryRowContext(ctx, `SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&old))
	require.Empty(t, old)
	require.Zero(t, serviceAuditCount(t, h), "independent connection must not see staged success")
	for _, probe := range []struct{ sql, id string }{
		{`SELECT id FROM services WHERE id=$1 FOR UPDATE`, h.UUID("service-b")},
		{`SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("policy-b")},
		{`SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("replacement")},
		{`SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, h.UUID("org-b")},
		{`SELECT organization_id FROM normal_organizations WHERE organization_id=$1 FOR UPDATE`, h.UUID("org-b")},
	} {
		p, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = p.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`)
		require.NoError(t, err)
		_, err = p.ExecContext(ctx, probe.sql, probe.id)
		require.NoError(t, p.Rollback())
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55P03", pg.Code)
	}
	other, err := h.App().DB().BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = other.ExecContext(ctx, `UPDATE services SET description='unrelated probe' WHERE id=$1`, h.UUID("service-c"))
	require.NoError(t, err)
	require.NoError(t, other.Rollback())
	require.NoError(t, tx.Rollback())
	select {
	case r := <-done:
		require.Empty(t, r.Errors)
		done <- nil
	case <-ctx.Done():
		t.Fatal("update timed out")
	}
	var committed string
	require.NoError(t, h.App().DB().QueryRowContext(ctx, `SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&committed))
	require.Equal(t, "atomic visible", committed)
	require.Equal(t, 1, serviceAuditCount(t, h))
	serviceAuditRows(t, h)
}

func TestServiceUpdateAuditDedupeAndAppendOnly(t *testing.T) {
	h := serviceAuditHarness(t)
	e := updateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "human", ActorID: uuid.MustParse(h.UUID("user-a")), HomeOrganizationID: uuid.MustParse(harness.SmokeOrganizationID), AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER", ServiceID: uuid.MustParse(h.UUID("service-b")), TargetOrganizationID: uuid.MustParse(h.UUID("org-b")), RequestedFields: updateaudit.Description, Outcome: "committed", Reason: "updated", OccurredAt: time.Now()}
	tx, err := h.App().DB().Begin()
	require.NoError(t, err)
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("audit transaction cleanup failed")
		}
	}()
	require.NoError(t, updateaudit.Append(context.Background(), tx, e))
	require.NoError(t, updateaudit.Append(context.Background(), tx, e))
	changed := e
	changed.RequestedFields = updateaudit.Name
	require.ErrorIs(t, updateaudit.Append(context.Background(), tx, changed), updateaudit.ErrConflict)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, serviceAuditCount(t, h))
	independent, err := h.App().DB().Begin()
	require.NoError(t, err)
	defer func() {
		if err := independent.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("independent audit transaction cleanup failed")
		}
	}()
	require.NoError(t, updateaudit.Append(context.Background(), independent, e))
	require.ErrorIs(t, updateaudit.Append(context.Background(), independent, changed), updateaudit.ErrConflict)
	require.NoError(t, independent.Commit())
	require.Equal(t, 1, serviceAuditCount(t, h), "cross-connection retries preserve the original row")
	for _, q := range []string{`UPDATE service_update_audit_events SET reason_code='updated'`, `DELETE FROM service_update_audit_events`, `TRUNCATE service_update_audit_events`} {
		_, err := h.App().DB().Exec(q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	_, err = h.App().DB().Exec(`DELETE FROM services WHERE id=$1`, h.UUID("service-b"))
	require.NoError(t, err)
	require.Equal(t, 1, serviceAuditCount(t, h))
	serviceAuditRows(t, h)
}

func TestServiceUpdateAuditInvalidAndCancelledAuthority(t *testing.T) {
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", true)
	app := graphqlapp.App{DB: h.App().DB()}
	before := serviceManagementSnapshot(t, h)
	_, err := app.Mutation().UpdateService(context.Background(), graphql2.UpdateServiceInput{ID: h.UUID("service-b")})
	require.Error(t, err)
	var actor, source, outcome string
	var home, target sql.NullString
	require.NoError(t, h.App().DB().QueryRow(`SELECT actor_kind,authority_source,outcome,home_organization_id,target_organization_id FROM service_update_audit_events`).Scan(&actor, &source, &outcome, &home, &target))
	require.Equal(t, "unknown", actor)
	require.Equal(t, "unknown", source)
	require.Equal(t, "denied", outcome)
	require.False(t, home.Valid)
	require.False(t, target.Valid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = app.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: h.UUID("service-b")})
	require.Error(t, err)
	require.Equal(t, 2, serviceAuditCount(t, h), "bounded independent append survives request cancellation")
	valid, cancelValid := context.WithCancel(servicePlatformAdminContext(t, h))
	cancelValid()
	_, err = app.Mutation().UpdateService(valid, graphql2.UpdateServiceInput{ID: h.UUID("service-b")})
	require.Error(t, err)
	require.Equal(t, 3, serviceAuditCount(t, h), "canceled authorized Begin is recorded independently with verified identity")
	var reason string
	require.NoError(t, h.App().DB().QueryRow(`SELECT reason_code FROM service_update_audit_events WHERE actor_kind='human'`).Scan(&reason))
	require.Equal(t, "begin_failed", reason)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	serviceAuditRows(t, h)
}
