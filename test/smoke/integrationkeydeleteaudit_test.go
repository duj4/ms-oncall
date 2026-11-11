package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

func sd4Rows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var raw string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]')::text FROM integration_key_delete_audit_events e`).Scan(&raw))
	return raw
}
func sd4Count(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_key_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
	return n
}
func sd4Query(keys []uuid.UUID, others ...string) string {
	targets := append([]string{}, others...)
	for _, k := range keys {
		targets = append(targets, fmt.Sprintf(`{type:integrationKey,id:%q}`, k.String()))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}
func TestIntegrationKeyDeleteAuditHTTPIdentity(t *testing.T) {
	for _, mode := range []string{"org_admin", "platform_admin", "multiple_orgs", "default_pa"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			ikSetAuthority(t, h, "ORG_ADMIN", mode != "org_admin")
			if mode == "default_pa" {
				_, err := db.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
				require.NoError(t, err)
			}
			roots := []string{h.UUID("service-a")}
			if mode != "org_admin" {
				roots = []string{h.UUID("service-b")}
			}
			if mode == "multiple_orgs" || mode == "default_pa" {
				roots = append(roots, h.UUID("service-c"))
			}
			keys := []uuid.UUID{}
			safeIDs := map[string]string{}
			for _, root := range roots {
				key, safe := sd3Key(t, h, root)
				keys = append(keys, key)
				safeIDs[safe.String()] = root
				_, err := db.Exec(`UPDATE integration_keys SET name=$2 WHERE id=$1`, key, "SYNTHETIC_TOKEN_SECRET SYNTHETIC_HASH_SECRET SYNTHETIC_PREFIX_SECRET https://synthetic.invalid/credential")
				require.NoError(t, err)
				sd3Alert(t, h, root, "closed")
			}
			response := stepOrganizationQuery(t, h, sd4Query(append(keys, keys[0])))
			require.Empty(t, response.Errors)
			require.Equal(t, len(roots), sd4Count(t, h))
			require.Zero(t, sd1Count(t, h, "committed"))
			var events []map[string]any
			raw := sd4Rows(t, h)
			require.NoError(t, json.Unmarshal([]byte(raw), &events))
			for _, e := range events {
				require.Equal(t, "integration_key.delete", e["operation"])
				require.Equal(t, "EXPLICIT", e["provenance"])
				require.Equal(t, "explicit_sql", e["deletion_mechanism"])
				require.Equal(t, h.UUID("user-a"), e["actor_id"])
				home := harness.SmokeOrganizationID
				if mode == "default_pa" {
					home = organization.DefaultOrganizationID
				}
				require.Equal(t, home, e["home_organization_id"])
				require.Equal(t, safeIDs[e["root_resource_id"].(string)], e["parent_service_id"])
				var target string
				require.NoError(t, db.QueryRow(`SELECT organization_id FROM services WHERE id=$1`, e["parent_service_id"]).Scan(&target))
				require.Equal(t, target, e["target_organization_id"])
			}
			for _, key := range keys {
				require.NotContains(t, raw, key.String())
			}
			require.NotContains(t, raw, "SYNTHETIC_")
			require.NotContains(t, raw, "synthetic.invalid")
			var services, alerts int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM services`).Scan(&services))
			require.Equal(t, 3, services)
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM alerts`).Scan(&alerts))
			require.Equal(t, len(roots), alerts)
			// A later HTTP request is a missing Human target, never a replayed success.
			response = stepOrganizationQuery(t, h, sd4Query(keys))
			require.NotEmpty(t, response.Errors)
			require.Equal(t, len(roots), sd4Count(t, h))
			require.NotContains(t, sd4Rows(t, h), keys[0].String())
		})
	}
}
func TestIntegrationKeyDeleteAuditDeniedAndLimits(t *testing.T) {
	for _, mode := range []string{"member", "foreign", "missing", "50", "51"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			if mode != "member" {
				ikSetAuthority(t, h, "ORG_ADMIN", false)
			}
			root := h.UUID("service-a")
			if mode == "foreign" {
				root = h.UUID("service-b")
			}
			key, _ := sd3Key(t, h, root)
			id := key
			if mode == "missing" {
				id = uuid.New()
			}
			n := 1
			if mode == "50" {
				n = 50
			}
			if mode == "51" {
				n = 51
			}
			keys := make([]uuid.UUID, n)
			for i := range keys {
				keys[i] = id
			}
			r := stepOrganizationQuery(t, h, sd4Query(keys))
			if mode == "50" {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, sd4Count(t, h))
			} else {
				require.NotEmpty(t, r.Errors)
				require.Zero(t, sd4Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", key.String()))
				require.NotContains(t, sd4Rows(t, h), key.String())
				var known int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM integration_key_delete_audit_events WHERE root_resource_id IS NOT NULL`).Scan(&known))
				require.Zero(t, known)
			}
		})
	}
}
func TestIntegrationKeyDeleteAuditPartition(t *testing.T) {
	for _, mode := range []string{"actual_parent", "cascade_only", "unrelated", "suppressed_parent", "suppressed_key", "human_suppressed_key", "late_explicit"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := h.UUID("service-b")
			key, safe := sd3Key(t, h, root)
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())}
			serviceRoot := root
			if mode == "unrelated" {
				serviceRoot = h.UUID("service-c")
			}
			if !strings.HasSuffix(mode, "suppressed_key") {
				input = append(input, sd3Target(assignment.TargetTypeService, serviceRoot))
			}
			if mode == "cascade_only" {
				input = input[1:]
			}
			if mode == "suppressed_parent" {
				_, err := db.Exec(`CREATE FUNCTION sd4_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER sd4_suppress BEFORE DELETE ON services FOR EACH ROW EXECUTE FUNCTION sd4_suppress()`)
				require.NoError(t, err)
			}
			if strings.HasSuffix(mode, "suppressed_key") || mode == "late_explicit" {
				body := `RETURN NULL;`
				if mode == "late_explicit" {
					body = `IF pg_trigger_depth()=1 THEN RETURN NULL; END IF; RETURN OLD;`
				}
				_, err := db.Exec(`CREATE FUNCTION sd4_suppress() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ` + body + ` END $$; CREATE TRIGGER sd4_suppress BEFORE DELETE ON integration_keys FOR EACH ROW EXECUTE FUNCTION sd4_suppress()`)
				require.NoError(t, err)
			}
			ctx := sd3System()
			if mode == "human_suppressed_key" {
				ikSetAuthority(t, h, "ORG_MEMBER", true)
				ctx = servicePlatformAdminContext(t, h)
			}
			ok, err := sd3App(h).Mutation().DeleteAll(ctx, input)
			if mode == "human_suppressed_key" {
				require.ErrorIs(t, err, sql.ErrNoRows)
				require.False(t, ok)
				require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", key.String()))
				require.Zero(t, sd4Count(t, h))
				return
			}

			require.NoError(t, err)
			require.True(t, ok)
			roots := 0
			if mode == "unrelated" || mode == "suppressed_parent" {
				roots = 1
			}
			require.Equal(t, roots, sd4Count(t, h))
			if roots == 1 {
				var resource, parent, org string
				require.NoError(t, db.QueryRow(`SELECT root_resource_id,parent_service_id,target_organization_id FROM integration_key_delete_audit_events WHERE record_kind='success_witness'`).Scan(&resource, &parent, &org))
				require.Equal(t, safe.String(), resource)
				require.Equal(t, root, parent)
				require.Equal(t, h.UUID("org-b"), org)
			}

			if mode == "suppressed_key" {
				require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", key.String()))
				require.Zero(t, sd1Count(t, h, "committed"))
				return
			}
			require.Zero(t, serviceManagementCount(t, h, "integration_keys", key.String()))
			if mode == "suppressed_parent" {
				require.Zero(t, sd1Count(t, h, "committed"))
				return
			}
			effects := sd3Effects(t, h, serviceRoot)
			if mode == "unrelated" {
				require.Empty(t, effects)
				return
			}
			require.Len(t, effects, 1)
			require.Equal(t, safe, *effects[0].ResourceUUID)
			provenance, mechanism := "EXPLICIT", "explicit_sql"
			if mode == "cascade_only" {
				provenance, mechanism = "CASCADE", "fk_cascade"
			}
			if mode == "late_explicit" {
				mechanism = "fk_cascade"
			}
			require.Equal(t, provenance, effects[0].Provenance)
			require.Equal(t, mechanism, effects[0].DeletionMechanism)
		})
	}
}
func TestIntegrationKeyDeleteAuditMixedAtomicity(t *testing.T) {
	for _, mode := range []string{"success", "all_typed_success", "key_append_failure", "all_typed_key_append_failure", "cmnr_append_failure", "late_group_failure", "key_postcheck_failure", "schema_missing"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			ikSetAuthority(t, h, "ORG_ADMIN", true)
			key := sd4SensitiveKey(t, h, h.UUID("service-b"))
			cm, nr := uuid.New(), uuid.New()
			_, err := db.Exec(`INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'SD4 CM','{"Type":"builtin-smtp-email","Args":{"email_address":"sd4@example.invalid"}}')`, cm, h.UUID("user-a"))
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, nr, h.UUID("user-a"), cm)
			require.NoError(t, err)
			targets := []string{fmt.Sprintf(`{type:contactMethod,id:%q},{type:notificationRule,id:%q}`, cm, nr)}
			if strings.HasPrefix(mode, "all_typed_") {
				targets = append(targets, fmt.Sprintf(`{type:service,id:%q}`, h.UUID("service-c")))
			}
			if mode == "late_group_failure" {
				targets = append(targets, fmt.Sprintf(`{type:escalationPolicy,id:%q}`, h.UUID("missing-policy")))
			}
			if strings.HasSuffix(mode, "key_append_failure") || mode == "cmnr_append_failure" {
				table := "integration_key_delete_audit_events"
				if mode == "cmnr_append_failure" {
					table = "user_cmnr_delete_audit_events"
				}
				_, err = db.Exec(`CREATE FUNCTION sd4_append_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_DRIVER_SECRET aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa SYNTHETIC_TOKEN_SECRET SYNTHETIC_HASH_SECRET SYNTHETIC_PREFIX_SECRET SYNTHETIC_NAME_SECRET https://synthetic.invalid/credential'; END $$; CREATE TRIGGER sd4_append_fail BEFORE INSERT ON ` + table + ` FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd4_append_fail()`)
				require.NoError(t, err)
			}
			if mode == "key_postcheck_failure" {
				_, err = db.Exec(`CREATE FUNCTION sd4_reinsert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO integration_keys(id,service_id,type,name,audit_resource_id) VALUES(OLD.id,OLD.service_id,OLD.type,OLD.name,OLD.audit_resource_id); RETURN OLD; END $$; CREATE TRIGGER sd4_reinsert AFTER DELETE ON integration_keys FOR EACH ROW EXECUTE FUNCTION sd4_reinsert()`)
				require.NoError(t, err)
			}
			if mode == "schema_missing" {
				_, err = db.Exec(`ALTER TABLE integration_key_delete_audit_events RENAME TO sd4_hidden_audit`)
				require.NoError(t, err)
				h.IgnoreErrorsWith("audit persistence unavailable")
			}
			var expectedError func()
			if mode != "success" && mode != "all_typed_success" && mode != "schema_missing" {
				message := "deleteAll transaction failed"
				if mode == "late_group_failure" {
					message = "sql: no rows in result set"
				}
				expectedError = h.ExpectBackendError(message)
			}
			r := stepOrganizationQuery(t, h, sd4Query([]uuid.UUID{key}, targets...))
			if expectedError != nil {
				expectedError()
			}

			if mode == "schema_missing" {
				_, err = db.Exec(`ALTER TABLE sd4_hidden_audit RENAME TO integration_key_delete_audit_events`)
				require.NoError(t, err)
			}
			if mode == "success" || mode == "all_typed_success" {
				require.Empty(t, r.Errors)
				require.Equal(t, 1, sd4Count(t, h))
				require.Equal(t, 2, cmnrAuditCount(t, h, "success_witness"))
				var requests, executions, attempts int
				require.NoError(t, db.QueryRow(`SELECT count(DISTINCT request_id),count(DISTINCT execution_id),count(DISTINCT attempt_id) FROM (SELECT request_id,execution_id,attempt_id FROM integration_key_delete_audit_events UNION ALL SELECT request_id,execution_id,attempt_id FROM user_cmnr_delete_audit_events UNION ALL SELECT request_id,execution_id,attempt_id FROM service_delete_audit_events)e`).Scan(&requests, &executions, &attempts))
				require.Equal(t, []int{1, 1, 1}, []int{requests, executions, attempts})
			} else {
				require.NotEmpty(t, r.Errors)
				require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", key.String()))
				require.Equal(t, 1, serviceManagementCount(t, h, "user_contact_methods", cm.String()))
				require.Equal(t, 1, serviceManagementCount(t, h, "user_notification_rules", nr.String()))
				require.Zero(t, sd4Count(t, h))
				require.Zero(t, cmnrAuditCount(t, h, "success_witness"))
				require.NotContains(t, r.Errors[0].Message, "SYNTHETIC_")
				require.NotContains(t, r.Errors[0].Message, key.String())
				require.NotContains(t, r.Errors[0].Message, "synthetic.invalid")
			}
			if strings.HasPrefix(mode, "all_typed_") {
				want := 1
				if mode == "all_typed_success" {
					want = 0
				}
				require.Equal(t, want, serviceManagementCount(t, h, "services", h.UUID("service-c")))
				require.Equal(t, 1-want, sd1Count(t, h, "committed"))
			}
			raw := sd4Rows(t, h) + cmnrAuditRows(t, h) + sd1Rows(t, h)
			require.NotContains(t, raw, key.String())
			require.NotContains(t, raw, "SYNTHETIC_")
			require.NotContains(t, raw, "sd4@example.invalid")
			require.NotContains(t, raw, "synthetic.invalid")
		})
	}
}
func TestIntegrationKeyDeleteAuditControlledCommitOverPostgres(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown", "begin_failed"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			key := sd4SensitiveKey(t, h, h.UUID("service-b"))
			var database string
			require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&database))
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			controlled.SetMaxOpenConns(1)
			app := &graphqlapp.App{DB: controlled, IntKeyStore: h.App().IntegrationKeyStore}
			var output bytes.Buffer
			logger := log.NewLogger()
			logger.SetOutput(&output)
			ctx := log.WithLogger(sd3System(), logger)
			ok, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())})
			require.Error(t, err)
			require.False(t, ok)
			require.False(t, strings.Contains(err.Error(), "SYNTHETIC_"))
			require.NotContains(t, output.String(), key.String())
			require.NotContains(t, output.String(), "SYNTHETIC_")
			require.EqualValues(t, 2, connector.begins.Load())
			want := 0
			if mode == "commit_then_error" || mode == "completion_unknown" {
				want = 1
			}
			require.Equal(t, want, sd4Count(t, h))
			require.Equal(t, 1-want, serviceManagementCount(t, h, "integration_keys", key.String()))
			var outcomes string
			require.NoError(t, db.QueryRow(`SELECT string_agg(DISTINCT outcome,',') FROM integration_key_delete_audit_events WHERE record_kind='attempt_observation'`).Scan(&outcomes))
			if mode != "begin_failed" {
				require.Equal(t, "commit_unknown", outcomes)
			}
		})
	}
}
func TestIntegrationKeyDeleteAuditParentLockWait(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	key, safe := sd3Key(t, h, h.UUID("service-b"))
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	// Move the Key while holding its lock. The delete must capture the new parent
	// and its new Normal Organization after the observed PostgreSQL lock wait.
	_, err = tx.Exec(`UPDATE integration_keys SET service_id=$2 WHERE id=$1`, key, h.UUID("service-c"))
	require.NoError(t, err)
	gate, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer gate.Close()
	var gatePID int
	require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID))
	_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_lock(990094,$1)`, gatePID)
	require.NoError(t, err)
	defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990094,$1)`, gatePID) }()
	_, err = db.Exec(fmt.Sprintf(`CREATE FUNCTION sd4_before_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(990094,%d); RETURN NEW; END $$; CREATE TRIGGER sd4_before_append BEFORE INSERT ON integration_key_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd4_before_append()`, gatePID))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	require.NoError(t, tx.Commit())
	sd3WaitBlocked(t, db, gatePID)
	// At the audit append gate all new safe capture locks must still be held.
	// Use an independent session to measure PostgreSQL locks, not pool starvation.
	var database string
	require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&database))
	cfg, err := pgx.ParseConfig(harness.DBURL(database))
	require.NoError(t, err)
	writer := stdlib.OpenDB(*cfg)
	defer writer.Close()
	for _, q := range []string{`SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE NOWAIT`, `SELECT organization_id FROM normal_organizations WHERE organization_id=$1 FOR UPDATE NOWAIT`} {
		target := h.UUID("org-c")
		if strings.Contains(q, "FROM services") {
			target = h.UUID("service-c")
		}
		lockTx, err := writer.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = lockTx.ExecContext(ctx, q, target)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55P03", pg.Code)
		require.NoError(t, lockTx.Rollback())
	}
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_unlock(990094,$1)`, gatePID)
	require.NoError(t, err)
	require.NoError(t, <-done)
	lockTx, err := writer.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = lockTx.ExecContext(ctx, `SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("service-c"))
	require.NoError(t, err)
	require.NoError(t, lockTx.Rollback())
	var parent, org, resource string
	require.NoError(t, db.QueryRow(`SELECT root_resource_id,parent_service_id,target_organization_id FROM integration_key_delete_audit_events WHERE record_kind='success_witness'`).Scan(&resource, &parent, &org))
	require.Equal(t, safe.String(), resource)
	require.Equal(t, h.UUID("service-c"), parent)
	require.Equal(t, h.UUID("org-c"), org)
}

// All values here are fixed synthetic sentinels, never usable credentials.
func sd4SensitiveKey(t *testing.T, h *harness.Harness, root string) uuid.UUID {
	t.Helper()
	id := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	_, err := h.App().DB().Exec(`INSERT INTO integration_keys(id,service_id,name,type,external_system_name) VALUES($1,$2,'SYNTHETIC_NAME_SECRET SYNTHETIC_TOKEN_SECRET SYNTHETIC_HASH_SECRET SYNTHETIC_PREFIX_SECRET','generic','https://synthetic.invalid/credential')`, id, root)
	require.NoError(t, err)
	return id
}
func TestIntegrationKeyDeleteAuditSystemMissingAndNoop(t *testing.T) {
	h := sd1Harness(t)
	a := sd3App(h)
	missing := sd3Target(assignment.TargetTypeIntegrationKey, uuid.NewString())
	ok, err := a.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{missing})
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, sd4Count(t, h))
	key := sd4SensitiveKey(t, h, h.UUID("service-b"))
	target := sd3Target(assignment.TargetTypeIntegrationKey, key.String())
	for i := 0; i < 2; i++ {
		ok, err = a.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{missing, target, target})
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, 1, sd4Count(t, h))
	}
	require.NotContains(t, sd4Rows(t, h), key.String())
	require.NotContains(t, sd4Rows(t, h), "SYNTHETIC_")
	require.NotContains(t, sd4Rows(t, h), "synthetic.invalid")
}

func TestIntegrationKeyDeleteAuditIsolationCompatibility(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var database string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&database))
	for _, isolation := range []string{"read committed", "repeatable read", "serializable"} {
		t.Run(isolation, func(t *testing.T) {
			cfg, err := pgx.ParseConfig(harness.DBURL(database))
			require.NoError(t, err)
			cfg.RuntimeParams["default_transaction_isolation"] = isolation
			isolated := stdlib.OpenDB(*cfg)
			defer isolated.Close()
			isolated.SetMaxOpenConns(2)
			var actual string
			require.NoError(t, isolated.QueryRow(`SHOW transaction_isolation`).Scan(&actual))
			require.Equal(t, isolation, actual)
			key, _ := sd3Key(t, h, h.UUID("service-b"))
			app := &graphqlapp.App{DB: isolated, IntKeyStore: h.App().IntegrationKeyStore}
			targets := []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, key.String())}
			for i := 0; i < 2; i++ {
				ok, err := app.Mutation().DeleteAll(sd3System(), targets)
				require.NoError(t, err)
				require.True(t, ok)
			}
		})
	}
	require.Equal(t, 3, sd4Count(t, h))
	require.Zero(t, sd1Count(t, h, "committed"))
}
