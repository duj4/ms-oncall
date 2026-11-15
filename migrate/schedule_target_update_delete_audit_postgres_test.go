package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// These tests require explicit opt-in AND the identity of an isolated cluster.
// They never accept an unmarked shared database as an integration substitute.
func u03NativeIdentity(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	var dir, version, address, database, marker, system string
	var tls bool
	require.NotEmpty(t, os.Getenv("MS_ONCALL_U03_TEST_CLUSTER_MARKER"))
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT current_setting('data_directory'),current_setting('server_version'),host(inet_server_addr()),current_database(),current_setting('cluster_name'),(SELECT system_identifier::text FROM pg_control_system()),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())`).Scan(&dir, &version, &address, &database, &marker, &system, &tls))
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_DATA_DIRECTORY"), dir)
	require.Equal(t, "17.11", version)
	require.Equal(t, "127.0.0.1", address)
	require.Equal(t, name, database)
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_CLUSTER_MARKER"), marker)
	require.Equal(t, os.Getenv("MS_ONCALL_U03_TEST_SYSTEM_ID"), system)
	require.Equal(t, "verify-full", os.Getenv("PGSSLMODE"))
	require.True(t, tls)
	t.Logf("isolated database=%s version=%s marker=%s system=%s TLS=verify-full", database, version, marker, system)
}

func u03SchemaEvent() sraudit.Event {
	e := sd6SchemaEvent(sraudit.Schedule)
	e.SchemaVersion, e.EffectsVersion, e.Operation = 2, 2, sraudit.ScheduleTargetUpdate
	e.Reason, e.Cause = "children_deleted", "update_induced"
	id := uuid.New()
	e.Effects = []sraudit.Effect{{EffectID: uuid.New(), ResourceType: sraudit.Rule, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		ResourceUUID: &id, Relation: "schedule.schedule_rule", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced",
		RuleDeletion: &sraudit.RuleDeleteDetail{ScheduleID: e.RootID, TargetKind: "user", TargetID: uuid.New()}}}
	return e
}

func u03SchemaAppend(t *testing.T, db *sql.DB, e sraudit.Event) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, sraudit.Append(t.Context(), tx, e))
	require.NoError(t, tx.Commit())
}

func u03HistoryRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var rows string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT jsonb_build_object('ep',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]') FROM escalation_policy_delete_audit_events e),'sr',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_id),'[]') FROM schedule_rotation_delete_audit_events e))::text`).Scan(&rows))
	return rows
}

func u03HistoryEvidence(t *testing.T, phase, rows string) {
	t.Helper()
	if dir := os.Getenv("MS_ONCALL_U03_EVIDENCE"); dir != "" {
		f, err := os.CreateTemp(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-"+phase+"-*.json")
		require.NoError(t, err)
		_, err = f.WriteString(rows + "\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())
		t.Log("full immutable audit projection:", f.Name())
	}
}

func TestPostgresScheduleTargetUpdate306FreshForwardCompatibility(t *testing.T) {
	for _, start := range []int{0, 305} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
			db, err := sql.Open("pgx", uri)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			u03NativeIdentity(t, db, name)
			ep := sd5SchemaEvent()
			updates := []epaudit.Event{ep305Event(epaudit.PolicyUpdate), ep305Event(epaudit.StepUpdate)}
			s, r := sd6SchemaEvent(sraudit.Schedule), sd6SchemaEvent(sraudit.Rotation)
			seed := func() {
				ep305Append(t, t.Context(), db, ep)
				for _, e := range updates {
					ep305Append(t, t.Context(), db, e)
				}
				u03SchemaAppend(t, db, s)
				u03SchemaAppend(t, db, r)
			}
			var before string
			if start > 0 {
				n, err := Up(t.Context(), uri, Names()[304])
				require.NoError(t, err)
				require.Equal(t, 305, n)
				seed()
				before = u03HistoryRows(t, db)
				u03HistoryEvidence(t, "before306", before)
			}
			n, err := Up(t.Context(), uri, "")
			require.NoError(t, err)
			require.Equal(t, 306-start, n)
			require.NoError(t, VerifyAll(t.Context(), uri))
			require.NoError(t, VerifyIsLatest(t.Context(), uri))
			h, err := loadEmbeddedHistory()
			require.NoError(t, err)
			require.Len(t, assertDeterministicProvenanceState(t, t.Context(), uri, h), 306)
			if start > 0 {
				after := u03HistoryRows(t, db)
				u03HistoryEvidence(t, "after306", after)
				require.Equal(t, before, after, "306 must preserve complete v1/U01/U02 rows")
			} else {
				seed()
			}
			seed() // exact historical replays remain idempotent
			// New writes by every old writer after 306, independently of replay.
			ep.EventID, ep.AttemptID = uuid.New(), uuid.New()
			ep305Append(t, t.Context(), db, ep)
			for _, e := range updates {
				e.EventID, e.AttemptID = uuid.New(), uuid.New()
				ep305Append(t, t.Context(), db, e)
			}
			for _, e := range []sraudit.Event{s, r} {
				e.EventID, e.AttemptID = uuid.New(), uuid.New()
				u03SchemaAppend(t, db, e)
			}
			e := u03SchemaEvent()
			u03SchemaAppend(t, db, e)
			u03SchemaAppend(t, db, e)
			var count int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&count))
			require.Equal(t, 1, count)
			changed := e
			changed.RequestID = uuid.New()
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			require.ErrorIs(t, sraudit.Append(t.Context(), tx, changed), sraudit.ErrConflict)
			require.NoError(t, tx.Rollback())
			for _, table := range []string{"schedule_rotation_delete_audit_events", "escalation_policy_delete_audit_events"} {
				for _, statement := range []string{"UPDATE " + table + " SET outcome=outcome", "DELETE FROM " + table, "TRUNCATE " + table} {
					_, err := db.ExecContext(t.Context(), statement)
					var pg *pgconn.PgError
					require.ErrorAs(t, err, &pg)
					require.Equal(t, "55000", pg.Code)
				}
			}
			n, err = Up(t.Context(), uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
			t.Log("fresh/forward, 306 provenance, full historical rows, five old writers, U03 writer, idempotency, conflict, append-only and repeat Up PASS")
		})
	}
}

func u03ClosedSQL(t *testing.T, ctx context.Context, db *sql.DB, e sraudit.Event, change func(map[string]any)) error {
	t.Helper()
	var raw []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e) FROM schedule_rotation_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
	var row map[string]any
	require.NoError(t, json.Unmarshal(raw, &row))
	row["event_id"], row["attempt_id"] = uuid.NewString(), uuid.NewString()
	change(row)
	raw, err := json.Marshal(row)
	require.NoError(t, err)
	// jsonb_populate_record maps a JSON null field to SQL NULL. Preserve the
	// original JSONB-null before_state instead of accidentally testing NOT NULL.
	_, err = db.ExecContext(ctx, `INSERT INTO schedule_rotation_delete_audit_events SELECT (jsonb_populate_record((SELECT e FROM schedule_rotation_delete_audit_events e WHERE event_id=$2),$1::jsonb-'before_state')).*`, string(raw), e.EventID)
	return err
}

func TestPostgresScheduleTargetUpdate306ClosedValidator(t *testing.T) {
	name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
	db, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	u03NativeIdentity(t, db, name)
	_, err = Up(t.Context(), uri, "")
	require.NoError(t, err)
	e := u03SchemaEvent()
	u03SchemaAppend(t, db, e)
	for _, mode := range []string{"correct", "rotation", "wrong_root", "wrong_org", "wrong_parent", "wrong_target", "duplicate_rule", "duplicate_effect", "empty_success", "extra_key", "extra_detail", "root_cause", "effect_cause", "failed_effects", "failure_empty"} {
		t.Run(mode, func(t *testing.T) {
			err := u03ClosedSQL(t, t.Context(), db, e, func(row map[string]any) {
				fs := row["effects"].([]any)
				f := fs[0].(map[string]any)
				d := f["rule_deletion"].(map[string]any)
				switch mode {
				case "rotation":
					d["target_kind"] = "rotation"
				case "wrong_root":
					f["root_id"] = uuid.NewString()
				case "wrong_org":
					f["target_organization_id"] = uuid.NewString()
				case "wrong_parent":
					d["schedule_id"] = uuid.NewString()
				case "wrong_target", "duplicate_rule", "duplicate_effect":
					b, err := json.Marshal(f)
					require.NoError(t, err)
					var other map[string]any
					require.NoError(t, json.Unmarshal(b, &other))
					if mode != "duplicate_effect" {
						other["effect_id"] = uuid.NewString()
					}
					if mode != "duplicate_rule" {
						other["resource_uuid"] = uuid.NewString()
					}
					if mode == "wrong_target" {
						other["rule_deletion"].(map[string]any)["target_id"] = uuid.NewString()
					}
					row["effects"] = append(fs, other)
				case "empty_success":
					row["effects"] = []any{}
				case "extra_key":
					f["extra"] = "SYNTHETIC_PRIVATE"
				case "extra_detail":
					d["extra"] = "SYNTHETIC_PRIVATE"
				case "root_cause":
					row["cause"] = "explicit_target"
				case "effect_cause":
					f["cause"] = "schedule_delete"
				case "failed_effects", "failure_empty":
					row["record_kind"], row["outcome"], row["reason_code"] = "attempt_observation", "tx_failed", "write_failed"
					row["cause"], row["provenance"], row["deletion_mechanism"] = nil, nil, nil
					if mode == "failure_empty" {
						row["effects"] = []any{}
					}
				}
			})
			if mode == "correct" || mode == "rotation" || mode == "failure_empty" {
				require.NoError(t, err)
			} else {
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "23514", pg.Code)
			}
		})
	}
}

func TestPostgresScheduleTargetUpdate306CapacityRollback(t *testing.T) {
	name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
	db, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	u03NativeIdentity(t, db, name)
	_, err = Up(t.Context(), uri, "")
	require.NoError(t, err)
	e := u03CapacityEvent(210)
	require.NoError(t, e.Validate())
	u03SchemaAppend(t, db, e)
	e = u03OversizedCapacityEvent(t)
	require.ErrorIs(t, e.Validate(), sraudit.ErrCapacity, "exact JSONB budget rejects this compact-fitting event")
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	var sqlBytes int
	var valid bool
	require.NoError(t, db.QueryRow(`SELECT octet_length($1::jsonb::text),schedule_target_update_delete_effects_valid($1::jsonb,$2,$3)`, string(raw), e.RootID, e.TargetOrganizationID).Scan(&sqlBytes, &valid))
	require.Greater(t, sqlBytes, sraudit.MaxJSONBytes)
	require.Equal(t, len(raw)+27*len(e.Effects)-1, sqlBytes)
	require.False(t, valid)
	// Go rejection leaves the transaction usable; its owner still rolls back
	// the business deletion. The separate SQL test exercises native rejection.
	fixture := newBoundedFixture(t, t.Context(), db)
	ruleID := uuid.New()
	_, err = db.Exec(`INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, ruleID, fixture.schedule, fixture.user)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`DELETE FROM schedule_rules WHERE id=$1`, ruleID)
	require.NoError(t, err)
	err = sraudit.Append(t.Context(), tx, e)
	require.ErrorIs(t, err, sraudit.ErrCapacity)
	require.NotErrorIs(t, err, sraudit.ErrUnavailable)
	var usable int
	require.NoError(t, tx.QueryRowContext(t.Context(), `SELECT 1`).Scan(&usable))
	require.Equal(t, 1, usable, "Go preflight did not abort the database transaction")
	require.NoError(t, tx.Rollback())
	var rules, witnesses int
	require.NoError(t, db.QueryRow(`SELECT (SELECT count(*) FROM schedule_rules WHERE id=$1),(SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE event_id=$2)`, ruleID, e.EventID).Scan(&rules, &witnesses))
	require.Equal(t, 1, rules)
	require.Zero(t, witnesses)
	t.Logf("normal210 PASS; effects=%d Go compact bytes=%d SQL JSONB-text bytes=%d; Validate/Append ErrCapacity, usable transaction, owner rollback, restored rule=1, witness=0 PASS", len(e.Effects), e.JSONBytes(), sqlBytes)
	e = u03CapacityEvent(sraudit.MaxEffects + 1)
	require.ErrorIs(t, e.Validate(), sraudit.ErrCapacity)
}
