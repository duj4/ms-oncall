package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	pgdump "github.com/target/goalert/devtools/pgdump-lite"
	audit "github.com/target/goalert/schedule/updateaudit"
	a1 "github.com/target/goalert/service/updateaudit"
)

const boundedAuditTable = "schedule_rotation_update_audit_events"

func boundedAuditDB(t *testing.T, position int) (context.Context, string, *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
	t.Log("task-owned isolated database:", name)
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	n, err := Up(ctx, uri, h.entries[position-1].Name)
	require.NoError(t, err)
	require.Equal(t, position, n)
	db, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return ctx, uri, db
}

func boundedEvidence(t *testing.T, db *sql.DB, label string) string {
	t.Helper()
	var data string
	err := db.QueryRow(`SELECT jsonb_build_object(
	 'database',current_database(),'version',current_setting('server_version'),
	 'ledger',(SELECT jsonb_agg(to_jsonb(p) ORDER BY canonical_position) FROM ms_oncall_migration_provenance p),
	 'gorp',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM gorp_migrations g),
	 'a1',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY event_id),'[]') FROM service_update_audit_events a),
	 'c4',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY event_id),'[]') FROM schedule_rotation_update_audit_events a),
	 'schedules',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]') FROM schedules s),
	 'rotations',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]') FROM rotations r),
	 'participants',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY rotation_id,position),'[]') FROM rotation_participants p),
	 'state',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY rotation_id),'[]') FROM rotation_state s))::text`).Scan(&data)
	require.NoError(t, err)
	if dir := os.Getenv("C4_AUDIT_EVIDENCE_DIR"); dir != "" {
		var v any
		require.NoError(t, json.Unmarshal([]byte(data), &v))
		pretty, err := json.MarshalIndent(v, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name(), "/", "-")+"-"+label+".json"), append(pretty, '\n'), 0600))
	}
	return data
}

type boundedFixture struct{ org, actor, user, schedule, rotation uuid.UUID }

func newBoundedFixture(t *testing.T, ctx context.Context, db *sql.DB) boundedFixture {
	t.Helper()
	f := boundedFixture{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations(id,canonical_name,display_name,classification) VALUES($1,$2,'synthetic C4','NORMAL')`, []any{f.org, f.org.String()}},
		{`INSERT INTO normal_organizations(organization_id,corporate_mapping_key,iana_time_zone) VALUES($1,$2,'UTC')`, []any{f.org, f.org.String()}},
		{`INSERT INTO users(id,name) VALUES($1,'synthetic C4 actor'),($2,'synthetic C4 participant')`, []any{f.actor, f.user}},
		{`INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,$3,'UTC')`, []any{f.schedule, f.org, f.schedule.String()}},
		{`INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,$3,'daily','UTC')`, []any{f.rotation, f.org, f.rotation.String()}},
		{`INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES($1,$2,$3)`, []any{uuid.New(), f.rotation, f.user}},
	} {
		_, err := db.ExecContext(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
	return f
}

func (f boundedFixture) event(op audit.Operation) audit.Event {
	id := f.schedule
	if op == audit.RotationUpdate {
		id = f.rotation
	}
	return audit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), Operation: op,
		ActorKind: "human", ActorID: f.actor, HomeOrganizationID: f.org,
		AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN",
		TargetID: id, TargetOrganizationID: f.org, Outcome: "committed", Reason: "updated", OccurredAt: time.Now().UTC(), ScheduleRowWritten: op == audit.ScheduleUpdate}
}

func boundedCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow("SELECT count(*) FROM "+boundedAuditTable).Scan(&n))
	return n
}

func TestPostgresBoundedAuditUpgradePreservation(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 290)
	f := newBoundedFixture(t, ctx, db)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, a1.Append(ctx, tx, a1.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "human", ActorID: f.actor, HomeOrganizationID: f.org, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN", ServiceID: uuid.New(), TargetOrganizationID: f.org, Outcome: "committed", Reason: "updated", OccurredAt: time.Now().UTC()}))
	require.NoError(t, tx.Commit())
	// Compare complete old audit rows, old business rows, both ledgers and old
	// audit schema/trigger definitions, including recorded/applied timestamps.
	queries := []string{
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id)::text FROM service_update_audit_events a`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM schedules a`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM rotations a`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM rotation_participants a`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY rotation_id)::text FROM rotation_state a`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY canonical_position)::text FROM ms_oncall_migration_provenance a WHERE canonical_position<=290`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY id)::text FROM gorp_migrations a WHERE id NOT IN ('20261103175233-schedule-rotation-update-audit.sql','20261107115255-existing-root-global-update-audit.sql')`,
		`SELECT jsonb_agg(to_jsonb(a) ORDER BY ordinal_position)::text FROM information_schema.columns a WHERE table_name='service_update_audit_events'`,
		`SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname)::text FROM pg_constraint WHERE conrelid='service_update_audit_events'::regclass`,
		`SELECT jsonb_agg(pg_get_triggerdef(oid) ORDER BY tgname)::text FROM pg_trigger WHERE tgrelid='service_update_audit_events'::regclass`,
		`SELECT pg_get_functiondef('service_update_audit_append_only()'::regprocedure)`,
	}
	before := make([]string, len(queries))
	for i, q := range queries {
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&before[i]))
	}
	n, err := Up(ctx, uri, "existing-root-global-update-audit")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	for i, q := range queries {
		var after string
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&after))
		require.Equal(t, before[i], after, "old snapshot %d", i)
	}
	n, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	n, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.Zero(t, n)
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	for _, target := range []string{h.entries[289].Name, h.entries[288].Name} {
		n, err = Down(ctx, uri, target)
		require.Zero(t, n)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
		require.NoError(t, VerifyAll(ctx, uri))
	}
	boundedEvidence(t, db, "after-up-and-refused-down")
}

func TestPostgresBoundedAuditMigrationAtomicity(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 290)
	_, err := db.ExecContext(ctx, "CREATE TABLE "+boundedAuditTable+"(collision boolean)")
	require.NoError(t, err)
	n, err := Up(ctx, uri, "existing-root-global-update-audit")
	require.Error(t, err)
	require.Zero(t, n)
	checkAbsent := func() {
		var functionAbsent bool
		var count int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regprocedure('schedule_rotation_audit_snapshot_valid(uuid[],uuid[],integer[],integer,bigint,integer,uuid,timestamptz,integer)') IS NULL`).Scan(&functionAbsent))
		require.True(t, functionAbsent, "DDL preceding the collision must roll back")
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM gorp_migrations`).Scan(&count))
		require.Equal(t, 290, count)
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM ms_oncall_migration_provenance`).Scan(&count))
		require.Equal(t, 290, count)
	}
	checkAbsent()
	_, err = db.ExecContext(ctx, "DROP TABLE "+boundedAuditTable)
	require.NoError(t, err)
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	m, err := parseMigrations(h)
	require.NoError(t, err)
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	_, err = conn.Begin(ctx)
	require.NoError(t, err)
	for _, stmt := range m[290].Up.statements {
		_, err = conn.Exec(ctx, stmt)
		require.NoError(t, err)
	}
	_, err = conn.Exec(ctx, insertMigrationRecord, h.entries[290].ID)
	require.NoError(t, err)
	applied, err := readAppliedMigrationRecords(ctx, conn)
	require.NoError(t, err)
	_, byID, err := validateAppliedPrefix(h, applied)
	require.NoError(t, err)
	require.NoError(t, insertAppliedProvenance(ctx, conn, h.entries[290], byID[h.entries[290].ID].AppliedAt, recordOriginCanonical))
	// Actual connection interruption after all DDL and both ledger inserts.
	require.NoError(t, conn.Close(ctx))
	checkAbsent()
	var absent bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT to_regclass('"+boundedAuditTable+"') IS NULL").Scan(&absent))
	require.True(t, absent)
	n, err = Up(ctx, uri, "existing-root-global-update-audit")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	boundedEvidence(t, db, "recovered")
}

func TestPostgresBoundedAuditHistoryFailClosed(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 291)
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer conn.Close(ctx)
	for name, mutation := range map[string]string{
		"unknown":            `INSERT INTO gorp_migrations(id,applied_at) VALUES('99999999999999-unapproved.sql',now())`,
		"missing":            `DELETE FROM gorp_migrations WHERE id='20261103125657-service-update-audit.sql'`,
		"missing-provenance": `DELETE FROM ms_oncall_migration_provenance WHERE canonical_position=291`,
		"wrong-checksum":     `UPDATE ms_oncall_migration_provenance SET content_sha256=repeat('0',64) WHERE canonical_position=290`,
		"wrong-source":       `UPDATE ms_oncall_migration_provenance SET source_binding=replace(source_binding,'5d06c43fe194baea872a76a3a8f0d1d317ada9ee',repeat('1',40)) WHERE canonical_position=291`,
		"out-of-order":       `UPDATE ms_oncall_migration_provenance SET canonical_position=999 WHERE canonical_position=291`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = conn.Exec(ctx, mutation)
			require.NoError(t, err)
			h, err := loadEmbeddedHistory()
			require.NoError(t, err)
			_, err = loadAppliedHistory(ctx, conn, h)
			require.Error(t, err)
			require.NoError(t, tx.Rollback(ctx))
		})
	}
	_, err = db.ExecContext(ctx, `INSERT INTO gorp_migrations SELECT * FROM gorp_migrations LIMIT 1`)
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	require.Equal(t, "23505", pg.Code)
	n, err := Up(ctx, uri, "existing-root-global-update-audit")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.NoError(t, VerifyAll(ctx, uri))
	boundedEvidence(t, db, "rejected-corruption-restored")
}

func TestPostgresBoundedAuditTransactions(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 291)
	type privateContextKey struct{}
	privateSentinels := []string{"synthetic-C4-SessionID", "synthetic-C4-SourceInfo", "synthetic-C4-cookie", "synthetic-C4-raw-destination", "synthetic-C4-token"}
	ctx = context.WithValue(ctx, privateContextKey{}, privateSentinels)
	f := newBoundedFixture(t, ctx, db)
	e := f.event(audit.ScheduleUpdate)
	e.RequestedFields = audit.ScheduleDescription
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE schedules SET description='synthetic-C4-private-body' WHERE id=$1`, f.schedule)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.Zero(t, boundedCount(t, db), "separate connection cannot see staged header/effects")
	var description string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT description FROM schedules WHERE id=$1`, f.schedule).Scan(&description))
	require.Empty(t, description)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, boundedCount(t, db))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT description FROM schedules WHERE id=$1`, f.schedule).Scan(&description))
	require.Equal(t, "synthetic-C4-private-body", description)
	for _, mode := range []string{"rollback", "audit-rejected", "business-rejected", "deferred-commit-rejected"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "audit-rejected" {
				_, err := db.ExecContext(ctx, `CREATE FUNCTION c4_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING MESSAGE='synthetic-C4-SQL-error-detail', DETAIL='synthetic-C4-token'; END $$; CREATE TRIGGER c4_reject BEFORE INSERT ON schedule_rotation_update_audit_events FOR EACH ROW EXECUTE FUNCTION c4_reject_audit()`)
				require.NoError(t, err)
			}
			if mode == "deferred-commit-rejected" {
				_, err := db.ExecContext(ctx, `CREATE TABLE c4_guard(id int PRIMARY KEY); CREATE TABLE c4_guard_probe(id int REFERENCES c4_guard DEFERRABLE INITIALLY DEFERRED)`)
				require.NoError(t, err)
			}
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `UPDATE schedules SET description='synthetic-C4-must-rollback' WHERE id=$1`, f.schedule)
			require.NoError(t, err)
			event := f.event(audit.ScheduleUpdate)
			if mode == "business-rejected" {
				_, err = tx.ExecContext(ctx, `UPDATE schedules SET time_zone=NULL WHERE id=$1`, f.schedule)
				require.Error(t, err)
			} else {
				if mode == "deferred-commit-rejected" {
					_, err = tx.ExecContext(ctx, `INSERT INTO c4_guard_probe VALUES(1)`)
					require.NoError(t, err)
				}
				err = audit.Append(ctx, tx, event)
				if mode == "audit-rejected" {
					require.ErrorIs(t, err, audit.ErrUnavailable)
					require.NotContains(t, err.Error(), "synthetic-C4")
				} else {
					require.NoError(t, err)
				}
			}
			if mode == "deferred-commit-rejected" {
				require.Error(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			if mode == "audit-rejected" {
				_, err = db.ExecContext(ctx, `DROP TRIGGER c4_reject ON schedule_rotation_update_audit_events; DROP FUNCTION c4_reject_audit()`)
				require.NoError(t, err)
			}
			// Positive lock-release proof on an independent session before failure append.
			probe, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = probe.ExecContext(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE NOWAIT`, f.schedule)
			require.NoError(t, err)
			require.NoError(t, probe.Rollback())
			require.Equal(t, 1, boundedCount(t, db))
			require.NoError(t, db.QueryRowContext(ctx, `SELECT description FROM schedules WHERE id=$1`, f.schedule).Scan(&description))
			require.Equal(t, "synthetic-C4-private-body", description)
		})
	}
	failure := f.event(audit.ScheduleUpdate)
	failure.Outcome = "tx_failed"
	failure.Reason = "write_failed"
	failure.ScheduleRowWritten = false
	require.NoError(t, audit.RecordFailure(db, failure))
	require.Equal(t, 2, boundedCount(t, db))
	var persisted string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(e))::text FROM schedule_rotation_update_audit_events e`).Scan(&persisted))
	for _, sentinel := range []string{"synthetic-C4-private-body", "synthetic-C4-must-rollback", "synthetic-C4-SQL-error-detail", "synthetic-C4-token"} {
		require.NotContains(t, persisted, sentinel)
	}
	for _, sentinel := range privateSentinels {
		require.NotContains(t, persisted, sentinel)
	}
	boundedEvidence(t, db, "transaction-results")
}

func TestPostgresBoundedAuditFailureObservations(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 291)
	f := newBoundedFixture(t, ctx, db)
	witness := f.event(audit.ScheduleUpdate)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, tx, witness))
	require.NoError(t, tx.Commit())
	for outcome, reason := range map[string]string{
		"denied": "authority_denied", "validation_failed": "invalid_fields", "tx_failed": "begin_failed",
		"commit_unknown": "commit_unconfirmed", "rollback_unconfirmed": "rollback_unconfirmed",
	} {
		e := witness
		e.EventID = uuid.New()
		e.Outcome, e.Reason, e.ScheduleRowWritten = outcome, reason, false
		if outcome == "denied" {
			e.ActorKind, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "unknown", "unknown", "unknown", "unknown"
			e.ActorID, e.HomeOrganizationID, e.TargetID, e.TargetOrganizationID = uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil
		}
		if outcome == "tx_failed" {
			e.ActorKind, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "internal_system", "trusted_internal_system", "internal_system", "unknown"
			e.ActorID, e.HomeOrganizationID = uuid.Nil, uuid.Nil
		}
		require.NoError(t, audit.RecordFailure(db, e))
		require.NoError(t, audit.RecordFailure(db, e), "identical independent observation dedupes")
	}
	require.Equal(t, 6, boundedCount(t, db), "committed witness coexists with separate uncertainty observations")
	var committed, unknown int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE outcome='committed'),count(*) FILTER (WHERE outcome='commit_unknown') FROM schedule_rotation_update_audit_events WHERE attempt_id=$1 AND request_id=$2`, witness.AttemptID, witness.RequestID).Scan(&committed, &unknown))
	require.Equal(t, 1, committed)
	require.Equal(t, 1, unknown)
	boundedEvidence(t, db, "independent-observations")
}

func TestPostgresBoundedAuditRotationEffects(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 291)
	f := newBoundedFixture(t, ctx, db)
	for _, mode := range []string{"scalar-shift-start", "add-duplicate-user", "replace-user", "reorder", "set-active", "remove", "clear", "empty-no-change"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE;`)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `SELECT id FROM rotations WHERE id=$1 FOR UPDATE`, f.rotation)
			require.NoError(t, err)
			e := f.event(audit.RotationUpdate)
			e.Before, err = audit.CaptureRotation(ctx, tx, f.rotation)
			require.NoError(t, err)
			switch mode {
			case "scalar-shift-start":
				e.RequestedFields = 63
				e.RotationRowWritten = true
				_, err = tx.ExecContext(ctx, `WITH s AS (UPDATE rotation_state SET shift_start=now() WHERE rotation_id=$1) UPDATE rotations SET name=name,description='synthetic-C4-rotation-secret',start_time=now(),type='hourly',shift_length=2,time_zone='UTC' WHERE id=$1`, f.rotation)
			case "add-duplicate-user":
				e.RequestedFields = audit.RotationUserIDs
				_, err = tx.ExecContext(ctx, `INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES($1,$2,$3)`, uuid.New(), f.rotation, f.user)
			case "replace-user":
				e.RequestedFields = audit.RotationUserIDs
				_, err = tx.ExecContext(ctx, `UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=0`, f.rotation, f.actor)
			case "reorder":
				e.RequestedFields = audit.RotationUserIDs
				_, err = tx.ExecContext(ctx, `UPDATE rotation_participants SET position=1-position WHERE rotation_id=$1`, f.rotation)
			case "set-active":
				e.RequestedFields = audit.RotationActiveUserIndex
				_, err = tx.ExecContext(ctx, `UPDATE rotation_state SET rotation_participant_id=(SELECT id FROM rotation_participants WHERE rotation_id=$1 AND position=1),position=1 WHERE rotation_id=$1`, f.rotation)
			case "remove":
				e.RequestedFields = audit.RotationUserIDs
				_, err = tx.ExecContext(ctx, `DELETE FROM rotation_participants WHERE rotation_id=$1 AND position=1`, f.rotation)
			case "clear":
				e.RequestedFields = audit.RotationUserIDs
				_, err = tx.ExecContext(ctx, `DELETE FROM rotation_state WHERE rotation_id=$1`, f.rotation)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `DELETE FROM rotation_participants WHERE rotation_id=$1`, f.rotation)
			}
			require.NoError(t, err)
			e.After, err = audit.CaptureRotation(ctx, tx, f.rotation)
			require.NoError(t, err)
			require.NoError(t, audit.Append(ctx, tx, e))
			require.NoError(t, tx.Commit())
			// Persisted arrays/state are checked against the independent actual rows.
			var matches bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT after_participant_count=r.participant_count
			 AND after_participant_ids=ARRAY(SELECT id FROM rotation_participants WHERE rotation_id=r.id ORDER BY position)
			 AND after_user_ids=ARRAY(SELECT user_id FROM rotation_participants WHERE rotation_id=r.id ORDER BY position)
			 AND after_positions=ARRAY(SELECT position FROM rotation_participants WHERE rotation_id=r.id ORDER BY position)
			 AND (after_state_id,after_state_position,after_state_participant_id,after_shift_start,after_state_version)
			 IS NOT DISTINCT FROM (s.id,s.position,s.rotation_participant_id,s.shift_start,s.version)
			 FROM schedule_rotation_update_audit_events e JOIN rotations r ON r.id=e.target_id LEFT JOIN rotation_state s ON s.rotation_id=r.id WHERE event_id=$1`, e.EventID).Scan(&matches))
			require.True(t, matches)
		})
	}
	require.Equal(t, 8, boundedCount(t, db))
	// A complete header plus participant/state effects also disappears together
	// on rollback. Read both business snapshots again from a new transaction.
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	e := f.event(audit.RotationUpdate)
	e.RequestedFields = audit.RotationUserIDs
	e.Before, err = audit.CaptureRotation(ctx, tx, f.rotation)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES($1,$2,$3)`, uuid.New(), f.rotation, f.user)
	require.NoError(t, err)
	e.After, err = audit.CaptureRotation(ctx, tx, f.rotation)
	require.NoError(t, err)
	require.NotNil(t, e.After.State)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.Equal(t, 8, boundedCount(t, db))
	require.NoError(t, tx.Rollback())
	probe, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = probe.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	afterRollback, err := audit.CaptureRotation(ctx, probe, f.rotation)
	require.NoError(t, err)
	require.Equal(t, e.Before, afterRollback)
	require.NoError(t, probe.Rollback())
	require.Equal(t, 8, boundedCount(t, db))
	boundedEvidence(t, db, "all-persisted-effects")
}

// Reproduce the make db-schema header and the repository's actual DumpSchema
// using only a new isolated DB. No shared mk_dump_schema name or schema fixture.
func TestPostgresBoundedAuditCanonicalSchema(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 294)
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer conn.Close(ctx)
	entries, err := migrationFS.ReadDir("migrations")
	require.NoError(t, err)
	var disk, data []string
	for _, entry := range entries {
		raw, err := migrationFS.ReadFile("migrations/" + entry.Name())
		require.NoError(t, err)
		disk = append(disk, entry.Name()+"\n")
		data = append(data, fmt.Sprintf("%x  migrate/migrations/%s\n", sha256.Sum256(raw), entry.Name()))
	}
	sort.Strings(disk)
	sort.Strings(data)
	rows, err := conn.Query(ctx, `SELECT id FROM gorp_migrations ORDER BY id`)
	require.NoError(t, err)
	var applied []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		applied = append(applied, id+"\n")
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, disk, applied)
	schema, err := pgdump.DumpSchema(ctx, conn)
	require.NoError(t, err)
	result := []byte(fmt.Sprintf("-- This file is auto-generated by \"make db-schema\"; DO NOT EDIT\n-- DATA=%x  -\n-- DISK=%x  -\n-- PSQL=%x  -\n--\n-- pgdump-lite database dump\n--\n\n%s",
		sha256.Sum256([]byte(strings.Join(data, ""))), sha256.Sum256([]byte(strings.Join(disk, ""))), sha256.Sum256([]byte(strings.Join(applied, ""))), schema.String()))
	if out := os.Getenv("C4_AUDIT_SCHEMA"); out != "" {
		require.NoError(t, os.WriteFile(out, result, 0600))
	} else {
		canonical, err := os.ReadFile("schema.sql")
		require.NoError(t, err)
		require.True(t, bytes.Equal(canonical, result), "canonical schema differs from real isolated PostgreSQL generation")
	}
	boundedEvidence(t, db, "canonical-install")
}

func TestPostgresBoundedAuditDedupeAndConstraints(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 291)
	f := newBoundedFixture(t, ctx, db)
	e := f.event(audit.RotationUpdate)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	e.Before, err = audit.CaptureRotation(ctx, tx, f.rotation)
	require.NoError(t, err)
	e.After = e.Before
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	appendOnce := func(event audit.Event) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err = audit.Append(ctx, tx, event); err != nil {
			return err
		}
		return tx.Commit()
	}
	require.NoError(t, appendOnce(e))
	for name, mutate := range map[string]func(*audit.Event){
		"attempt":        func(e *audit.Event) { e.AttemptID = uuid.New() },
		"request":        func(e *audit.Event) { e.RequestID = uuid.New() },
		"actor":          func(e *audit.Event) { e.ActorID = uuid.New() },
		"authority-role": func(e *audit.Event) { e.AuthorityRole = "platform_admin" },
		"org-role":       func(e *audit.Event) { e.AuthorityRole = "platform_admin"; e.OrganizationRole = "ORG_MEMBER" },
		"system": func(e *audit.Event) {
			e.ActorKind = "internal_system"
			e.ActorID = uuid.Nil
			e.HomeOrganizationID = uuid.Nil
			e.AuthoritySource = "trusted_internal_system"
			e.AuthorityRole = "internal_system"
			e.OrganizationRole = "unknown"
		},
		"target":              func(e *audit.Event) { e.TargetID = uuid.New() },
		"home-and-target-org": func(e *audit.Event) { e.HomeOrganizationID = uuid.New(); e.TargetOrganizationID = e.HomeOrganizationID },
		"operation": func(e *audit.Event) {
			e.Operation = audit.ScheduleUpdate
			e.Before = nil
			e.After = nil
			e.ScheduleRowWritten = true
		},
		"fields":     func(e *audit.Event) { e.RequestedFields = audit.RotationActiveUserIndex },
		"row-effect": func(e *audit.Event) { e.RequestedFields = audit.RotationName; e.RotationRowWritten = true },
		"outcome": func(e *audit.Event) {
			e.Outcome = "tx_failed"
			e.Reason = "write_failed"
			e.Before = nil
			e.After = nil
		},
		"time":                func(e *audit.Event) { e.OccurredAt = e.OccurredAt.Add(time.Microsecond) },
		"before-user":         func(e *audit.Event) { e.Before.Participants[0].UserID = uuid.New() },
		"after-user":          func(e *audit.Event) { e.After.Participants[0].UserID = uuid.New() },
		"state-id":            func(e *audit.Event) { e.After.State.ID++ },
		"state-version":       func(e *audit.Event) { e.After.State.Version++ },
		"state-shift":         func(e *audit.Event) { e.After.State.ShiftStart = e.After.State.ShiftStart.Add(time.Microsecond) },
		"state-absence":       func(e *audit.Event) { e.After.State = nil },
		"participant-effects": func(e *audit.Event) { e.After.Participants = nil; e.After.ParticipantCount = 0; e.After.State = nil },
	} {
		t.Run(name, func(t *testing.T) {
			// Independent deep copies ensure each change is compared with the original.
			copyEvent := e
			clone := func(s *audit.RotationSnapshot) *audit.RotationSnapshot {
				c := *s
				c.Participants = append([]audit.Participant(nil), s.Participants...)
				if s.State != nil {
					state := *s.State
					c.State = &state
				}
				return &c
			}
			copyEvent.Before = clone(e.Before)
			copyEvent.After = clone(e.After)
			mutate(&copyEvent)
			require.ErrorIs(t, appendOnce(copyEvent), audit.ErrConflict)
		})
	}
	// A second connection must wait on the actual unique index, then dedupe.
	concurrent := e
	concurrent.EventID = uuid.New()
	first, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, first, concurrent))
	done := make(chan error, 1)
	go func() { done <- appendOnce(concurrent) }()
	require.Eventually(t, func() bool {
		var waiters int
		err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
		 AND wait_event_type='Lock' AND query LIKE 'INSERT INTO schedule_rotation_update_audit_events%'`).Scan(&waiters)
		return err == nil && waiters == 1
	}, 2*time.Second, 10*time.Millisecond, "observe the second INSERT actually waiting in PostgreSQL")
	t.Log("real PostgreSQL unique-index lock wait observed before releasing first transaction")
	select {
	case err := <-done:
		t.Fatalf("unique-key wait ended before first commit: %v", err)
	default:
	}
	require.NoError(t, first.Commit())
	require.NoError(t, <-done)
	require.Equal(t, 2, boundedCount(t, db))
	// Bypass the typed writer to exercise real PG constraints for every class.
	rows, err := db.QueryContext(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name=$1 ORDER BY ordinal_position`, boundedAuditTable)
	require.NoError(t, err)
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	for name, overrides := range map[string]map[string]string{
		"zero-event":               {"event_id": "'00000000-0000-0000-0000-000000000000'::uuid"},
		"zero-actor":               {"actor_id": "'00000000-0000-0000-0000-000000000000'::uuid"},
		"missing-actor":            {"actor_id": "NULL"},
		"untrusted-authority":      {"authority_source": "'untrusted'"},
		"foreign-human":            {"target_organization_id": "gen_random_uuid()"},
		"missing-target-org":       {"target_organization_id": "NULL"},
		"bad-operation":            {"operation": "'service.update'"},
		"bad-target-type":          {"target_type": "'schedule'"},
		"unknown-success":          {"actor_kind": "'unknown'"},
		"member-success":           {"authority_role": "'org_member'", "organization_role": "'ORG_MEMBER'"},
		"schema-version":           {"schema_version": "2"},
		"mask":                     {"requested_fields": "256"},
		"outcome-reason":           {"reason_code": "'write_failed'"},
		"missing-effects":          {"after_participant_ids": "NULL"},
		"effect-count":             {"after_participant_count": "2"},
		"effect-array-length":      {"after_user_ids": "'{}'::uuid[]"},
		"effect-array-null":        {"after_user_ids": "ARRAY[NULL]::uuid[]"},
		"effect-array-zero":        {"after_user_ids": "ARRAY['00000000-0000-0000-0000-000000000000']::uuid[]"},
		"effect-negative-position": {"after_positions": "ARRAY[-1]"},
		"effect-lower-bound":       {"after_positions": "'[0:0]={0}'::integer[]"},
		"effect-state-partial":     {"after_state_version": "NULL"},
		"effect-state-target":      {"after_state_participant_id": "gen_random_uuid()"},
		"effect-state-position":    {"after_state_position": "3"},
		"effect-state-infinite":    {"after_shift_start": "'infinity'::timestamptz"},
		"effect-on-failure":        {"outcome": "'tx_failed'", "reason_code": "'write_failed'"},
	} {
		t.Run(name, func(t *testing.T) {
			exprs := append([]string(nil), cols...)
			for i, c := range cols {
				if c == "event_id" {
					exprs[i] = "gen_random_uuid()"
				}
				if v, ok := overrides[c]; ok {
					exprs[i] = v
				}
			}
			_, err := db.ExecContext(ctx, "INSERT INTO "+boundedAuditTable+" ("+strings.Join(cols, ",")+") SELECT "+strings.Join(exprs, ",")+" FROM "+boundedAuditTable+" WHERE event_id=$1", e.EventID)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Contains(t, []string{"23514", "23502"}, pg.Code)
		})
	}
	for _, statement := range []string{"UPDATE " + boundedAuditTable + " SET reason_code=reason_code", "DELETE FROM " + boundedAuditTable, "TRUNCATE " + boundedAuditTable} {
		_, err := db.ExecContext(ctx, statement)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	before := boundedCount(t, db)
	for _, q := range []struct {
		q  string
		id uuid.UUID
	}{
		{"DELETE FROM schedules WHERE id=$1", f.schedule}, {"DELETE FROM rotations WHERE id=$1", f.rotation},
		{"DELETE FROM users WHERE id=$1", f.actor}, {"DELETE FROM users WHERE id=$1", f.user},
		{"DELETE FROM normal_organizations WHERE organization_id=$1", f.org}, {"DELETE FROM organizations WHERE id=$1", f.org},
	} {
		_, err := db.ExecContext(ctx, q.q, q.id)
		require.NoError(t, err)
	}
	require.Equal(t, before, boundedCount(t, db))
	var persistence string
	var fks, publicGrants int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT relpersistence FROM pg_class WHERE oid='"+boundedAuditTable+"'::regclass").Scan(&persistence))
	require.Equal(t, "p", persistence)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='"+boundedAuditTable+"'::regclass").Scan(&fks))
	require.Zero(t, fks)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM pg_class c, LATERAL aclexplode(c.relacl) a WHERE c.oid='"+boundedAuditTable+"'::regclass AND a.grantee=0").Scan(&publicGrants))
	require.Zero(t, publicGrants)
	boundedEvidence(t, db, "history-after-resource-user-org-deletion")
}

func TestBoundedAuditCanonicalTail(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(h.entries), 294)
	e := h.entries[290]
	require.EqualValues(t, 291, e.Position)
	require.Equal(t, "ms-oncall-schedule-rotation-update-audit-d09-c4", e.BundleID)
	require.Equal(t, h.entries[289].ID, e.PredecessorID)
	source, err := parseCanonicalSourceBinding(e.SourceBinding)
	require.NoError(t, err)
	require.Equal(t, "5d06c43fe194baea872a76a3a8f0d1d317ada9ee", source.BaseCommit)
	require.Equal(t, "105de9799900cf5f20028808ad6bb926b9049621", source.BaseTree)
	require.Equal(t, "ed31bb51e6c1f6f79a835fdc4aab597ebc72e699", source.AuthorizationCommit)
	require.Contains(t, e.DependencyEvidence, h.entries[289].SHA256)
	require.Equal(t, "MS_ONCALL", e.Provenance)
	t.Logf("position %d %s sha256=%s", e.Position, e.ID, e.SHA256)
	require.EqualValues(t, 292, h.entries[291].Position)
	require.Equal(t, "20261107115255-existing-root-global-update-audit.sql", h.entries[291].ID)
	require.Equal(t, e.ID, h.entries[291].PredecessorID)
}
