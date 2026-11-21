package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
)

func TestPostgresScheduleJSONMigration308AndRawConstraints(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 307)
	var version, oldBefore, oldAfter string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	const old = `SELECT coalesce(jsonb_agg(jsonb_build_array(c.conrelid::regclass::text,c.conname,pg_get_constraintdef(c.oid)) ORDER BY c.conrelid::regclass::text,c.conname),'[]')::text FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid WHERE t.relname LIKE 'schedule_rotation_delete_audit%'`
	require.NoError(t, db.QueryRowContext(ctx, old).Scan(&oldBefore))
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-307, n)
	require.NoError(t, db.QueryRowContext(ctx, old).Scan(&oldAfter))
	require.Equal(t, oldBefore, oldAfter)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	b := []audit.Coverage{{Kind: "temporary", Start: "0", End: "100"}}
	a := []audit.Coverage{{Kind: "temporary", Start: "0", End: "30"}, {Kind: "temporary", Start: "70", End: "100"}}
	effects, err := audit.Diff(b, a)
	require.NoError(t, err)
	e := audit.Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: uuid.New(), OrganizationID: uuid.New(), EnvelopeID: 1, Operation: audit.Clear, Mode: "clear", OccurredAt: time.Now(), Before: b, After: a, Effects: effects}
	tx := userPhaseATx(t, ctx, db)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events`))
	for name, patch := range map[string]map[string]any{
		"version": {"schema_version": 2}, "root_delete": {"operation": "schedule.delete"}, "root": {"root_type": "user"}, "mode": {"update_mode": "set"},
		"actor": {"actor_kind": "human"}, "missing_actor": {"actor_id": uuid.NewString()}, "zero_identity": {"schedule_id": uuid.Nil.String()}, "empty_envelope": {"envelope_id": 0},
		"null_before": {"before_coverage": nil}, "wrong_shape": {"before_coverage": map[string]any{}}, "null_after": {"after_coverage": nil},
		"invalid_range":  {"after_coverage": []audit.Coverage{{Kind: "temporary", Start: "10", End: "0"}}},
		"outside_range":  {"after_coverage": []audit.Coverage{{Kind: "temporary", Start: "-62135596800000000001", End: "0"}}},
		"missing_effect": {"effects": []audit.Effect{}, "effect_count": 0}, "wrong_count": {"effect_count": 0},
		"duplicate_effect":        {"effects": []audit.Effect{effects[0], effects[0]}, "effect_count": 2},
		"bad_source":              {"effects": []map[string]any{{"kind": "temporary", "user_id": "", "start_ns": "30", "end_ns": "70", "change": "coverage_removed", "source": "CASCADE"}}},
		"added_in_clear":          {"before_coverage": a, "after_coverage": b, "effects": []map[string]any{{"kind": "temporary", "user_id": "", "start_ns": "30", "end_ns": "70", "change": "coverage_added", "source": "EXPLICIT"}}},
		"incomplete_projection":   {"after_coverage": []map[string]any{{"kind": "temporary", "start_ns": "0", "end_ns": "30"}}},
		"unknown_field":           {"after_coverage": []map[string]any{{"kind": "temporary", "user_id": "", "start_ns": "0", "end_ns": "30", "secret": "synthetic-forbidden-field"}}},
		"shift_without_temporary": {"after_coverage": []audit.Coverage{{Kind: "fixed_shift", UserID: uuid.NewString(), Start: "0", End: "30"}}},
	} {
		t.Run(name, func(t *testing.T) {
			patch["event_id"] = uuid.NewString()
			patch["attempt_id"] = uuid.NewString()
			raw, err := json.Marshal(patch)
			require.NoError(t, err)
			tx := userPhaseATx(t, ctx, db)
			_, err = tx.ExecContext(ctx, `INSERT INTO schedule_json_update_audit_events SELECT (jsonb_populate_record(NULL::schedule_json_update_audit_events,to_jsonb(a)||$2::jsonb)).* FROM schedule_json_update_audit_events a WHERE event_id=$1`, e.EventID, raw)
			require.Error(t, err, "raw INSERT must be rejected independently of Go validation")
			require.NoError(t, tx.Rollback())
		})
	}
	tx = userPhaseATx(t, ctx, db)
	conflict := e
	conflict.RequestID = uuid.New()
	require.Error(t, audit.Append(ctx, tx, conflict))
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events`))
}

func TestPostgresScheduleJSONUpdateVersionDrift(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f := newUserPhaseAFixture(t, ctx, db)
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	id := f.newSchedule(t, ctx)
	temp := userPhaseATemp(f.user)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
	input := map[string]any{"scheduleID": id.String(), "start": temp.Start, "end": temp.End}
	p, errs := scheduleJSONHTTP(t, ctx, app, input, true, false)
	require.Empty(t, errs)
	input["confirmation"] = scheduleJSONConfirm(p)
	before := scheduleJSONInventory(t, ctx, db, id)
	input["end"] = temp.End.Add(time.Hour)
	_, errs = scheduleJSONHTTP(t, ctx, app, input, true, true)
	require.NotEmpty(t, errs)
	require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
	input["end"] = temp.End
	enforcementExec(t, ctx, db, `UPDATE schedules SET time_zone='Asia/Shanghai' WHERE id=$1`, id)
	_, errs = scheduleJSONHTTP(t, ctx, app, input, true, true)
	require.NotEmpty(t, errs)
	require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
}

// A concurrent read of the audit and JSON cannot see only one committed side.
func scheduleJSONNoPartial(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID, old string) {
	t.Helper()
	require.Equal(t, old, scheduleJSONInventory(t, ctx, db, id))
}

func TestPostgresScheduleJSON308AuditCoexistence(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 307)
	// Existing accepted v1/v2 appenders, with all their original validators.
	scheduleV1, rotationV1, updateV2 := sd6SchemaEvent(sraudit.Schedule), sd6SchemaEvent(sraudit.Rotation), u03SchemaEvent()
	for _, e := range []sraudit.Event{scheduleV1, rotationV1, updateV2} {
		u03SchemaAppend(t, db, e)
	}
	before := u03HistoryRows(t, db)
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-307, n)
	require.Equal(t, before, u03HistoryRows(t, db), "old audit rows must be byte-equivalent after 308")
	for _, e := range []sraudit.Event{scheduleV1, rotationV1, updateV2} {
		u03SchemaAppend(t, db, e)
	}
	require.Equal(t, before, u03HistoryRows(t, db), "exact old-event replay remains idempotent")
	for _, e := range []sraudit.Event{sd6SchemaEvent(sraudit.Schedule), sd6SchemaEvent(sraudit.Rotation), u03SchemaEvent()} {
		u03SchemaAppend(t, db, e)
	}
	for _, table := range []string{"schedule_rotation_delete_audit_events", "schedule_json_update_audit_events"} {
		for _, statement := range []string{"UPDATE " + table + " SET operation=operation", "DELETE FROM " + table, "TRUNCATE " + table} {
			_, err := db.ExecContext(ctx, statement)
			require.Error(t, err)
			jsonWriterCode(t, err, "55000")
		}
	}
	n, err = Down(ctx, uri, Names()[306])
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyIsLatest(ctx, uri))
}
