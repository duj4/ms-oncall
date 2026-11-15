package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

func u03CapacityEvent(n int) sraudit.Event {
	e := u03SchemaEvent()
	template := e.Effects[0]
	e.Effects = make([]sraudit.Effect, n)
	for i := range e.Effects {
		id := uuid.New()
		f := template
		f.ResourceUUID, f.EffectID = &id, uuid.New()
		e.Effects[i] = f
	}
	return e
}

func u03OversizedCapacityEvent(t *testing.T) sraudit.Event {
	t.Helper()
	// Preserve the original counterexample: compact JSON fits, JSONB text does
	// not. Validate checks its closed semantics before the exact byte guard.
	e := u03CapacityEvent(15650)
	require.LessOrEqual(t, len(e.Effects), sraudit.MaxEffects)
	require.Equal(t, 8388401, e.JSONBytes())
	require.LessOrEqual(t, e.JSONBytes(), sraudit.MaxJSONBytes)
	require.Equal(t, 8810950, e.JSONBytes()+27*len(e.Effects)-1)
	for start := 0; start < len(e.Effects); start += 210 {
		bounded := e
		bounded.Effects = e.Effects[start:min(start+210, len(e.Effects))]
		require.NoError(t, bounded.Validate(), "every bounded projection is semantically valid")
	}
	require.ErrorIs(t, e.Validate(), sraudit.ErrCapacity)
	return e
}

// This small transport records the actual production Writer statement and its
// database/sql-converted arguments; it owns no persistence or validation logic.
// An unexpected query/prepare fails, so a zero execution count cannot hide SQL.
type u03AppendRecorder struct {
	calls int
	query string
	args  []driver.NamedValue
}

func (r *u03AppendRecorder) Connect(context.Context) (driver.Conn, error) { return r, nil }
func (r *u03AppendRecorder) Driver() driver.Driver                        { return r }
func (r *u03AppendRecorder) Open(string) (driver.Conn, error)             { return r, nil }
func (r *u03AppendRecorder) Close() error                                 { return nil }
func (r *u03AppendRecorder) Begin() (driver.Tx, error)                    { return r, nil }
func (r *u03AppendRecorder) Commit() error                                { return nil }
func (r *u03AppendRecorder) Rollback() error                              { return nil }
func (r *u03AppendRecorder) Prepare(string) (driver.Stmt, error) {
	r.calls++
	return nil, errors.New("unexpected audit statement preparation")
}
func (r *u03AppendRecorder) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	r.calls++
	r.query, r.args = query, append([]driver.NamedValue(nil), args...)
	return driver.RowsAffected(1), nil
}

func u03RecordAppend(t *testing.T, e sraudit.Event, want error) *u03AppendRecorder {
	t.Helper()
	r := new(u03AppendRecorder)
	db := sql.OpenDB(r)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	err = sraudit.Append(t.Context(), tx, e)
	if want == nil {
		require.NoError(t, err)
	} else {
		require.ErrorIs(t, err, want)
		require.NotErrorIs(t, err, sraudit.ErrUnavailable)
	}
	require.NoError(t, tx.Rollback())
	return r
}

func TestScheduleTargetUpdate306CapacityPreflightNoSQL(t *testing.T) {
	e := u03OversizedCapacityEvent(t)
	r := u03RecordAppend(t, e, sraudit.ErrCapacity)
	require.Zero(t, r.calls, "capacity rejection must precede every SQL execution")
	require.Empty(t, r.query)
	require.Empty(t, r.args)
	require.ErrorIs(t, sraudit.Append(t.Context(), nil, e), sraudit.ErrCapacity)
	t.Log("Validate=ErrCapacity; Append=ErrCapacity; driver SQL calls=0; no ErrUnavailable PASS")
}

func TestPostgresScheduleTargetUpdate306SQLCapacityConstraint(t *testing.T) {
	name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
	db, err := sql.Open("pgx", uri)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	u03NativeIdentity(t, db, name)
	n, err := Up(t.Context(), uri, "")
	require.NoError(t, err)
	require.Equal(t, 306, n)
	require.NoError(t, VerifyAll(t.Context(), uri))
	require.NoError(t, VerifyIsLatest(t.Context(), uri))

	e := u03OversizedCapacityEvent(t)
	bounded := e
	bounded.Effects = e.Effects[:210]
	r := u03RecordAppend(t, bounded, nil)
	require.Equal(t, 1, r.calls)
	require.Len(t, r.args, 26)
	require.Contains(t, r.query, "INSERT INTO schedule_rotation_delete_audit_events (")
	args := make([]any, len(r.args))
	for i, arg := range r.args {
		args[i] = arg.Value
	}
	// The exact captured INSERT succeeds with the same header and bounded
	// canonical Effects. Roll it back before changing only its Effects argument.
	control, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = control.Rollback() }()
	_, err = control.ExecContext(t.Context(), r.query, args...)
	require.NoError(t, err, "actual Writer SQL and all non-capacity fields are valid")
	require.NoError(t, control.Rollback())
	// Get the oversized bytes from the same canonical projection as the Writer.
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	args[22] = string(raw)
	var sqlBytes, count int
	var valid bool
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT octet_length($1::jsonb::text),jsonb_array_length($1::jsonb),schedule_target_update_delete_effects_valid($1::jsonb,$2,$3)`, string(raw), e.RootID, e.TargetOrganizationID).Scan(&sqlBytes, &count, &valid))
	require.Equal(t, len(e.Effects), count)
	require.Equal(t, len(raw)+27*count-1, sqlBytes)
	require.Equal(t, 8810950, sqlBytes)
	require.False(t, valid)

	fixture := newBoundedFixture(t, t.Context(), db)
	ruleID, probeID := uuid.New(), uuid.New()
	_, err = db.ExecContext(t.Context(), `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, ruleID, fixture.schedule, fixture.user)
	require.NoError(t, err)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	deleted, err := tx.ExecContext(t.Context(), `DELETE FROM schedule_rules WHERE id=$1`, ruleID)
	require.NoError(t, err)
	deletedCount, err := deleted.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, deletedCount)
	_, err = tx.ExecContext(t.Context(), `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, probeID, fixture.schedule, fixture.user)
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), r.query, args...)
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	t.Logf("native rejection SQLSTATE=%s schema=%s table=%s constraint=%s validator=schedule_target_update_delete_effects_valid", pg.Code, pg.SchemaName, pg.TableName, pg.ConstraintName)
	require.Equal(t, "23514", pg.Code)
	require.Equal(t, "schedule_rotation_delete_audit_events", pg.TableName)
	require.Equal(t, "schedule_rotation_delete_audit_events_check1", pg.ConstraintName)
	require.NoError(t, tx.Rollback())
	var definition string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='schedule_rotation_delete_audit_events'::regclass AND conname=$1`, pg.ConstraintName).Scan(&definition))
	require.Contains(t, definition, "schedule_target_update_delete_effects_valid")
	var rules, probes, witnesses, effects int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM schedule_rules WHERE id=$1),(SELECT count(*) FROM schedule_rules WHERE id=$2),(SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE event_id=$3),(SELECT coalesce(sum(jsonb_array_length(effects)),0) FROM schedule_rotation_delete_audit_events WHERE event_id=$3)`, ruleID, probeID, e.EventID).Scan(&rules, &probes, &witnesses, &effects))
	require.Equal(t, 1, rules)
	require.Zero(t, probes)
	require.Zero(t, witnesses)
	require.Zero(t, effects)
	t.Logf("fresh0->306; actual Writer INSERT bounded control PASS; N=%d C=%d D=%d; native rollback PASS; restored rule=1 business probe=0 audit row=0 partial/truncated Effects=0", count, len(raw), sqlBytes)
}
