package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

type sd8EmptyPage struct{}

func (sd8EmptyPage) Columns() []string         { return []string{"type", "key", "payload", "bytes"} }
func (sd8EmptyPage) Close() error              { return nil }
func (sd8EmptyPage) Next([]driver.Value) error { return io.EOF }

type sd8FaultRows struct {
	driver.Rows
	interrupt, wrongIdentity bool
	seen                     bool
}

func (r *sd8FaultRows) Next(values []driver.Value) error {
	if r.interrupt && r.seen {
		return io.ErrUnexpectedEOF
	}
	err := r.Rows.Next(values)
	if err == nil {
		r.seen = true
		if r.wrongIdentity {
			values[0] = uuid.NewString()
		}
	}
	return err
}

func TestUserDeleteAuditPageAndTempFaults(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"temp_write_error", "temp_suppressed_insert", "missing_page", "duplicate_page", "page_rows_error", "wrong_returning", "wrong_manifest"} {
		t.Run(mode, func(t *testing.T) {
			u := smokeOwnedUser(t, h)
			var hits atomic.Int64
			sd8Exec(t, h, `CREATE SEQUENCE sd8_temp_hits`)
			t.Cleanup(func() { sd8Exec(t, h, `DROP SEQUENCE sd8_temp_hits`) })
			sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,$2,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM generate_series(1,300) g`, s, u)
			connector, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			app := sd7App(h)
			app.DB = controlled
			if strings.HasPrefix(mode, "temp_") {
				connector.afterExec = func(ctx context.Context, c driver.Conn, q string) error {
					if !strings.HasPrefix(q, "CREATE TEMP TABLE sd8_user_delete_witness") {
						return nil
					}
					body := `RAISE EXCEPTION USING ERRCODE='53100',MESSAGE='SYNTHETIC_PRIVATE';`
					if mode == "temp_suppressed_insert" {
						body = `RETURN NULL;`
					}
					_, err := c.(driver.ExecerContext).ExecContext(ctx, `CREATE FUNCTION pg_temp.sd8_temp_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('sd8_temp_hits'); `+body+`END;$$;CREATE TRIGGER sd8_temp_fault BEFORE INSERT ON pg_temp.sd8_user_delete_witness FOR EACH ROW EXECUTE FUNCTION pg_temp.sd8_temp_fault()`, nil)
					return err
				}
			}
			pages := 0
			connector.queryHook = func(ctx context.Context, c driver.Conn, q string, args []driver.NamedValue) (driver.Rows, error, bool) {
				if mode == "wrong_returning" && strings.HasPrefix(q, "DELETE FROM users WHERE id=$1 RETURNING") {
					rows, err := c.(driver.QueryerContext).QueryContext(ctx, q, args)
					if err != nil {
						return nil, err, true
					}
					hits.Add(1)
					return &sd8FaultRows{Rows: rows, wrongIdentity: true}, nil, true
				}
				if !strings.HasPrefix(q, `SELECT resource_type,resource_key,payload::text,octet_length(payload::text)`) {
					return nil, nil, false
				}
				pages++
				if mode == "page_rows_error" {
					rows, err := c.(driver.QueryerContext).QueryContext(ctx, q, args)
					if err != nil {
						return nil, err, true
					}
					hits.Add(1)
					return &sd8FaultRows{Rows: rows, interrupt: true}, nil, true
				}
				if pages == 2 && mode == "missing_page" {
					hits.Add(1)
					return sd8EmptyPage{}, nil, true
				}
				if pages == 2 && mode == "duplicate_page" {
					hits.Add(1)
					args[1].Value = ""
					args[2].Value = ""
					rows, err := c.(driver.QueryerContext).QueryContext(ctx, q, args)
					return rows, err, true
				}
				return nil, nil, false
			}
			if mode == "wrong_manifest" {
				connector.beforeExec = func(_ context.Context, _ driver.Conn, q string, args []driver.NamedValue) error {
					if !strings.HasPrefix(q, `INSERT INTO user_delete_audit_events`) {
						return nil
					}
					var object map[string]json.RawMessage
					if err := json.Unmarshal([]byte(args[0].Value.(string)), &object); err != nil {
						return err
					}
					if string(object["record_kind"]) != `"success_witness"` {
						return nil
					}
					object["effect_json_bytes"] = json.RawMessage("1")
					raw, err := json.Marshal(object)
					if err != nil {
						return err
					}
					args[0].Value = string(raw)
					hits.Add(1)
					return nil
				}
			}
			before := smokeUserBusinessState(t, h)
			ok, err := smokeDeleteAll(t, h, app, permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.Error(t, err)
			require.False(t, ok)
			if strings.HasPrefix(mode, "temp_") {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM sd8_temp_hits WHERE is_called`), "nontransactional sequence proves actual temp INSERT trigger reached")
			} else {
				require.EqualValues(t, 1, hits.Load(), "actual rows/identity/manifest corruption reached")
			}
			require.Equal(t, before, smokeUserBusinessState(t, h), "all 17 business tables rolled back with Audit")
			t.Logf("fault=%s actually reached; business and success Audit rolled back", mode)
			require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 300, sd8Scalar(t, h, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=$1`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
			require.EqualValues(t, 2, connector.begins.Load(), "one business and one non-assertive failure transaction; sticky faults do not replay")
		})
	}
}

func TestUserDeleteAuditCommitUnknownOverPostgres(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown"} {
		t.Run(mode, func(t *testing.T) {
			u := sd7User(t, h)
			sd8Assign(t, h, u, harness.SmokeOrganizationID)
			sd8Exec(t, h, `CREATE SEQUENCE sd8_commit_hits; CREATE FUNCTION sd8_commit_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('sd8_commit_hits'); RETURN NEW; END $$; CREATE TRIGGER sd8_commit_probe BEFORE INSERT ON user_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd8_commit_probe()`)
			t.Cleanup(func() {
				sd8Exec(t, h, `DROP TRIGGER sd8_commit_probe ON user_delete_audit_events; DROP FUNCTION sd8_commit_probe(); DROP SEQUENCE sd8_commit_hits`)
			})
			cm, nr := sd8CMNR(t, h, u)
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			controlled := sql.OpenDB(connector)
			controlled.SetMaxOpenConns(1)
			defer controlled.Close()
			app := sd7App(h)
			app.DB = controlled
			ok, err := smokeDeleteAll(t, h, app, permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.Error(t, err)
			require.False(t, ok)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM sd8_commit_hits WHERE is_called`), "business success appender reached before injected commit acknowledgement")
			require.EqualValues(t, 2, connector.begins.Load(), "single business attempt plus one observation writer")
			committed := mode != "rollback_then_error"
			wantUser, wantRoot := int64(1), int64(0)
			if committed {
				wantUser, wantRoot = 0, 1
			}
			require.Equal(t, wantUser, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.Equal(t, wantUser, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, cm))
			require.Equal(t, wantUser, sd8Scalar(t, h, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
			require.Equal(t, wantRoot, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='commit_unknown' AND before_context='null' AND effect_count=0 AND related_explicit_events='[]'`, u))
			t.Log("controlled acknowledgement over real PG", mode, "durable_success", committed, "business_attempts", 1)
		})
	}
}

func TestUserDeleteAuditRotationStateFaults(t *testing.T) {
	h := sd1Harness(t)
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"suppressed_state_update", "wrong_state_binding"} {
		t.Run(mode, func(t *testing.T) {
			u, v, w := smokeOwnedUser(t, h), smokeOwnedUser(t, h), smokeOwnedUser(t, h)
			rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
			parts := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
			for i, user := range []string{u, v, w} {
				sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, parts[i], rot, user, i)
			}
			sd8Exec(t, h, `UPDATE rotation_state SET position=2,rotation_participant_id=$2 WHERE rotation_id=$1`, rot, parts[2])
			connector, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			controlled := sql.OpenDB(connector)
			defer controlled.Close()
			app := sd7App(h)
			app.DB = controlled
			var stateHits atomic.Int64
			sd8Exec(t, h, `CREATE SEQUENCE sd8_state_hits`)
			t.Cleanup(func() { sd8Exec(t, h, `DROP SEQUENCE sd8_state_hits`) })
			if mode == "suppressed_state_update" {
				sd8Exec(t, h, `CREATE FUNCTION sd8_suppress_state() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('sd8_state_hits'); RETURN NULL;END;$$;CREATE TRIGGER sd8_suppress_state BEFORE UPDATE ON rotation_state FOR EACH ROW EXECUTE FUNCTION sd8_suppress_state()`)
				defer sd8Exec(t, h, `DROP TRIGGER sd8_suppress_state ON rotation_state;DROP FUNCTION sd8_suppress_state()`)
			} else {
				connector.beforeExec = func(_ context.Context, _ driver.Conn, query string, args []driver.NamedValue) error {
					if strings.HasPrefix(query, "UPDATE rotation_state SET position=$2,") {
						// The real trigger derives position from this participant.
						// Use a valid, surviving but incorrect relationship.
						stateHits.Add(1)
						args[2].Value = parts[0]
					}
					return nil
				}
			}
			smokeAssertBlockedUser(t, h, app, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.Zero(t, stateHits.Load())
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM sd8_state_hits WHERE is_called`))
			t.Logf("HOLD: fault=%s hits=0; original rotation_state fault has no legal User-only path under retained-reference BLOCK", mode)
			ok, err := smokeDeleteAll(t, h, app, permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.Error(t, err)
			require.False(t, ok)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 3, sd8Scalar(t, h, `SELECT participant_count FROM rotations WHERE id=$1`, rot))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1 AND position=2 AND rotation_participant_id=$2`, rot, parts[2]))
			for i, user := range []string{u, v, w} {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE id=$1 AND user_id=$2 AND position=$3`, parts[i], user, i))
			}
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
		})
	}
}
