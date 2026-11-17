package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/user/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
)

// This is an audit contract harness. Users and assignments remain present;
// neither the product deletion guard nor its User-only HOLD is bypassed.
func sessionReplayStage(t *testing.T, ctx context.Context, db *sql.DB, count int) (audit.Receipt, []uuid.UUID, *sql.Conn, *sql.Tx) {
	t.Helper()
	f := newUserPhaseAFixture(t, ctx, db)
	locators, _ := sessionIdentityCreate(t, ctx, db, f, count)
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	sessionIdentitySpool(t, ctx, tx)
	e := sessionIdentityRoot(f.user)
	org, err := audit.SnapshotOrganization(ctx, tx, f.user)
	require.NoError(t, err)
	require.NoError(t, audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, org))
	_, err = tx.ExecContext(ctx, `DELETE FROM auth_user_sessions WHERE user_id=$1`, f.user)
	require.NoError(t, err)
	return sessionIdentityFinalize(t, ctx, tx, e), locators, conn, tx
}

// Reconstruct only the exact persisted safe carrier, never the expired mapping.
func sessionReplaySpool(t *testing.T, ctx context.Context, tx *sql.Tx, event uuid.UUID) {
	t.Helper()
	var missing bool
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT to_regclass('pg_temp.sd8_user_session_identity') IS NULL`).Scan(&missing))
	require.True(t, missing, "replay must not possess a Session identity mapping")
	sessionIdentitySpool(t, ctx, tx)
	_, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.sd8_user_delete_witness
 (root_ordinal,resource_type,resource_key,before_value,after_value,organization_id,org_resolution,effect_id,payload)
 SELECT 0,resource_type,resource_key,payload->'before',payload->'after',
 (payload->>'target_organization_id')::uuid,payload->>'org_resolution',effect_id,payload
 FROM user_delete_audit_effects WHERE event_id=$1`, event)
	require.NoError(t, err)
}

func sessionReplayState(t *testing.T, ctx context.Context, db *sql.DB, event uuid.UUID) string {
	t.Helper()
	var state string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object('event',to_jsonb(e),'xmin',e.xmin::text,
 'effects',(SELECT coalesce(jsonb_agg(to_jsonb(f)||jsonb_build_object('xmin',f.xmin::text) ORDER BY effect_ordinal),'[]')
 FROM user_delete_audit_effects f WHERE f.event_id=e.event_id))::text
 FROM user_delete_audit_events e WHERE e.event_id=$1`, event).Scan(&state))
	return state
}

func TestPostgresUserDeleteSessionReplayCommitted(t *testing.T) {
	for _, count := range []int{1, 257} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			base, _, db := boundedAuditDB(t, len(Names()))
			ctx := permission.SystemContext(base, "SessionReplay")
			r, locators, first, tx := sessionReplayStage(t, ctx, db, count)
			var initialPID int
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&initialPID))
			require.NoError(t, audit.AppendReceipt(ctx, tx, r))
			require.NoError(t, audit.AppendReceipt(ctx, tx, r), "same transaction repeat")
			require.NoError(t, tx.Commit())
			var dropped bool
			require.NoError(t, first.QueryRowContext(ctx, `SELECT to_regclass('pg_temp.sd8_user_session_identity') IS NULL`).Scan(&dropped))
			require.True(t, dropped)
			before := sessionReplayState(t, ctx, db, r.Event.EventID)
			sessionIdentityNoLeak(t, []byte(before), locators)
			replay := userPhaseATx(t, ctx, db)
			var replayPID int
			require.NoError(t, replay.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&replayPID))
			require.NotEqual(t, initialPID, replayPID)
			sessionReplaySpool(t, ctx, replay, r.Event.EventID)
			_, err := replay.ExecContext(ctx, `CREATE FUNCTION pg_temp.replay_insert_forbidden() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unexpected exact replay INSERT'; END $$;
 CREATE TRIGGER aaa_replay_insert_forbidden BEFORE INSERT ON user_delete_audit_effects
 FOR EACH ROW EXECUTE FUNCTION pg_temp.replay_insert_forbidden()`)
			require.NoError(t, err)
			err = audit.AppendReceipt(ctx, replay, r)
			if err != nil {
				sessionIdentityNoLeak(t, []byte(err.Error()), locators)
				require.NoError(t, replay.Rollback())
				require.True(t, before == sessionReplayState(t, ctx, db, r.Event.EventID), "failed replay changed committed audit")
			}
			require.NoError(t, err, "committed exact Session v2 replay on a distinct connection without mapping")
			_, err = replay.ExecContext(ctx, `DROP TRIGGER aaa_replay_insert_forbidden ON user_delete_audit_effects`)
			require.NoError(t, err)
			require.NoError(t, replay.Commit())
			require.True(t, before == sessionReplayState(t, ctx, db, r.Event.EventID), "replay changed bytes or xmin")
			require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects WHERE event_id=$1`, r.Event.EventID))
		})
	}
}

func TestPostgresUserDeleteSessionReplayRejected(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionReplayRejected")
	r, locators, _, tx := sessionReplayStage(t, ctx, db, 1)
	require.NoError(t, audit.AppendReceipt(ctx, tx, r))
	require.NoError(t, tx.Commit())
	before := sessionReplayState(t, ctx, db, r.Event.EventID)
	logPath := os.Getenv("SESSION_AUDIT_TEST_SERVER_LOG")
	for _, mode := range []string{"payload", "effect_id", "safe_identity", "resource_key", "root_payload", "root_event", "manifest", "declared_count", "missing_event", "missing_effect", "raw_id", "unknown_version"} {
		t.Run(mode, func(t *testing.T) {
			replay := userPhaseATx(t, ctx, db)
			sessionReplaySpool(t, ctx, replay, r.Event.EventID)
			candidate := r
			want := audit.ErrConflict
			var err error
			switch mode {
			case "payload":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_set(payload,'{before,row_version}',to_jsonb((payload->'before'->>'row_version')::bigint+1))`)
			case "effect_id":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_set(payload,'{effect_id}',to_jsonb($1::text))`, uuid.NewString())
			case "safe_identity":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET resource_key=$1,payload=jsonb_set(jsonb_set(payload,'{resource_key}',to_jsonb($1::text)),'{before,audit_resource_id}',to_jsonb($1::text))`, uuid.NewString())
			case "resource_key":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET resource_key=$1,payload=jsonb_set(payload,'{resource_key}',to_jsonb($1::text))`, uuid.NewString())
				want = audit.ErrInvalid
			case "root_payload":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_set(payload,'{trigger_user_id}',to_jsonb($1::text))`, uuid.NewString())
				want = audit.ErrInvalid
			case "root_event":
				root := uuid.New()
				b := *candidate.Event.BeforeContext
				b.UserID = root
				candidate.Event.BeforeContext = &b
				candidate.Event.RootID, candidate.DeletedUserID = &root, root
			case "manifest":
				candidate.Event.Manifest = map[string]int64{"auth_subject": 1}
			case "declared_count":
				candidate.Event.Manifest = map[string]int64{"user_session": 2}
				candidate.Event.EffectCount = 2
			case "missing_event", "missing_effect":
				candidate.Event.EventID, candidate.Event.AttemptID = uuid.New(), uuid.New()
				want = audit.ErrUnavailable
				if mode == "missing_effect" {
					// A header with a missing declared effect cannot be committed.
					// Exercise the absent-row insertion path on a staged header.
					require.NoError(t, audit.Append(ctx, replay, candidate.Event))
					var n int
					require.NoError(t, replay.QueryRowContext(ctx, `SELECT count(*) FROM user_delete_audit_effects WHERE event_id=$1`, candidate.Event.EventID).Scan(&n))
					require.Zero(t, n)
				}
			case "raw_id":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_set(payload,'{before,id}',to_jsonb($1::text))`, locators[0].String())
				want = audit.ErrInvalid
			case "unknown_version":
				_, err = replay.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_set(payload,'{before,version}','3')`)
				want = audit.ErrInvalid
			}
			require.NoError(t, err)
			err = audit.AppendReceipt(ctx, replay, candidate)
			require.ErrorIs(t, err, want)
			sessionIdentityNoLeak(t, []byte(err.Error()), locators)
			require.NoError(t, replay.Rollback())
			require.True(t, before == sessionReplayState(t, ctx, db, r.Event.EventID), "rejected replay changed history")
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events`))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
			if logPath != "" {
				raw, err := os.ReadFile(logPath)
				require.NoError(t, err)
				sessionIdentityNoLeak(t, raw, locators)
			}
		})
	}
}

func sessionReplayCarrier(t *testing.T, ctx context.Context, tx *sql.Tx, raw string) {
	t.Helper()
	var missing bool
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT to_regclass('pg_temp.sd8_user_session_identity') IS NULL`).Scan(&missing))
	require.True(t, missing)
	sessionIdentitySpool(t, ctx, tx)
	_, err := tx.ExecContext(ctx, `INSERT INTO pg_temp.sd8_user_delete_witness
 (root_ordinal,resource_type,resource_key,before_value,after_value,organization_id,org_resolution,effect_id,payload)
 SELECT 0,p->>'resource_type',p->>'resource_key',p->'before',p->'after',
 (p->>'target_organization_id')::uuid,p->>'org_resolution',(p->>'effect_id')::uuid,p FROM (SELECT $1::jsonb p) s`, raw)
	require.NoError(t, err)
}

func TestPostgresUserDeleteSessionReplayConcurrent(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback", "bounded_timeout"} {
		t.Run(outcome, func(t *testing.T) {
			base, _, db := boundedAuditDB(t, len(Names()))
			ctx := permission.SystemContext(base, "SessionReplayConcurrent")
			r, locators, _, writer := sessionReplayStage(t, ctx, db, 1)
			require.NoError(t, audit.AppendReceipt(ctx, writer, r))
			var carrier string
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT payload::text FROM pg_temp.sd8_user_delete_witness`).Scan(&carrier))
			sessionIdentityNoLeak(t, []byte(carrier), locators)
			replay := userPhaseATx(t, ctx, db)
			sessionReplayCarrier(t, ctx, replay, carrier)
			var visible bool
			require.NoError(t, replay.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_delete_audit_effects WHERE event_id=$1)`, r.Event.EventID).Scan(&visible))
			require.False(t, visible, "first query must not see writer's uncommitted effect")
			// Native effect-level behavior before unique-conflict arbitration:
			// even an uncommitted duplicate must pass the original identity gate.
			probe := userPhaseATx(t, ctx, db)
			_, err := probe.ExecContext(ctx, `INSERT INTO user_delete_audit_effects
 (event_id,effect_ordinal,declared_effect_count,effect_id,resource_type,resource_key,transition_slot,payload)
 SELECT $1,0,1,(p->>'effect_id')::uuid,'user_session',p->>'resource_key','row',p
 FROM (SELECT $2::jsonb p) s ON CONFLICT(event_id,effect_ordinal) DO NOTHING`, r.Event.EventID, carrier)
			require.Error(t, err)
			pg := sqlutil.MapError(err)
			require.NotNil(t, pg)
			require.Equal(t, "23514", pg.Code)
			sessionIdentityNoLeak(t, []byte(err.Error()+pg.Detail+pg.Where), locators)
			require.NoError(t, probe.Rollback())
			var replayPID int
			require.NoError(t, replay.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&replayPID))
			_, err = replay.ExecContext(ctx, `SET LOCAL lock_timeout='1500ms'; SET LOCAL statement_timeout='3s'`)
			require.NoError(t, err)
			if outcome == "bounded_timeout" {
				_, err = replay.ExecContext(ctx, `SET LOCAL lock_timeout='60ms'`)
				require.NoError(t, err)
				require.ErrorIs(t, audit.AppendReceipt(ctx, replay, r), audit.ErrUnavailable)
				require.NoError(t, replay.Rollback())
				require.NoError(t, writer.Commit())
				// The existing transaction owner may retry after the writer commits.
				retry := userPhaseATx(t, ctx, db)
				sessionReplaySpool(t, ctx, retry, r.Event.EventID)
				require.NoError(t, audit.AppendReceipt(ctx, retry, r))
				require.NoError(t, retry.Commit())
			} else {
				done := make(chan error, 1)
				go func() { done <- audit.AppendReceipt(ctx, replay, r) }()
				// Append's header ON CONFLICT serializes the real same-event path
				// before the effect read. Observe that wait instead of guessing it.
				require.Eventually(t, func() bool {
					var waiting bool
					err := db.QueryRowContext(ctx, `SELECT coalesce(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, replayPID).Scan(&waiting)
					return err == nil && waiting
				}, time.Second, 5*time.Millisecond)
				if outcome == "commit" {
					require.NoError(t, writer.Commit())
				} else {
					require.NoError(t, writer.Rollback())
				}
				select {
				case err = <-done:
				case <-time.After(4 * time.Second):
					t.Fatal("bounded concurrent replay did not finish")
				}
				if outcome == "commit" {
					require.NoError(t, err)
					require.NoError(t, replay.Commit())
				} else {
					require.ErrorIs(t, err, audit.ErrUnavailable)
					sessionIdentityNoLeak(t, []byte(err.Error()), locators)
					require.NoError(t, replay.Rollback())
				}
			}
			want := 1
			if outcome == "rollback" {
				want = 0
			}
			require.Equal(t, want, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events`))
			require.Equal(t, want, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
			// No User root product deletion was performed by this harness.
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, r.DeletedUserID))
		})
	}
}

func TestPostgresUserDeleteSessionReplayBeforeInsertGate(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionReplayGate")
	r, locators, _, tx := sessionReplayStage(t, ctx, db, 1)
	require.NoError(t, audit.AppendReceipt(ctx, tx, r))
	require.NoError(t, tx.Commit())
	before := sessionReplayState(t, ctx, db, r.Event.EventID)
	tx = userPhaseATx(t, ctx, db)
	sessionReplaySpool(t, ctx, tx, r.Event.EventID)
	// This is an already committed exact duplicate. PostgreSQL must still run
	// the real BEFORE INSERT gate before ON CONFLICT can discard it.
	_, err := tx.ExecContext(ctx, `INSERT INTO user_delete_audit_effects SELECT * FROM user_delete_audit_effects
 WHERE event_id=$1 ON CONFLICT(event_id,effect_ordinal) DO NOTHING`, r.Event.EventID)
	require.Error(t, err)
	pg := sqlutil.MapError(err)
	require.NotNil(t, pg)
	require.Equal(t, "23514", pg.Code)
	require.Equal(t, "Invalid user.delete Session identity", pg.Message)
	sessionIdentityNoLeak(t, []byte(err.Error()+pg.Detail+pg.Where), locators)
	t.Log("native duplicate INSERT: Session BEFORE INSERT gate rejected with SQLSTATE 23514; exact row already committed")
	require.NoError(t, tx.Rollback())
	require.True(t, before == sessionReplayState(t, ctx, db, r.Event.EventID))
}

func TestPostgresUserDeleteSessionReplayPagedAtomicity(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionReplayAtomicity")
	r, locators, _, tx := sessionReplayStage(t, ctx, db, 257)
	_, err := tx.ExecContext(ctx, `CREATE FUNCTION pg_temp.replay_page_fault() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN IF NEW.effect_ordinal=256 THEN RAISE EXCEPTION 'synthetic second page fault'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER zzz_replay_page_fault BEFORE INSERT ON user_delete_audit_effects
 FOR EACH ROW EXECUTE FUNCTION pg_temp.replay_page_fault()`)
	require.NoError(t, err)
	err = audit.AppendReceipt(ctx, tx, r)
	require.ErrorIs(t, err, audit.ErrUnavailable)
	sessionIdentityNoLeak(t, []byte(err.Error()), locators)
	require.NoError(t, tx.Rollback())
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events`))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
	require.Equal(t, 257, enforcementCount(t, ctx, db, `SELECT count(*) FROM auth_user_sessions WHERE user_id=$1`, r.DeletedUserID))
	// The fault DDL and all first-page writes rolled back. Recapture the same
	// real Sessions, using their existing safe identities and no fake mapping.
	retry := userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, retry)
	org, err := audit.SnapshotOrganization(ctx, retry, r.DeletedUserID)
	require.NoError(t, err)
	require.NoError(t, audit.CaptureSessions(ctx, retry, r.DeletedUserID, 0, r.Event.EventID, org))
	_, err = retry.ExecContext(ctx, `DELETE FROM auth_user_sessions WHERE user_id=$1`, r.DeletedUserID)
	require.NoError(t, err)
	r = sessionIdentityFinalize(t, ctx, retry, r.Event)
	require.NoError(t, audit.AppendReceipt(ctx, retry, r))
	require.NoError(t, retry.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events`))
	require.Equal(t, 257, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
	sessionIdentityNoLeak(t, []byte(sessionReplayState(t, ctx, db, r.Event.EventID)), locators)
	// A header whose declared Effect is absent cannot be committed at all.
	missing := userPhaseATx(t, ctx, db)
	e := r.Event
	e.EventID, e.AttemptID = uuid.New(), uuid.New()
	require.NoError(t, audit.Append(ctx, missing, e))
	require.Error(t, missing.Commit(), "deferred manifest must reject a missing committed effect")
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE event_id=$1`, e.EventID))
	require.Equal(t, 257, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
}
