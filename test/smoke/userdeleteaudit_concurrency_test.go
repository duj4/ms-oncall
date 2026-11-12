package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func sd8WaitLock(t *testing.T, db *sql.DB, waiter, blocker int) time.Time {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var lock, blocked, ungranted bool
		err := db.QueryRow(`SELECT coalesce(a.wait_event_type='Lock',false),$2=ANY(pg_blocking_pids(a.pid)),EXISTS(SELECT FROM pg_locks WHERE pid=a.pid AND NOT granted) FROM pg_stat_activity a WHERE a.pid=$1`, waiter, blocker).Scan(&lock, &blocked, &ungranted)
		require.NoError(t, err)
		if lock && blocked && ungranted {
			var clock string
			require.NoError(t, db.QueryRow(`SELECT clock_timestamp()::text`).Scan(&clock))
			t.Logf("lock waiter_pid=%d blocker_pid=%d wait_event_type=Lock ungranted=true database_time=%s", waiter, blocker, clock)
			return time.Now()
		}
		select {
		case <-deadline.C:
			t.Fatalf("no database lock evidence for waiter %d blocker %d", waiter, blocker)
			return time.Time{}
		case <-tick.C:
		}
	}
}

func TestUserDeleteAuditRealTwoSecondWriter(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"commit", "rollback", "writer_first"} {
		for iteration := range 3 {
			t.Run(fmt.Sprintf("%s/%d", mode, iteration), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				u := sd7User(t, h)
				_, nr := sd8CMNR(t, h, u)
				connector, err := sd8PGConnector(harness.DBURL(name))
				require.NoError(t, err)
				controlled := sql.OpenDB(connector)
				controlled.SetMaxOpenConns(1)
				defer controlled.Close()
				app := sd7App(h)
				app.DB = controlled
				beforeDelete := make(chan int, 1)
				release := make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				connector.beforeDelete = func(ctx context.Context, native driver.Conn) error {
					pid, err := sd8NativePID(ctx, native)
					if err != nil {
						return err
					}
					beforeDelete <- pid
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				writer, err := db.Conn(ctx)
				require.NoError(t, err)
				defer writer.Close()
				var wpid int
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&wpid))
				writerTx, err := writer.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writerTx.Rollback() }()
				var dp int
				if mode == "writer_first" {
					_, err = writerTx.ExecContext(ctx, `UPDATE user_notification_rules SET delay_minutes=delay_minutes+1 WHERE id=$1`, nr)
					require.NoError(t, err)

				}
				if mode == "rollback" {
					sd8Exec(t, h, `CREATE FUNCTION sd8_business_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd8_business_fail BEFORE INSERT ON user_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd8_business_fail()`)
				}
				done := make(chan error, 1)
				go func() {
					_, err := app.Mutation().DeleteAll(permission.SystemContext(ctx, "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
					done <- err
				}()
				if mode == "writer_first" {
					// Read PID through pg_stat_activity instead of racing with the driver's hook.
					require.Eventually(t, func() bool {
						return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1`, wpid).Scan(&dp) == nil
					}, 5*time.Second, 10*time.Millisecond)
					start := sd8WaitLock(t, db, dp, wpid)
					timer := time.NewTimer(2100 * time.Millisecond)
					<-timer.C
					sd8WaitLock(t, db, dp, wpid)
					require.GreaterOrEqual(t, time.Since(start), 2*time.Second)
					require.NoError(t, writerTx.Commit())
					select {
					case <-beforeDelete:
					case <-ctx.Done():
						t.Fatal("delete capture did not finish")
					}
					unblock()
					require.NoError(t, <-done)
					var delay int
					require.NoError(t, db.QueryRow(`SELECT (f.payload->'before'->>'delay_minutes')::integer FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND f.resource_type='notification_rule'`, u).Scan(&delay))
					require.Equal(t, 1, delay)
					return
				}
				select {
				case dp = <-beforeDelete:
				case <-ctx.Done():
					t.Fatal("delete capture did not reach barrier")
				}
				updateDone := make(chan struct {
					n   int64
					err error
				}, 1)
				go func() {
					result, err := writerTx.ExecContext(ctx, `UPDATE user_notification_rules SET delay_minutes=delay_minutes+1 WHERE id=$1`, nr)
					var n int64
					if err == nil {
						n, err = result.RowsAffected()
					}
					updateDone <- struct {
						n   int64
						err error
					}{n, err}
				}()
				start := sd8WaitLock(t, db, wpid, dp)
				timer := time.NewTimer(2100 * time.Millisecond)
				<-timer.C
				sd8WaitLock(t, db, wpid, dp)
				require.GreaterOrEqual(t, time.Since(start), 2*time.Second)
				select {
				case <-updateDone:
					t.Fatal("writer completed inside proven competition window")
				default:
				}
				unblock()
				deleteErr := <-done
				update := <-updateDone
				require.NoError(t, update.err)
				require.NoError(t, writerTx.Commit())
				if mode == "commit" {
					require.NoError(t, deleteErr)
					require.Zero(t, update.n)
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
				} else {
					require.Error(t, deleteErr)
					require.EqualValues(t, 1, update.n)
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT delay_minutes FROM user_notification_rules WHERE id=$1`, nr))
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
					sd8Exec(t, h, `DROP TRIGGER sd8_business_fail ON user_delete_audit_events;DROP FUNCTION sd8_business_fail()`)
				}
				t.Logf("branch=%s iteration=%d proven_wait=%s writer_rows=%d begins=%d commits=%d", mode, iteration, time.Since(start), update.n, connector.begins.Load(), connector.commits.Load())
			})
		}
	}
}
