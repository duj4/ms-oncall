package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
)

// Trace barriers intercept real database/sql/pgx calls without production hooks
// or extra database locks. All waits are bounded by the operation's context.
type scheduleDataTrace struct {
	before       func(context.Context, string)
	parentChecks atomic.Int32
}
type scheduleDataTraceKey struct{}

func (tr *scheduleDataTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if tr.before != nil {
		tr.before(ctx, d.SQL)
	}
	return context.WithValue(ctx, scheduleDataTraceKey{}, d.SQL)
}
func (tr *scheduleDataTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	q, _ := ctx.Value(scheduleDataTraceKey{}).(string)
	if strings.Contains(q, "-- name: SchedCheckOrganization") && d.Err == nil {
		tr.parentChecks.Add(1)
	}
}

func scheduleDataTraced(t *testing.T, h *harness.Harness, tr *scheduleDataTrace) (*sql.DB, *schedule.Store) {
	t.Helper()
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	cfg.Tracer = tr
	db := sql.OpenDB(stdlib.GetConnector(*cfg))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	s, err := schedule.NewStore(context.Background(), db, h.App().UserStore)
	require.NoError(t, err)
	return db, s
}

func scheduleDataTx(t *testing.T, ctx context.Context, db *sql.DB) (*sql.Tx, int) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='8s'`)
	require.NoError(t, err)
	var pid int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	return tx, pid
}

func scheduleDataWaitBlocked(t *testing.T, ctx context.Context, db *sql.DB, waiter, blocker int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		err := db.QueryRowContext(ctx, `SELECT $2 = ANY(pg_blocking_pids($1))`, waiter, blocker).Scan(&blocked)
		require.NoError(t, err, "expected database-observed blocking edge")
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("blocking edge not observed before deadline")
		case <-tick.C:
		}
	}
}

func scheduleDataAsync(fn func() error) <-chan error {
	c := make(chan error, 1)
	go func() { c <- fn() }()
	return c
}
func scheduleDataReceive(t *testing.T, ctx context.Context, c <-chan error) error {
	t.Helper()
	select {
	case err := <-c:
		return err
	case <-ctx.Done():
		t.Fatal("operation exceeded bounded context")
		return ctx.Err()
	}
}
func scheduleDataBarrier(t *testing.T, ctx context.Context, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-ctx.Done():
		t.Fatal("query barrier was not reached")
	}
}
func scheduleDataFinish(tx *sql.Tx, err error) error {
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
func scheduleDataNoOrphans(t *testing.T, h *harness.Harness) {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_data d LEFT JOIN schedules s ON s.id=d.schedule_id WHERE s.id IS NULL`).Scan(&n))
	require.Zero(t, n)
}

func TestScheduleDataConcurrency(t *testing.T) {
	// Separate harnesses isolate destructive controls and preserve identical
	// fixtures/configuration for candidate and exact-base runs.
	t.Run("existing-mutation-vs-delete", func(t *testing.T) {
		h := scheduleDataHarness(t)
		ctx := scheduleDataContext(t)
		org := uuid.MustParse(harness.SmokeOrganizationID)
		scheduleDataReset(t, h, "own", `{}`)
		a, apid := scheduleDataTx(t, ctx, h.App().DB())
		b, bpid := scheduleDataTx(t, ctx, h.App().DB())
		require.NoError(t, scheduleDataMutate(ctx, h.App().ScheduleStore, a, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), "set", &org))
		deleted := scheduleDataAsync(func() error {
			_, err := b.ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, h.UUID("own"))
			return scheduleDataFinish(b, err)
		})
		scheduleDataWaitBlocked(t, ctx, h.App().DB(), bpid, apid)
		require.NoError(t, a.Commit())
		err := scheduleDataReceive(t, ctx, deleted)
		scheduleDataRecord(t, scheduleDataOutcome(err))
		require.NoError(t, err)
		scheduleDataNoOrphans(t, h)
	})
	t.Run("delete-after-authorization-before-child-access", func(t *testing.T) {
		h := scheduleDataHarness(t)
		ctx := scheduleDataContext(t)
		org := uuid.MustParse(harness.SmokeOrganizationID)
		scheduleDataReset(t, h, "own", `{}`)
		reached, release := make(chan struct{}, 1), make(chan struct{})
		tr := &scheduleDataTrace{before: func(ctx context.Context, q string) {
			if strings.Contains(q, "-- name: SchedFindDataForUpdate") {
				reached <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
		}}
		_, s := scheduleDataTraced(t, h, tr)
		result := scheduleDataAsync(func() error {
			return scheduleDataMutate(ctx, s, nil, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), "set", &org)
		})
		scheduleDataBarrier(t, ctx, reached)
		require.EqualValues(t, 1, tr.parentChecks.Load(), "authorization succeeded before child access")
		_, err := h.App().DB().ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, h.UUID("own"))
		require.NoError(t, err)
		close(release)
		err = scheduleDataReceive(t, ctx, result)
		scheduleDataRecord(t, scheduleDataOutcome(err))
		require.Equal(t, "SQLSTATE 23503", scheduleDataOutcome(err))
		scheduleDataNoOrphans(t, h)
	})
	for _, control := range []string{"root-update", "unrelated-root-lock"} {
		t.Run(control, func(t *testing.T) {
			h := scheduleDataHarness(t)
			ctx := scheduleDataContext(t)
			org := uuid.MustParse(harness.SmokeOrganizationID)
			tx, _ := scheduleDataTx(t, ctx, h.App().DB())
			if control == "root-update" {
				scheduleDataReset(t, h, "own", `{}`)
				_, err := tx.ExecContext(ctx, `UPDATE schedules SET description='root edit' WHERE id=$1`, h.UUID("own"))
				require.NoError(t, err)
			} else {
				_, err := tx.ExecContext(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, h.UUID("foreign"))
				require.NoError(t, err)
			}
			bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			err := scheduleDataMutate(bounded, h.App().ScheduleStore, nil, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), "set", &org)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
		})
	}
	t.Run("simultaneous-first-write", func(t *testing.T) {
		h := scheduleDataHarness(t)
		ctx := scheduleDataContext(t)
		org := uuid.MustParse(harness.SmokeOrganizationID)
		reached, release := make(chan struct{}, 2), make(chan struct{})
		tr := &scheduleDataTrace{before: func(ctx context.Context, q string) {
			if strings.Contains(q, "-- name: SchedInsertData") {
				reached <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
		}}
		_, s := scheduleDataTraced(t, h, tr)
		run := func() error {
			return scheduleDataMutate(ctx, s, nil, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), "set", &org)
		}
		a, b := scheduleDataAsync(run), scheduleDataAsync(run)
		scheduleDataBarrier(t, ctx, reached)
		scheduleDataBarrier(t, ctx, reached)
		close(release)
		outcomes := []string{scheduleDataOutcome(scheduleDataReceive(t, ctx, a)), scheduleDataOutcome(scheduleDataReceive(t, ctx, b))}
		sort.Strings(outcomes)
		scheduleDataRecord(t, outcomes)
		require.Equal(t, []string{"OK", "SQLSTATE 25P02"}, outcomes, "record actual first-write recovery outcome")
		require.NotEmpty(t, scheduleDataRaw(t, h, "own"))
		scheduleDataNoOrphans(t, h)
	})
	for _, pair := range []struct{ name, first, second string }{{"existing-row-writers", "set", "set"}, {"temporary-then-rules", "set", "rules"}, {"rules-then-temporary", "rules", "set"}} {
		t.Run(pair.name, func(t *testing.T) {
			h := scheduleDataHarness(t)
			ctx := scheduleDataContext(t)
			org, id := uuid.MustParse(harness.SmokeOrganizationID), uuid.MustParse(h.UUID("own"))
			scheduleDataReset(t, h, "own", `{}`)
			a, apid := scheduleDataTx(t, ctx, h.App().DB())
			b, bpid := scheduleDataTx(t, ctx, h.App().DB())
			run := func(tx *sql.Tx, op string) error {
				if op == "rules" {
					return h.App().ScheduleStore.SetOnCallNotificationRulesScoped(ctx, tx, id, []schedule.OnCallNotificationRule{{ChannelID: uuid.MustParse(h.UUID("channel"))}}, &org)
				}
				return scheduleDataMutate(ctx, h.App().ScheduleStore, tx, id, scheduleDataTemp(h), op, &org)
			}
			require.NoError(t, run(a, pair.first))
			result := scheduleDataAsync(func() error { return scheduleDataFinish(b, run(b, pair.second)) })
			scheduleDataWaitBlocked(t, ctx, h.App().DB(), bpid, apid)
			require.NoError(t, a.Commit())
			err := scheduleDataReceive(t, ctx, result)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
			var data schedule.Data
			require.NoError(t, json.Unmarshal([]byte(scheduleDataRaw(t, h, "own")), &data))
			require.Len(t, data.V1.TemporarySchedules, 1)
			if pair.first == "rules" || pair.second == "rules" {
				require.Len(t, data.V1.OnCallNotificationRules, 1)
			}
		})
	}
	for _, manager := range []string{"schedule-manager", "cleanup-manager"} {
		t.Run(manager, func(t *testing.T) {
			h := scheduleDataHarness(t)
			ctx := scheduleDataContext(t)
			org, id := uuid.MustParse(harness.SmokeOrganizationID), uuid.MustParse(h.UUID("own"))
			scheduleDataReset(t, h, "own", `{"V1":{},"ManagerValue":1}`)
			a, apid := scheduleDataTx(t, ctx, h.App().DB())
			b, bpid := scheduleDataTx(t, ctx, h.App().DB())
			g := gadb.New(a)
			if manager == "schedule-manager" {
				_, err := g.SchedMgrDataForUpdate(ctx)
				require.NoError(t, err)
			} else {
				_, err := g.CleanupMgrScheduleData(ctx, id)
				require.NoError(t, err)
			}
			result := scheduleDataAsync(func() error {
				return scheduleDataFinish(b, scheduleDataMutate(ctx, h.App().ScheduleStore, b, id, scheduleDataTemp(h), "set", &org))
			})
			scheduleDataWaitBlocked(t, ctx, h.App().DB(), bpid, apid)
			data := json.RawMessage(`{"V1":{},"ManagerValue":2}`)
			if manager == "schedule-manager" {
				require.NoError(t, g.SchedMgrSetData(ctx, gadb.SchedMgrSetDataParams{ScheduleID: id, Data: data}))
			} else {
				require.NoError(t, g.CleanupMgrUpdateScheduleData(ctx, gadb.CleanupMgrUpdateScheduleDataParams{ScheduleID: id, Data: data}))
			}
			require.NoError(t, a.Commit())
			err := scheduleDataReceive(t, ctx, result)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
			var got struct{ ManagerValue int }
			require.NoError(t, json.Unmarshal([]byte(scheduleDataRaw(t, h, "own")), &got))
			require.Equal(t, 2, got.ManagerValue)
		})
	}
	t.Run("outer-child-root-delete-other-child-cycle", func(t *testing.T) {
		h := scheduleDataHarness(t)
		ctx := scheduleDataContext(t)
		org := uuid.MustParse(harness.SmokeOrganizationID)
		scheduleDataReset(t, h, "own", `{}`)
		a, apid := scheduleDataTx(t, ctx, h.App().DB())
		b, bpid := scheduleDataTx(t, ctx, h.App().DB())
		require.NoError(t, scheduleDataMutate(ctx, h.App().ScheduleStore, a, uuid.MustParse(h.UUID("own")), scheduleDataTemp(h), "set", &org))
		deleted := scheduleDataAsync(func() error {
			_, err := b.ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, h.UUID("own"))
			return scheduleDataFinish(b, err)
		})
		scheduleDataWaitBlocked(t, ctx, h.App().DB(), bpid, apid)
		inserted := scheduleDataAsync(func() error {
			_, err := a.ExecContext(ctx, `INSERT INTO schedule_rules(id,schedule_id,sunday,monday,tuesday,wednesday,thursday,friday,saturday,start_time,end_time,tgt_user_id)
			 VALUES($1,$2,true,true,true,true,true,true,true,'00:00:00','00:00:00',$3)`, uuid.New(), h.UUID("own"), h.UUID("user-a"))
			return scheduleDataFinish(a, err)
		})
		outcomes := []string{scheduleDataOutcome(scheduleDataReceive(t, ctx, inserted)), scheduleDataOutcome(scheduleDataReceive(t, ctx, deleted))}
		sort.Strings(outcomes)
		scheduleDataRecord(t, outcomes)
		require.Equal(t, []string{"OK", "SQLSTATE 40P01"}, outcomes)
		scheduleDataNoOrphans(t, h)
	})
	for _, op := range scheduleDataOperations {
		t.Run("foreign-child-locked/"+op, func(t *testing.T) {
			h := scheduleDataHarness(t)
			ctx := scheduleDataContext(t)
			org := uuid.MustParse(harness.SmokeOrganizationID)
			scheduleDataReset(t, h, "foreign", `{}`)
			lock, lpid := scheduleDataTx(t, ctx, h.App().DB())
			_, err := lock.ExecContext(ctx, `SELECT schedule_id FROM schedule_data WHERE schedule_id=$1 FOR UPDATE`, h.UUID("foreign"))
			require.NoError(t, err)
			access := make(chan struct{}, 1)
			tr := &scheduleDataTrace{before: func(_ context.Context, q string) {
				if strings.Contains(q, "-- name: SchedFindDataForUpdate") {
					select {
					case access <- struct{}{}:
					default:
					}
				}
			}}
			db, s := scheduleDataTraced(t, h, tr)
			tx, pid := scheduleDataTx(t, ctx, db)
			result := scheduleDataAsync(func() error {
				return scheduleDataFinish(tx, scheduleDataMutate(ctx, s, tx, uuid.MustParse(h.UUID("foreign")), scheduleDataTemp(h), op, &org))
			})
			waited := false
			select {
			case err = <-result:
			case <-access:
				waited = true
				scheduleDataWaitBlocked(t, ctx, h.App().DB(), pid, lpid)
				require.NoError(t, lock.Rollback())
				err = scheduleDataReceive(t, ctx, result)
			case <-ctx.Done():
				t.Fatal("foreign mutation exceeded bounded context")
			}
			scheduleDataRecord(t, fmt.Sprintf("child access=%t; %s", waited, scheduleDataOutcome(err)))
			require.False(t, waited, "foreign rejection must not attempt the locked child query")
			scheduleDataUnavailable(t, err)
		})
	}
}

func TestScheduleDataNilScopeNoParentQuery(t *testing.T) {
	h := scheduleDataHarness(t)
	tr := new(scheduleDataTrace)
	_, s := scheduleDataTraced(t, h, tr)
	for _, op := range scheduleDataOperations {
		t.Run(op, func(t *testing.T) {
			err := scheduleDataUnscoped(scheduleDataContext(t), s, nil, uuid.MustParse(h.UUID("foreign")), scheduleDataTemp(h), op)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.NoError(t, err)
			require.Zero(t, tr.parentChecks.Load(), "nil scope must not add a parent query")
		})
	}
}
