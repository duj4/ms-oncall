package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditHundredUsersAndHeap(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	input := make([]assignment.RawTarget, 100)
	ids := make([]string, 100)
	for i := range input {
		ids[i] = sd7User(t, h)
		input[i] = assignment.RawTarget{Type: assignment.TargetTypeUser, ID: ids[i]}
	}
	sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,u.id,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM users u CROSS JOIN generate_series(1,257) g WHERE u.id=ANY($2::uuid[])`, s, pq.Array(ids))
	var name string
	var tempBefore int64
	require.NoError(t, db.QueryRow(`SELECT current_database(),temp_bytes FROM pg_stat_database WHERE datname=current_database()`).Scan(&name, &tempBefore))
	connector, err := sd8PGConnector(harness.DBURL(name))
	require.NoError(t, err)
	controlled := sql.OpenDB(connector)
	defer controlled.Close()
	app := sd7App(h)
	app.DB = controlled
	var relationBytes atomic.Int64
	connector.beforeCommit = func(ctx context.Context, c driver.Conn) error {
		rows, err := c.(driver.QueryerContext).QueryContext(ctx, `SELECT pg_total_relation_size('pg_temp.sd8_user_delete_witness'::regclass)`, nil)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		values := make([]driver.Value, 1)
		if err = rows.Next(values); err != nil {
			return err
		}
		relationBytes.Store(values[0].(int64))
		return nil
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapAlloc)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for old := peak.Load(); m.HeapAlloc > old; old = peak.Load() {
					if peak.CompareAndSwap(old, m.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	start := time.Now()
	ok, deleteErr := app.Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), input)
	elapsed := time.Since(start)
	close(stop)
	<-stopped
	runtime.ReadMemStats(&after)
	require.NoError(t, deleteErr)
	require.True(t, ok)
	require.EqualValues(t, 1, connector.commits.Load())
	require.EqualValues(t, 100, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
	require.EqualValues(t, 25700, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
	rows, err := db.Query(`SELECT root_id,root_ordinal,effect_count FROM user_delete_audit_events WHERE record_kind='success_witness' ORDER BY root_ordinal`)
	require.NoError(t, err)
	i := 0
	for rows.Next() {
		var id string
		var ordinal, count int
		require.NoError(t, rows.Scan(&id, &ordinal, &count))
		require.Equal(t, i, ordinal)
		require.Equal(t, ids[i], id)
		require.Equal(t, 257, count)
		i++
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, 100, i)
	var bytes, tempAfter int64
	require.NoError(t, db.QueryRow(`SELECT sum(effect_json_bytes) FROM user_delete_audit_events`).Scan(&bytes))
	require.Greater(t, bytes, int64(4194304))
	require.NoError(t, db.QueryRow(`SELECT temp_bytes FROM pg_stat_database WHERE datname=current_database()`).Scan(&tempAfter))
	require.Greater(t, relationBytes.Load(), int64(0))
	t.Logf("users=100 history=25700 pages=200 persisted_json_bytes=%d temp_relation_bytes_before_commit=%d query_spill_temp_bytes_delta=%d heap_alloc_before=%d sampled_peak_heap_alloc=%d heap_alloc_after=%d total_go_alloc_delta=%d elapsed=%s", bytes, relationBytes.Load(), tempAfter-tempBefore, before.HeapAlloc, peak.Load(), after.HeapAlloc, after.TotalAlloc-before.TotalAlloc, elapsed)
}
