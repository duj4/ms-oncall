package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditHundredUsersAndHeap(t *testing.T) {
	t.Run("original_100_roots_25700_history_preserved", func(t *testing.T) { smokeUserHeap(t, 100, true) })
	t.Run("independent_legal_10_roots", func(t *testing.T) { smokeUserHeap(t, 10, false) })
}

func smokeUserHeap(t *testing.T, userCount int, refuse bool) {
	h := sd1Harness(t)
	db := h.App().DB()
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	input := make([]assignment.RawTarget, userCount)
	ids := make([]string, userCount)
	for i := range input {
		ids[i] = smokeOwnedUser(t, h)
		input[i] = assignment.RawTarget{Type: assignment.TargetTypeUser, ID: ids[i]}
	}
	sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,u.id,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM users u CROSS JOIN generate_series(1,257) g WHERE u.id=ANY($2::uuid[])`, s, pq.Array(ids))
	if refuse {
		require.Len(t, input, 100)
		require.EqualValues(t, 25700, sd8Scalar(t, h, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=ANY($1::uuid[])`, pq.Array(ids)))
		before := smokeUserBusinessState(t, h)
		_, err := smokeDeletionPreview(t, h, sd3System(), input)
		smokeDeletionCode(t, err, ds.DeletionPreviewLimitExceeded)
		ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, nil)
		require.Error(t, err)
		require.False(t, ok)
		require.Equal(t, before, smokeUserBusinessState(t, h))
		require.Zero(t, smokeDeletionSuccesses(t, h))
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
		t.Log("original 100-root/25700-history input refused intact; original successful heap/>4MiB throughput is not executable under the frozen profile")
		return
	}
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
	ok, deleteErr := smokeDeleteAll(t, h, app, permission.SystemContext(t.Context(), "Engine"), input)
	elapsed := time.Since(start)
	close(stop)
	<-stopped
	runtime.ReadMemStats(&after)
	require.NoError(t, deleteErr)
	require.True(t, ok)
	require.EqualValues(t, 1, connector.commits.Load())
	require.EqualValues(t, userCount, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
	require.EqualValues(t, userCount*258, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=ANY($1::uuid[])`, pq.Array(ids)))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=ANY($1::uuid[])`, pq.Array(ids)))
	rows, err := db.Query(`SELECT root_id,root_ordinal,effect_count FROM user_delete_audit_events WHERE record_kind='success_witness' ORDER BY root_ordinal`)
	require.NoError(t, err)
	defer rows.Close()
	// ConsumeUser executes the Guard's canonical effective target order.
	expectedOrder := append([]string(nil), ids...)
	slices.Sort(expectedOrder)
	i := 0
	for rows.Next() {
		var id string
		var ordinal, count int
		require.NoError(t, rows.Scan(&id, &ordinal, &count))
		require.Equal(t, i, ordinal)
		require.Equal(t, expectedOrder[i], id)
		require.Equal(t, 258, count) // 257 history rows and the real organization assignment.
		i++
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, userCount, i)
	var bytes, tempAfter int64
	require.NoError(t, db.QueryRow(`SELECT sum(effect_json_bytes) FROM user_delete_audit_events`).Scan(&bytes))
	require.Greater(t, bytes, int64(0))
	require.NoError(t, db.QueryRow(`SELECT temp_bytes FROM pg_stat_database WHERE datname=current_database()`).Scan(&tempAfter))
	require.Greater(t, relationBytes.Load(), int64(0))
	t.Logf("legal users=%d history=%d pages=%d persisted_json_bytes=%d temp_relation_bytes_before_commit=%d query_spill_temp_bytes_delta=%d heap_alloc_before=%d sampled_peak_heap_alloc=%d heap_alloc_after=%d total_go_alloc_delta=%d elapsed=%s", userCount, userCount*257, userCount*2, bytes, relationBytes.Load(), tempAfter-tempBefore, before.HeapAlloc, peak.Load(), after.HeapAlloc, after.TotalAlloc-before.TotalAlloc, elapsed)
}
