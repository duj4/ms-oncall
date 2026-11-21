package migrate

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

// This is a synchronization barrier on an actual PostgreSQL connection after
// enforcement has taken its locks, immediately before business DML. SQL still
// executes on PostgreSQL; another physical connection proves lock ownership.
type updateNativeBarrier struct {
	prefix  string
	names   sync.Map
	armed   atomic.Bool
	ready   chan uint32
	release chan struct{}
}

func (b *updateNativeBarrier) TraceQueryStart(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	sql := q.SQL
	if prepared, ok := b.names.Load(sql); ok {
		sql = prepared.(string)
	}
	if strings.Contains(strings.ToLower(sql), b.prefix) && b.armed.CompareAndSwap(true, false) {
		b.ready <- c.PgConn().PID()
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (b *updateNativeBarrier) TracePrepareStart(ctx context.Context, _ *pgx.Conn, d pgx.TracePrepareStartData) context.Context {
	b.names.Store(d.Name, d.SQL)
	return ctx
}
func (*updateNativeBarrier) TracePrepareEnd(context.Context, *pgx.Conn, pgx.TracePrepareEndData) {}
func (*updateNativeBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData)     {}

func TestPostgresUpdateInducedSafetyConcurrency(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	ctx := permission.SystemContext(base, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, kind := range []string{"U01", "U02", "U03"} {
		for _, mode := range []string{"same_update", "child_writer", "root_delete", "json_writer", "parent_scope", "non_destructive"} {
			if (kind != "U03" && mode == "json_writer") || (kind != "U02" && (mode == "parent_scope" || mode == "non_destructive")) {
				continue
			} // No JSON column refers to an EP Step or Action.
			t.Run(kind+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
				defer cancel()
				f := newUpdateNativeFixture(t, ctx, db, kind)
				if mode == "non_destructive" {
					f.nondestructive()
				}
				if mode == "json_writer" {
					enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{"V1":{"TemporarySchedules":[],"OnCallNotificationRules":[]}}')`, f.schedule)
				}
				p, err := f.preview(ctx, app)
				require.NoError(t, err)
				confirm := updateNativeConfirmation(p)
				if mode == "non_destructive" {
					require.False(t, p.RequiresConfirmation)
					confirm = nil
				}
				rootInput := epProfileInput(f.epProfileFixture.policy)
				previewInput := epProfilePreviewInput(f.epProfileFixture.policy)
				if kind == "U03" {
					rootInput = scheduleProfileInput(f.schedule)
					previewInput = scheduleProfilePreviewInput(f.schedule)
				}
				var rootConfirm *graphql2.DeletionSafetyConfirmationInput
				if mode == "root_delete" {
					rootConfirm = enforcementPreview(t, ctx, app, previewInput...)
				}
				prefix := "update escalation_policies"
				if kind == "U02" {
					prefix = "delete from escalation_policy_actions"
					if mode == "non_destructive" {
						prefix = "update escalation_policy_steps"
					}
				}
				if kind == "U03" {
					prefix = "delete from schedule_rules"
				}
				barrier := &updateNativeBarrier{prefix: prefix, ready: make(chan uint32, 1), release: make(chan struct{})}
				cfg, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				cfg.Tracer = barrier
				ownerDB := stdlib.OpenDB(*cfg)
				t.Cleanup(func() { require.NoError(t, ownerDB.Close()) })
				owner := updateNativeApp(t, ctx, ownerDB)
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(barrier.release) }) }
				t.Cleanup(release)
				ownerDone := make(chan error, 1)
				barrier.armed.Store(true)
				go func() { _, e := f.mutate(ctx, owner, confirm); ownerDone <- e }()
				var ownerPID uint32
				select {
				case ownerPID = <-barrier.ready:
				case e := <-ownerDone:
					require.FailNow(t, "owner did not reach actual DML barrier", "%v", e)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				switch mode {
				case "root_delete":
					_, err := app.Mutation().DeleteAll(ctx, rootInput, rootConfirm)
					require.Error(t, err)
				case "json_writer":
					writer, err := db.BeginTx(ctx, nil)
					require.NoError(t, err)
					err = app.ScheduleStore.SetOnCallNotificationRules(ctx, writer, f.schedule, nil)
					require.Error(t, err, "JSON writer's existing NOWAIT parent lock must reject the concurrent rewrite")
					require.NoError(t, writer.Rollback())
				case "child_writer", "parent_scope", "non_destructive":
					writer, err := db.BeginTx(ctx, nil)
					require.NoError(t, err)
					query := `UPDATE escalation_policy_actions SET user_id=user_id WHERE id=$1`
					if mode == "non_destructive" {
						query = `UPDATE escalation_policy_actions SET user_id=NULL,schedule_id='` + f.schedule.String() + `' WHERE id=$1`
					}
					id := f.action.String()
					if kind == "U03" {
						require.NoError(t, db.QueryRowContext(ctx, `SELECT id::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 LIMIT 1`, f.schedule, f.user).Scan(&id))
						query = `UPDATE schedule_rules SET start_time='02:00' WHERE id=$1`
					}
					if mode == "parent_scope" {
						other := newEPProfileFixture(t, ctx, db, false)
						query = `UPDATE escalation_policies SET organization_id='` + other.org.String() + `' WHERE id=$1`
						id = f.epProfileFixture.policy.String()
					}
					done := serviceProfileWait(t, ctx, db, writer, func() error { _, e := writer.ExecContext(ctx, query, id); return e })
					// pg_blocking_pids is direct evidence of a different connection's
					// wait, while the mutation remains at its controlled barrier.
					var blocked bool
					require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, ownerPID).Scan(&blocked))
					require.True(t, blocked)
					release()
					require.NoError(t, <-ownerDone)
					require.NoError(t, <-done)
					require.NoError(t, writer.Commit())
					if mode == "non_destructive" {
						require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, f.action))
						require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
					}
					return
				case "same_update":
					done := make(chan error, 1)
					go func() { _, e := f.mutate(ctx, app, confirm); done <- e }()
					if kind == "U01" {
						enforceCode(t, <-done, ds.DeletionUnavailable)
					} else {
						for {
							var blocked bool
							require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, ownerPID).Scan(&blocked))
							if blocked {
								break
							}
							select {
							case e := <-done:
								require.FailNow(t, "second update did not wait for owner", "%v", e)
							default:
							}
							require.NoError(t, ctx.Err())
						}
						release()
						require.NoError(t, <-ownerDone)
						enforceCode(t, <-done, ds.DeletionDependencyChanged)
						return
					}
				}
				release()
				require.NoError(t, <-ownerDone)
				// No second operation may turn into an extra committed deletion.
				_, err = f.mutate(ctx, app, confirm)
				enforceCode(t, err, ds.DeletionDependencyChanged)
			})
		}
	}
}
