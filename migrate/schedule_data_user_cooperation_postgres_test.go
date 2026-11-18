package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/engine/cleanupmanager"
	"github.com/target/goalert/engine/schedulemanager"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/internal/scheduledataref"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/util/timeutil"
)

func jsonWriterCode(t *testing.T, err error, code string) {
	t.Helper()
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	require.Equal(t, code, pg.Code)
}

func jsonWriterUserLock(ctx context.Context, tx *sql.Tx, id uuid.UUID) error {
	var got uuid.UUID
	return tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT`, id).Scan(&got)
}

func jsonWriterData(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT data::text FROM schedule_data WHERE schedule_id=$1`, id).Scan(&raw))
	return raw
}

func jsonWriterStore(ctx context.Context, tx *sql.Tx, store *schedule.Store, f userPhaseAFixture, id uuid.UUID, kind string) error {
	temp := userPhaseATemp(f.user)
	start, end := temp.Start.Add(15*time.Minute), temp.Start.Add(30*time.Minute)
	switch kind {
	case "set":
		return store.SetTemporarySchedule(ctx, tx, id, temp)
	case "set_scoped":
		return store.SetTemporaryScheduleScoped(ctx, tx, id, temp, &f.org)
	case "clear_set":
		return store.SetClearTemporarySchedule(ctx, tx, id, temp, start, end)
	case "clear_set_scoped":
		return store.SetClearTemporaryScheduleScoped(ctx, tx, id, temp, start, end, &f.org)
	case "clear":
		return store.ClearTemporarySchedules(ctx, tx, id, start, end)
	case "clear_scoped":
		return store.ClearTemporarySchedulesScoped(ctx, tx, id, start, end, &f.org)
	case "rules":
		return store.SetOnCallNotificationRules(ctx, tx, id, []schedule.OnCallNotificationRule{})
	case "rules_scoped":
		return store.SetOnCallNotificationRulesScoped(ctx, tx, id, []schedule.OnCallNotificationRule{}, &f.org)
	default:
		panic("unknown test Writer")
	}
}

func TestPostgresUserJSONStoreCooperation(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	for _, kind := range []string{"set", "set_scoped", "clear_set", "clear_set_scoped", "clear", "clear_scoped", "rules", "rules_scoped"} {
		for _, first := range []string{"writer_commit", "writer_rollback", "delete_rollback", "delete_commit"} {
			t.Run(kind+"/"+first, func(t *testing.T) {
				id := f.newSchedule(t, ctx)
				require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org))
				before := jsonWriterData(t, ctx, db, id)
				writer, root := userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)

				// These legacy direct entry points now stop at the new removal
				// gate. Guarded Clear's retained/removed User locking is proved
				// separately through real signed Mutation concurrency tests.
				if kind == "clear" || kind == "clear_scoped" {
					enforceCode(t, jsonWriterStore(ctx, writer, f.schedules, f, id, kind), ds.DeletionConfirmationRequired)
					require.NoError(t, writer.Commit())
					require.NoError(t, root.Rollback())
					require.Equal(t, before, jsonWriterData(t, ctx, db, id))
					return
				}
				_, err := root.ExecContext(ctx, `LOCK TABLE rotation_participants,rotation_state,user_overrides IN EXCLUSIVE MODE NOWAIT`)
				require.NoError(t, err)
				if strings.HasPrefix(first, "writer") {
					require.NoError(t, jsonWriterStore(ctx, writer, f.schedules, f, id, kind))
					jsonWriterCode(t, jsonWriterUserLock(ctx, root, f.user), "55P03")
					require.NoError(t, root.Rollback())
					var strong int
					require.NoError(t, writer.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' AND mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')`).Scan(&strong))
					require.Zero(t, strong, "no new strong relation fence")
					if first == "writer_commit" {
						require.NoError(t, writer.Commit())
					} else {
						require.NoError(t, writer.Rollback())
						require.Equal(t, before, jsonWriterData(t, ctx, db, id))
					}
					root = userPhaseATx(t, ctx, db)
					require.NoError(t, jsonWriterUserLock(ctx, root, f.user))
					require.NoError(t, root.Rollback())
				} else {
					require.NoError(t, jsonWriterUserLock(ctx, root, f.user))
					jsonWriterCode(t, jsonWriterStore(ctx, writer, f.schedules, f, id, kind), "55P03")
					require.NoError(t, writer.Commit(), "failed Writer savepoint left no partial change")
					require.Equal(t, before, jsonWriterData(t, ctx, db, id))
					if first == "delete_commit" {
						// A real committed User state change, without using a product
						// deletion path or disabling any guard.
						_, err := root.ExecContext(ctx, `UPDATE users SET name=name || ' updated' WHERE id=$1`, f.user)
						require.NoError(t, err)
						require.NoError(t, root.Commit())
					} else {
						require.NoError(t, root.Rollback())
					}
					require.NoError(t, jsonWriterStore(ctx, nil, f.schedules, f, id, kind))
				}
			})
		}
	}
}

func jsonWriterTraced(t *testing.T, uri, needle string) (*sql.DB, *nrQueryBarrier) {
	t.Helper()
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	b := &nrQueryBarrier{needle: needle, arrived: make(chan struct{}), resume: make(chan struct{})}
	conf.Tracer = b
	db := sql.OpenDB(stdlib.GetConnector(*conf))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	t.Cleanup(func() {
		select {
		case <-b.resume:
		default:
			close(b.resume)
		}
	})
	return db, b
}

func jsonWriterWait(t *testing.T, ctx context.Context, b *nrQueryBarrier, done <-chan error) {
	t.Helper()
	select {
	case <-b.arrived:
	case err := <-done:
		t.Fatalf("actual Writer failed before deterministic barrier: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestPostgresUserJSONInsertConflictAndLateWriter(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	for _, mode := range []string{"unique_conflict", "late_user_lock"} {
		t.Run(mode, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			needle := "-- name: SchedInsertData"
			if mode == "late_user_lock" {
				needle = "-- name: SchedUpdateData"
			}
			traced, b := jsonWriterTraced(t, uri, needle)
			store, err := schedule.NewStore(ctx, traced, f.users)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- store.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org) }()
			jsonWriterWait(t, ctx, b, done)
			if mode == "unique_conflict" {
				// A second normal Store wins the INSERT and commits its envelope.
				require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org))
			} else {
				root := userPhaseATx(t, ctx, db)
				jsonWriterCode(t, jsonWriterUserLock(ctx, root, f.user), "55P03")
				require.NoError(t, root.Rollback())
			}
			close(b.resume)
			require.NoError(t, <-done)
			ids, err := scheduledataref.Users([]byte(jsonWriterData(t, ctx, db, id)), id)
			require.NoError(t, err)
			require.Equal(t, []uuid.UUID{f.user}, ids)
		})
	}
}

func jsonWriterBackground(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, id uuid.UUID, kind string) func() error {
	t.Helper()
	if strings.HasPrefix(kind, "cleanup") {
		manager, err := cleanupmanager.NewDB(ctx, db, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
		require.NoError(t, err)
		return func() error {
			return manager.CleanupScheduleData(ctx, &river.Job[cleanupmanager.SchedDataArgs]{Args: cleanupmanager.SchedDataArgs{ScheduleID: id}})
		}
	}
	manager, err := schedulemanager.NewDB(ctx, db)
	require.NoError(t, err)
	return func() error { return manager.UpdateAll(ctx) }
}

func jsonWriterBackgroundSetup(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, id uuid.UUID, kind string) {
	t.Helper()
	temp := userPhaseATemp(f.user)
	var data schedule.Data
	data.V1.TemporarySchedules = []schedule.TemporarySchedule{temp}
	data.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{}
	if kind == "cleanup_rewrite" {
		ended := temp
		ended.Start, ended.End = temp.Start.Add(-6*time.Hour), temp.End.Add(-6*time.Hour)
		ended.Shifts = []schedule.FixedShift{{Start: ended.Start, End: ended.End, UserID: f.user.String()}}
		data.V1.TemporarySchedules = append(data.V1.TemporarySchedules, ended)
	}
	if strings.HasPrefix(kind, "manager") {
		old, fresh := uuid.New(), uuid.New()
		for _, channel := range []uuid.UUID{old, fresh} {
			enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, channel)
		}
		clock, days := timeutil.NewClock(12, 0), timeutil.EveryDay()
		data.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{{ChannelID: old, Time: &clock, WeekdayFilter: &days}}
		require.NoError(t, schedule.PrepareOnCallNotificationRules(id, data.V1.OnCallNotificationRules))
		state := `{"HasMigratedScheduleData":true}`
		if kind == "manager_rules" {
			state = `{}`
			enforcementExec(t, ctx, db, `INSERT INTO notification_channel_duplicates(old_id,new_id,old_created_at) VALUES($1,$2,now())`, old, fresh)
		}
		enforcementExec(t, ctx, db, `UPDATE engine_processing_versions SET state=$1::jsonb WHERE type_id='schedule'`, state)
	}
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb) ON CONFLICT(schedule_id) DO UPDATE SET data=excluded.data`, id, string(raw))
}

func TestPostgresUserJSONBackgroundCooperation(t *testing.T) {
	for _, kind := range []string{"manager_rewrite", "manager_rules", "cleanup_rewrite", "cleanup_skip"} {
		for _, first := range []string{"writer", "delete"} {
			t.Run(kind+"/"+first, func(t *testing.T) {
				base, uri, db := boundedAuditDB(t, len(Names()))
				ctx := permission.SystemContext(base, "JSONWriterCooperation")
				var cfg config.Config
				cfg.Maintenance.ScheduleCleanupDays = 30
				ctx = cfg.Context(ctx)
				f := newUserPhaseAFixture(t, ctx, db)
				id := f.newSchedule(t, ctx)
				jsonWriterBackgroundSetup(t, ctx, db, f, id, kind)
				before := jsonWriterData(t, ctx, db, id)
				needle := "-- name: SchedMgrSetData"
				if kind == "manager_rules" {
					needle = "-- name: SchedMgrSetDataV1Rules"
				}
				if kind == "cleanup_rewrite" {
					needle = "-- name: CleanupMgrUpdateScheduleData"
				}
				if kind == "cleanup_skip" {
					needle = "-- name: CleanupMgrScheduleDataSkip"
				}
				if first == "delete" {
					needle = "unreachable barrier"
				}
				traced, b := jsonWriterTraced(t, uri, needle)
				run := jsonWriterBackground(t, ctx, traced, f, id, kind)
				root := userPhaseATx(t, ctx, db)
				_, err := root.ExecContext(ctx, `LOCK TABLE rotation_participants,rotation_state,user_overrides IN EXCLUSIVE MODE NOWAIT`)
				require.NoError(t, err)
				if first == "writer" {
					done := make(chan error, 1)
					go func() { done <- run() }()
					jsonWriterWait(t, ctx, b, done)
					jsonWriterCode(t, jsonWriterUserLock(ctx, root, f.user), "55P03")
					require.NoError(t, root.Rollback())
					close(b.resume)
					require.NoError(t, <-done)
				} else {
					require.NoError(t, jsonWriterUserLock(ctx, root, f.user))
					jsonWriterCode(t, run(), "55P03")
					require.Equal(t, before, jsonWriterData(t, ctx, db, id))
					require.NoError(t, root.Rollback())
					require.NoError(t, run())
				}
			})
		}
	}
}

func TestPostgresUserJSONManagerRepeatableRead(t *testing.T) {
	for _, kind := range []string{"manager_rewrite", "manager_rules"} {
		for _, change := range []string{"update", "delete"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				base, uri, db := boundedAuditDB(t, len(Names()))
				ctx := permission.SystemContext(base, "JSONWriterCooperation")
				f := newUserPhaseAFixture(t, ctx, db)
				id := f.newSchedule(t, ctx)
				jsonWriterBackgroundSetup(t, ctx, db, f, id, kind)
				before := jsonWriterData(t, ctx, db, id)
				traced, b := jsonWriterTraced(t, uri, "SELECT organization_id FROM public.schedules WHERE id=$1 FOR SHARE NOWAIT")
				run := jsonWriterBackground(t, ctx, traced, f, id, kind)
				done := make(chan error, 1)
				go func() { done <- run() }()
				jsonWriterWait(t, ctx, b, done)
				// Real database transitions in an isolated fixture only. This never
				// invokes or grants the fail-closed User DeleteAll product path.
				query := `UPDATE users SET name=name || ' changed' WHERE id=$1`
				if change == "delete" {
					query = `DELETE FROM users WHERE id=$1`
				}
				enforcementExec(t, ctx, db, query, f.user)
				close(b.resume)
				jsonWriterCode(t, <-done, "40001")
				require.Equal(t, before, jsonWriterData(t, ctx, db, id), "old snapshot must not commit any JSON rewrite")
			})
		}
	}
}

func TestPostgresUserJSONDeletedBeforeInsert(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	traced, b := jsonWriterTraced(t, uri, "SELECT organization_id FROM public.schedules WHERE id=$1 FOR SHARE NOWAIT")
	store, err := schedule.NewStore(ctx, traced, f.users)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- store.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org) }()
	jsonWriterWait(t, ctx, b, done)
	enforcementExec(t, ctx, db, `DELETE FROM users WHERE id=$1`, f.user)
	close(b.resume)
	require.Error(t, <-done)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, id))
}

func TestPostgresUserJSONCleanupOldRead(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	var cfg config.Config
	cfg.Maintenance.ScheduleCleanupDays = 30
	ctx = cfg.Context(ctx)
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	jsonWriterBackgroundSetup(t, ctx, db, f, id, "cleanup_rewrite")
	before := jsonWriterData(t, ctx, db, id)
	traced, b := jsonWriterTraced(t, uri, "SELECT organization_id FROM public.schedules WHERE id=$1 FOR SHARE NOWAIT")
	run := jsonWriterBackground(t, ctx, traced, f, id, "cleanup_rewrite")
	done := make(chan error, 1)
	go func() { done <- run() }()
	jsonWriterWait(t, ctx, b, done)
	enforcementExec(t, ctx, db, `DELETE FROM users WHERE id=$1`, f.user)
	close(b.resume)
	require.Error(t, <-done)
	require.Equal(t, before, jsonWriterData(t, ctx, db, id))
	// A fresh cleanup observes the absent User and preserves its established
	// cleanup semantics: only the expired/missing references are removed.
	require.NoError(t, run())
	ids, err := scheduledataref.Users([]byte(jsonWriterData(t, ctx, db, id)), id)
	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestPostgresUserJSONMultipleUsersScopeAndVersion(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f, g := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, g.user, f.org)
	a, b := f.newSchedule(t, ctx), f.newSchedule(t, ctx)
	one, two := userPhaseATemp(f.user), userPhaseATemp(g.user)
	one.Shifts = append(one.Shifts, two.Shifts...)
	two.Shifts = append(two.Shifts, one.Shifts[0])
	left, right := userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, left, a, one, &f.org))
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, right, b, two, &f.org))
	for _, id := range []uuid.UUID{f.user, g.user} {
		probe := userPhaseATx(t, ctx, db)
		jsonWriterCode(t, jsonWriterUserLock(ctx, probe, id), "55P03")
		require.NoError(t, probe.Rollback())
	}
	require.NoError(t, left.Commit())
	require.NoError(t, right.Commit())
	// Exercise opposite *persisted* array order too: the metadata Writers retain
	// these business-equivalent arrays verbatim and must still lock sorted IDs.
	enforcementExec(t, ctx, db, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules,0,Shifts}',(SELECT jsonb_agg(s ORDER BY n DESC) FROM jsonb_array_elements(data#>'{V1,TemporarySchedules,0,Shifts}') WITH ORDINALITY e(s,n))) WHERE schedule_id=$1`, b)
	beforeB := jsonWriterData(t, ctx, db, b)
	left, right = userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)
	require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, left, a, []schedule.OnCallNotificationRule{}, &f.org))
	require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, right, b, []schedule.OnCallNotificationRule{}, &f.org))
	require.NoError(t, left.Commit())
	require.NoError(t, right.Commit())
	var beforeData, afterData schedule.Data
	require.NoError(t, json.Unmarshal([]byte(beforeB), &beforeData))
	require.NoError(t, json.Unmarshal([]byte(jsonWriterData(t, ctx, db, b)), &afterData))
	require.Equal(t, beforeData.V1.TemporarySchedules, afterData.V1.TemporarySchedules)
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	build := func(facts collector.Result) (ds.DeletionPlan, error) {
		return ds.BuildPlan(ds.PlanInput{Operation: ds.OperationDeleteResources, Targets: []ds.Resource{root}, Intent: []ds.DestructiveChange{{Resource: root, Kind: ds.ChangeDeleted}}, ScopeFingerprint: facts.ScopeFingerprint, Collection: facts.Collection}, ds.Budget{})
	}
	plan, err := build(facts)
	require.NoError(t, err)
	beforeVersion := plan.ImpactVersion()
	require.NoError(t, jsonWriterConfirmedClear(t, ctx, db, f, a, one.Start, one.End))
	facts, err = collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	plan, err = build(facts)
	require.NoError(t, err)
	require.NotEqual(t, beforeVersion, plan.ImpactVersion())
	// A direct reference replacement now requires consent even when the
	// removed User would be absent from the final envelope's lock set.
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, a, userPhaseATemp(f.user), &f.org))
	removed := userPhaseATx(t, ctx, db)
	require.NoError(t, jsonWriterUserLock(ctx, removed, f.user))
	enforceCode(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, a, userPhaseATemp(g.user), &f.org), ds.DeletionConfirmationRequired)
	require.NoError(t, removed.Rollback())
	require.NoError(t, jsonWriterConfirmedSet(t, ctx, db, f, a, userPhaseATemp(g.user)))
	remaining, err := scheduledataref.Users([]byte(jsonWriterData(t, ctx, db, a)), a)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{g.user}, remaining)
	for _, kind := range []string{"cross_org", "no_assignment", "unknown_user"} {
		t.Run(kind, func(t *testing.T) {
			bad := uuid.New()
			if kind != "unknown_user" {
				h := newUserPhaseAFixture(t, ctx, db)
				bad = h.user
				if kind == "no_assignment" {
					enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, bad)
				}
			}
			id := f.newSchedule(t, ctx)
			for _, scoped := range []bool{false, true} {
				tx := userPhaseATx(t, ctx, db)
				var scope *uuid.UUID
				if scoped {
					scope = &f.org
				}
				require.Error(t, f.schedules.SetTemporaryScheduleScoped(ctx, tx, id, userPhaseATemp(bad), scope))
				require.NoError(t, tx.Commit())
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, id))
			}
		})
	}
}

func TestPostgresUserJSONScopeLocks(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org))
	for _, target := range []string{"user", "assignment", "parent", "organization", "normal"} {
		for _, first := range []string{"writer", "scope"} {
			t.Run(target+"/"+first, func(t *testing.T) {
				query := map[string]string{
					"user":         `UPDATE users SET name=name WHERE id=$1`,
					"assignment":   `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`,
					"parent":       `UPDATE schedules SET name=name WHERE id=$1`,
					"organization": `UPDATE organizations SET display_name=display_name WHERE id=$1`,
					"normal":       `UPDATE normal_organizations SET corporate_mapping_key=corporate_mapping_key WHERE organization_id=$1`,
				}[target]
				value := f.org
				if target == "user" || target == "assignment" {
					value = f.user
				}
				if target == "parent" {
					value = id
				}
				writer, other := userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)
				_, err := other.ExecContext(ctx, `SET LOCAL lock_timeout='150ms'`)
				require.NoError(t, err)
				write := func() error {
					return f.schedules.SetOnCallNotificationRulesScoped(ctx, writer, id, []schedule.OnCallNotificationRule{}, &f.org)
				}
				if first == "writer" {
					require.NoError(t, write())
					_, err = other.ExecContext(ctx, query, value)
					jsonWriterCode(t, err, "55P03")
					require.NoError(t, other.Rollback())
					require.NoError(t, writer.Commit())
				} else {
					_, err = other.ExecContext(ctx, query, value)
					require.NoError(t, err)
					jsonWriterCode(t, write(), "55P03")
					require.NoError(t, writer.Commit())
					require.NoError(t, other.Rollback())
				}
			})
		}
	}
	// A scope change after the scoped parent's ordinary authorization read is
	// rechecked under the final parent lock even when no User is being added.
	t.Run("parent_changed_after_authorization", func(t *testing.T) {
		other := newUserPhaseAFixture(t, ctx, db)
		traced, b := jsonWriterTraced(t, uri, "-- name: SchedFindDataForUpdate")
		store, err := schedule.NewStore(ctx, traced, f.users)
		require.NoError(t, err)
		before := jsonWriterData(t, ctx, db, id)
		done := make(chan error, 1)
		go func() {
			done <- store.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org)
		}()
		jsonWriterWait(t, ctx, b, done)
		enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, id, other.org)
		close(b.resume)
		require.Error(t, <-done)
		require.Equal(t, before, jsonWriterData(t, ctx, db, id))
	})
}

func TestPostgresUserJSONInvalidRetainedEnvelope(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	for _, value := range []string{"null", "[]", "{}", `"bad"`, "1", "true", "[null]"} {
		t.Run(value, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			raw := `{"V1":{"TemporarySchedules":` + value + `,"OnCallNotificationRules":[]}}`
			enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb)`, id, raw)
			before := jsonWriterData(t, ctx, db, id)
			err := f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org)
			if value == "null" || value == "[]" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, before, jsonWriterData(t, ctx, db, id))
			}
			facts, err := collectDeletion(t, ctx, db, ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}, collector.Limits{})
			if value == "null" || value == "[]" {
				require.NoError(t, err)
				require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
			} else {
				require.Error(t, err)
			}
			enforcementExec(t, ctx, db, `DELETE FROM schedule_data WHERE schedule_id=$1`, id)
		})
	}
	for _, kind := range []string{"unknown_envelope", "unknown_shift", "invalid_user", "missing_user", "invalid_time", "incomplete", "budget"} {
		t.Run(kind, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			temp := userPhaseATemp(f.user)
			var data schedule.Data
			data.V1.TemporarySchedules = []schedule.TemporarySchedule{temp}
			data.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{}
			raw, err := json.Marshal(data)
			require.NoError(t, err)
			s := string(raw)
			switch kind {
			case "unknown_envelope":
				s = strings.Replace(s, `"V1":`, `"Unknown":{},"V1":`, 1)
			case "unknown_shift":
				s = strings.Replace(s, `"UserID":`, `"Unknown":true,"UserID":`, 1)
			case "invalid_user":
				s = strings.ReplaceAll(s, f.user.String(), "not-a-user")
			case "missing_user":
				s = strings.ReplaceAll(s, f.user.String(), uuid.NewString())
			case "invalid_time":
				s = strings.ReplaceAll(s, temp.Start.Format(time.RFC3339Nano), "invalid-time")
			case "incomplete":
				s = `{"V1":{}}`
			case "budget":
				s = `{"V1":{"TemporarySchedules":null,"Unknown":"` + strings.Repeat("x", scheduledataref.MaxBytes) + `"}}`
			}
			enforcementExec(t, ctx, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb)`, id, s)
			before := jsonWriterData(t, ctx, db, id)
			for _, scoped := range []bool{false, true} {
				var scope *uuid.UUID
				if scoped {
					scope = &f.org
				}
				require.Error(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, scope))
				require.Equal(t, before, jsonWriterData(t, ctx, db, id))
			}
			enforcementExec(t, ctx, db, `DELETE FROM schedule_data WHERE schedule_id=$1`, id)
		})
	}
	t.Run("normal_empty_shifts", func(t *testing.T) {
		id := f.newSchedule(t, ctx)
		temp := userPhaseATemp(f.user)
		temp.Shifts = nil
		require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
		facts, err := collectDeletion(t, ctx, db, ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}, collector.Limits{})
		require.NoError(t, err)
		require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
	})
}

func TestPostgresUserJSONIndependentWriters(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org))
	other := newDeletionFixture(t, ctx, db)
	sameOrgSchedule := f.newSchedule(t, ctx)
	writes := []nrWrite{
		{name: "service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
		{name: "escalation_policy", query: `UPDATE escalation_policies SET name=name WHERE id=$1`, args: []any{other.policy}},
		{name: "integration_key", query: `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`, args: []any{other.keyAudit}},
		{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
		{name: "contact_method", query: `UPDATE user_contact_methods SET disabled=disabled WHERE id=$1`, args: []any{other.cm}},
		{name: "notification_rule", query: `UPDATE user_notification_rules SET delay_minutes=delay_minutes WHERE id=$1`, args: []any{other.nr}},
		{name: "user_override", query: `UPDATE user_overrides SET end_time=end_time WHERE id=$1`, args: []any{other.override}},
		{name: "other_organization_user", query: `UPDATE users SET name=name WHERE id=$1`, args: []any{other.user}},
		{name: "unrelated_schedule", query: `UPDATE schedules SET name=name WHERE id=$1`, args: []any{other.schedule}},
		{name: "same_organization_schedule", query: `UPDATE schedules SET name=name WHERE id=$1`, args: []any{sameOrgSchedule}},
	}
	for _, w := range writes {
		for _, first := range []string{"json", "independent"} {
			for _, commit := range []bool{false, true} {
				t.Run(w.name+"/"+first+"/"+map[bool]string{true: "commit", false: "rollback"}[commit], func(t *testing.T) {
					jtx, otx := userPhaseATx(t, ctx, db), userPhaseATx(t, ctx, db)
					independent := func() {
						r, err := otx.ExecContext(ctx, w.query, w.args...)
						require.NoError(t, err)
						n, err := r.RowsAffected()
						require.NoError(t, err)
						require.EqualValues(t, 1, n)
					}
					jsonWrite := func() {
						require.NoError(t, f.schedules.SetOnCallNotificationRulesScoped(ctx, jtx, id, []schedule.OnCallNotificationRule{}, &f.org))
					}
					if first == "json" {
						jsonWrite()
						independent()
					} else {
						independent()
						jsonWrite()
					}
					var added, strong int
					require.NoError(t, jtx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE mode='RowShareLock' AND relation IN ('users'::regclass,'schedules'::regclass,'user_organization_assignments'::regclass,'organizations'::regclass,'normal_organizations'::regclass)),count(*) FILTER(WHERE mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')) FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation'`).Scan(&added, &strong))
					require.Equal(t, 5, added)
					require.Zero(t, strong)
					if commit {
						require.NoError(t, jtx.Commit())
						require.NoError(t, otx.Commit())
					} else {
						require.NoError(t, jtx.Rollback())
						require.NoError(t, otx.Rollback())
					}
				})
			}
		}
	}
}

func TestPostgresUserJSONMigrationRollbackRetry(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	f, g := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
	a, b := f.newSchedule(t, ctx), g.newSchedule(t, ctx)
	jsonWriterBackgroundSetup(t, ctx, db, f, a, "manager_rules")
	jsonWriterBackgroundSetup(t, ctx, db, g, b, "manager_rules")
	beforeA, beforeB := jsonWriterData(t, ctx, db, a), jsonWriterData(t, ctx, db, b)
	last := f.user
	if a.String() < b.String() {
		last = g.user
	}
	root := userPhaseATx(t, ctx, db)
	require.NoError(t, jsonWriterUserLock(ctx, root, last))
	run := jsonWriterBackground(t, ctx, db, f, a, "manager_rules")
	jsonWriterCode(t, run(), "55P03")
	require.Equal(t, beforeA, jsonWriterData(t, ctx, db, a))
	require.Equal(t, beforeB, jsonWriterData(t, ctx, db, b))
	require.NoError(t, root.Rollback())
	require.NoError(t, run(), "same Manager must retry all transaction-rolled-back migration work")
	var migrated int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM schedule_data d JOIN notification_channel_duplicates m ON m.new_id=(d.data#>>'{V1,OnCallNotificationRules,0,ChannelID}')::uuid WHERE schedule_id=ANY($1::uuid[])`, sqlutil.StringArray([]string{a.String(), b.String()})).Scan(&migrated))
	require.Equal(t, 2, migrated)
}

func TestPostgresUserJSONCleanupRetainsValidAndStoreCompetition(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "JSONWriterCooperation")
	var cfg config.Config
	cfg.Maintenance.ScheduleCleanupDays = 30
	ctx = cfg.Context(ctx)
	f := newUserPhaseAFixture(t, ctx, db)
	id := f.newSchedule(t, ctx)
	jsonWriterBackgroundSetup(t, ctx, db, f, id, "cleanup_rewrite")
	missing := uuid.New()
	enforcementExec(t, ctx, db, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules,0,Shifts}',(data#>'{V1,TemporarySchedules,0,Shifts}')||jsonb_build_array(jsonb_set(data#>'{V1,TemporarySchedules,0,Shifts,0}','{UserID}',to_jsonb($2::text)))) WHERE schedule_id=$1`, id, missing.String())
	run := jsonWriterBackground(t, ctx, db, f, id, "cleanup_rewrite")
	require.NoError(t, run())
	var data schedule.Data
	require.NoError(t, json.Unmarshal([]byte(jsonWriterData(t, ctx, db, id)), &data))
	require.Len(t, data.V1.TemporarySchedules, 1)
	require.Len(t, data.V1.TemporarySchedules[0].Shifts, 1)
	require.Equal(t, f.user.String(), data.V1.TemporarySchedules[0].Shifts[0].UserID)
	for _, first := range []string{"cleanup", "store"} {
		t.Run(first, func(t *testing.T) {
			needle := "-- name: CleanupMgrScheduleDataSkip"
			if first == "store" {
				needle = "-- name: SchedUpdateData"
			}
			traced, b := jsonWriterTraced(t, uri, needle)
			store, err := schedule.NewStore(ctx, traced, f.users)
			require.NoError(t, err)
			cleanup := jsonWriterBackground(t, ctx, traced, f, id, "cleanup_skip")
			firstDone, secondDone := make(chan error, 1), make(chan error, 1)
			if first == "cleanup" {
				go func() { firstDone <- cleanup() }()
			} else {
				go func() {
					firstDone <- store.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org)
				}()
			}
			jsonWriterWait(t, ctx, b, firstDone)
			if first == "cleanup" {
				go func() {
					secondDone <- f.schedules.SetOnCallNotificationRulesScoped(ctx, nil, id, []schedule.OnCallNotificationRule{}, &f.org)
				}()
			} else {
				go func() { secondDone <- run() }()
			}
			// Observe the actual row-lock wait, never infer ordering from sleep.
			for enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%schedule_data%'`) == 0 {
				select {
				case err := <-secondDone:
					t.Fatalf("second Writer did not reach real ScheduleData wait: %v", err)
				default:
				}
				require.NoError(t, ctx.Err())
			}
			close(b.resume)
			require.NoError(t, <-firstDone)
			require.NoError(t, <-secondDone)
		})
	}
	// Cleanup keeps its independent lifecycle; an interactive direct Clear
	// cannot borrow that authority. Confirm explicitly after releasing the
	// competing User lock, then verify the complete reference set was removed.
	root := userPhaseATx(t, ctx, db)
	require.NoError(t, jsonWriterUserLock(ctx, root, f.user))
	temp := data.V1.TemporarySchedules[0]
	enforceCode(t, f.schedules.ClearTemporarySchedulesScoped(ctx, nil, id, temp.Start, temp.End, &f.org), ds.DeletionConfirmationRequired)
	require.NoError(t, root.Rollback())
	require.NoError(t, jsonWriterConfirmedClear(t, ctx, db, f, id, temp.Start, temp.End))
	ids, err := scheduledataref.Users([]byte(jsonWriterData(t, ctx, db, id)), id)
	require.NoError(t, err)
	require.Empty(t, ids)
}

// Use production Preview/confirmation for fixture mutations that intentionally
// remove coverage. No test-only capability or alternate writer is introduced.
func jsonWriterConfirmedClear(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, id uuid.UUID, start, end time.Time) error {
	t.Helper()
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	input := graphql2.ClearTemporarySchedulesInput{ScheduleID: id.String(), Start: start, End: end}
	preview, err := app.Query().PreviewClearTemporarySchedules(ctx, input)
	if err != nil {
		return err
	}
	input.Confirmation = updateNativeConfirmation(preview)
	_, err = app.Mutation().ClearTemporarySchedules(ctx, input)
	return err
}
func jsonWriterConfirmedSet(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, id uuid.UUID, temp schedule.TemporarySchedule) error {
	t.Helper()
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	input := graphql2.SetTemporaryScheduleInput{ScheduleID: id.String(), Start: temp.Start, End: temp.End, Shifts: temp.Shifts}
	preview, err := app.Query().PreviewSetTemporarySchedule(ctx, input)
	if err != nil {
		return err
	}
	input.Confirmation = updateNativeConfirmation(preview)
	_, err = app.Mutation().SetTemporarySchedule(ctx, input)
	return err
}
