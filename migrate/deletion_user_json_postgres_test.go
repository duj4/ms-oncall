package migrate

import (
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
)

func TestPostgresDeletionEnforcementUserJSONLateWriter(t *testing.T) {
	for _, phase := range []string{"old_read", "shared_lock"} {
		t.Run(phase, func(t *testing.T) {
			base, uri, db := boundedAuditDB(t, len(Names()))
			ctx := permission.SystemContext(base, "UserNative")
			f := userNativeLifecycle(t, ctx, db, 1, 1, true)
			id := f.newSchedule(t, ctx)
			app := enforcementApp(t, ctx, db)
			confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
			needle := "FROM public.schedules WHERE id=$1 FOR SHARE NOWAIT"
			if phase == "shared_lock" {
				needle = "-- name: SchedUpdateData"
			}
			traced, b := jsonWriterTraced(t, uri, needle)
			store, err := schedule.NewStore(ctx, traced, f.users)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- store.SetTemporaryScheduleScoped(ctx, nil, id, userPhaseATemp(f.user), &f.org) }()
			jsonWriterWait(t, ctx, b, done)
			_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
			if phase == "old_read" {
				require.NoError(t, err)
				close(b.resume)
				require.Error(t, <-done)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, id))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.user))
			} else {
				require.Error(t, err)
				close(b.resume)
				require.NoError(t, <-done)
				confirm = enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
				_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
				enforceCode(t, err, ds.DeletionBlocked)
				require.Contains(t, jsonWriterData(t, ctx, db, id), f.user.String())
			}
		})
	}
}

func TestPostgresDeletionEnforcementUserJSONFinalRecheck(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	f := userNativeLifecycle(t, ctx, db, 1, 1, true)
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	a, b := f.newSchedule(t, ctx), f.newSchedule(t, ctx)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, a, userPhaseATemp(f.user), &f.org))
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, b, userPhaseATemp(f.user), &f.org))
	_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionBlocked)
	// Removal needs no share lock on the removed User, but must still wait
	// for the locked envelope that the final Collector will inspect.
	confirm = enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	tx := userPhaseATx(t, ctx, db)
	_, _, err = guard.StabilizeUser(ctx, tx, userProfileSelectors(f.user))
	require.NoError(t, err)
	// The relevant envelope remains locked too; removal cannot invalidate an
	// already certified informational fragment behind the final Collector.
	writer := epProfileWriter(t, ctx, db)
	var pid int
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	done := make(chan error, 1)
	go func() {
		done <- f.schedules.ClearTemporarySchedulesScoped(ctx, writer, a, userPhaseATemp(f.user).Start, userPhaseATemp(f.user).End, &f.org)
	}()
	overrideWait(t, ctx, db, pid, done)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.NoError(t, writer.Commit())
	require.NoError(t, f.schedules.ClearTemporarySchedulesScoped(ctx, nil, b, userPhaseATemp(f.user).Start, userPhaseATemp(f.user).End, &f.org))
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	confirm = enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	require.NoError(t, err)
}

func TestPostgresDeletionEnforcementUserScopeWriters(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"organization", "normal", "parent"} {
			t.Run(first+"/"+kind, func(t *testing.T) {
				f := userNativeLifecycle(t, ctx, db, 1, 1, true)
				p := userNativeParentRows(t, ctx, db, f)
				userNativeAddReference(t, ctx, db, f, p, "ended_override")
				version := userProfileVersion(t, ctx, db, f.user)
				query := `UPDATE organizations SET display_name=display_name WHERE id=$1`
				id := f.org
				if kind == "normal" {
					query = `UPDATE normal_organizations SET corporate_mapping_key=corporate_mapping_key WHERE organization_id=$1`
				}
				if kind == "parent" {
					query = `UPDATE schedules SET description=description WHERE id=$1`
					id = p.schedule
				}
				tx, writer := userPhaseATx(t, ctx, db), epProfileWriter(t, ctx, db)
				if first == "writer" {
					_, err := writer.ExecContext(ctx, query, id)
					require.NoError(t, err)
					_, err = collector.Enforce(ctx, tx, userProfileSelectors(f.user), version, true, authorizeDeletionFixture(userProfileRoot(f.user)))
					require.Error(t, err)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
				} else {
					_ = userProfileEnforce(t, ctx, tx, f.user, version)
					var pid int
					require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
					done := make(chan error, 1)
					go func() { _, err := writer.ExecContext(ctx, query, id); done <- err }()
					overrideWait(t, ctx, db, pid, done)
					require.NoError(t, tx.Rollback())
					require.NoError(t, <-done)
					require.NoError(t, writer.Commit())
				}
			})
		}
	}
}
