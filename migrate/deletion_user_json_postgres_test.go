package migrate

import (
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2"
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
	temp := userPhaseATemp(f.user)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, a, temp, &f.org))
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, b, temp, &f.org))
	beforeA, beforeB := scheduleJSONInventory(t, ctx, db, a), scheduleJSONInventory(t, ctx, db, b)
	assertProtected := func() {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
		for _, table := range []string{"user_contact_methods", "user_notification_rules", "auth_user_sessions", "user_organization_assignments"} {
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE user_id=$1`, f.user))
		}
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.user))
	}
	_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionBlocked)
	assertProtected()
	// The legacy unconfirmed Store call must still wait for the envelope,
	// then fail closed under Migration308 without poisoning its caller's tx.
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
		done <- f.schedules.ClearTemporarySchedulesScoped(ctx, writer, a, temp.Start, temp.End, &f.org)
	}()
	overrideWait(t, ctx, db, pid, done)
	require.NoError(t, tx.Rollback())
	enforceCode(t, <-done, ds.DeletionConfirmationRequired)
	require.NoError(t, writer.Commit())
	require.Equal(t, beforeA, scheduleJSONInventory(t, ctx, db, a))
	require.Equal(t, beforeB, scheduleJSONInventory(t, ctx, db, b))
	assertProtected()
	t.Log("unconfirmed Scoped Clear rejected; caller commit preserved JSON, references and success audit")

	// A private physical SQL writer preserves the original Root-first removal
	// contention. It is not a protected business mutation and creates no audit.
	var expectedA string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_set(data,'{V1,TemporarySchedules}','[]'::jsonb)::text FROM schedule_data WHERE schedule_id=$1`, a).Scan(&expectedA))
	tx = userPhaseATx(t, ctx, db)
	_, _, err = guard.StabilizeUser(ctx, tx, userProfileSelectors(f.user))
	require.NoError(t, err)
	var rootPID int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&rootPID))
	writer = epProfileWriter(t, ctx, db)
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	var rows int64
	go func() {
		result, err := writer.ExecContext(ctx, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules}',$2::jsonb) WHERE schedule_id=$1`, a, `[]`)
		if err == nil {
			rows, err = result.RowsAffected()
		}
		done <- err
	}()
	overrideWait(t, ctx, db, pid, done)
	var blockedByRoot bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT $1::int=ANY(pg_blocking_pids($2))`, rootPID, pid).Scan(&blockedByRoot))
	require.True(t, blockedByRoot)
	require.Equal(t, beforeA, scheduleJSONInventory(t, ctx, db, a))
	assertProtected()
	t.Log("private SQL writer blocked by stabilized User Root on the referenced schedule_data envelope")
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.EqualValues(t, 1, rows)
	// The updated row stays locked and invisible to a separate connection until
	// the writer commits; NOWAIT proves real contention rather than elapsed time.
	probe := epProfileWriter(t, ctx, db)
	_, err = probe.ExecContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1 FOR UPDATE NOWAIT`, a)
	jsonWriterCode(t, err, "55P03")
	require.NoError(t, probe.Rollback())
	require.Equal(t, beforeA, scheduleJSONInventory(t, ctx, db, a))
	require.NoError(t, writer.Commit())
	require.JSONEq(t, expectedA, jsonWriterData(t, ctx, db, a))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE schedule_id=$1`, a))
	require.Equal(t, beforeB, scheduleJSONInventory(t, ctx, db, b))
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionBlocked) // b still protects the User.
	assertProtected()

	// Remove b through the existing production Preview/Confirmation/Mutation
	// path, using the actual signed version returned by Preview.
	app.UserStore, app.ScheduleStore = f.users, f.schedules
	input := graphql2.ClearTemporarySchedulesInput{ScheduleID: b.String(), Start: temp.Start, End: temp.End}
	p, err := app.Query().PreviewClearTemporarySchedules(ctx, input)
	require.NoError(t, err)
	require.True(t, p.Complete && p.CanProceed && p.RequiresConfirmation)
	input.Confirmation = updateNativeConfirmation(p)
	_, err = app.Mutation().ClearTemporarySchedules(ctx, input)
	require.NoError(t, err)
	require.NotContains(t, jsonWriterData(t, ctx, db, b), f.user.String())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE schedule_id=$1`, b))
	afterA, afterB := scheduleJSONInventory(t, ctx, db, a), scheduleJSONInventory(t, ctx, db, b)
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	assertProtected()
	require.Equal(t, afterA, scheduleJSONInventory(t, ctx, db, a))
	require.Equal(t, afterB, scheduleJSONInventory(t, ctx, db, b))
	confirm = enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
	_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
	require.NoError(t, err)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	for _, table := range []string{"user_contact_methods", "user_notification_rules", "auth_user_sessions", "user_organization_assignments"} {
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE user_id=$1`, f.user))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND record_kind='success_witness' AND operation='user.delete' AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql'`, f.user))
	for typ, count := range map[string]int{"contact_method": 1, "notification_rule": 1, "user_organization_assignment": 1, "user_session": 1} {
		require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND f.resource_type=$2 AND payload->>'deletion_mechanism'='fk_cascade'`, f.user, typ))
	}
	require.Equal(t, afterA, scheduleJSONInventory(t, ctx, db, a))
	require.Equal(t, afterB, scheduleJSONInventory(t, ctx, db, b))
	probe = epProfileWriter(t, ctx, db)
	_, err = probe.ExecContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id IN ($1,$2) FOR UPDATE NOWAIT`, a, b)
	require.NoError(t, err)
	require.NoError(t, probe.Rollback())
	t.Log("fresh User Delete recheck committed once; B2 effects match actual closure and JSON locks released")
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
