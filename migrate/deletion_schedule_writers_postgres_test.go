package migrate

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/engine/cleanupmanager"
	"github.com/target/goalert/engine/schedulemanager"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
)

func TestPostgresDeletionEnforcementScheduleMissingEnvelope(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, first := range []string{"writer", "delete"} {
		for _, mode := range []string{"raw_insert", "store_insert"} {
			t.Run(first+"_"+mode, func(t *testing.T) {
				f := newScheduleProfileFixture(t, ctx, db, false)
				version := scheduleProfileVersion(t, ctx, db, f.schedule)
				writer := epProfileWriter(t, ctx, db)
				run := func() error {
					if mode == "store_insert" {
						return app.ScheduleStore.SetTemporaryScheduleScoped(ctx, writer, f.schedule, schedule.TemporarySchedule{Start: f.now.Add(2 * time.Hour), End: f.now.Add(3 * time.Hour), Shifts: []schedule.FixedShift{{Start: f.now.Add(2 * time.Hour), End: f.now.Add(3 * time.Hour), UserID: f.user.String()}}}, &f.org)
					}
					_, err := writer.ExecContext(ctx, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb)`, f.schedule, scheduleProfileJSON(f))
					return err
				}
				if first == "writer" {
					require.NoError(t, run())
					tx := nrBegin(t, ctx, db)
					_, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
					tx = nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
					if mode == "raw_insert" {
						enforceCode(t, err, ds.DeletionDependencyChanged)
					} else {
						enforceCode(t, err, ds.DeletionUnavailable)
					} // ordinary Store can persist a null sibling array; frozen raw Collector fails closed
					require.NoError(t, tx.Rollback())
				} else {
					tx := nrBegin(t, ctx, db)
					bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
					done := serviceProfileWait(t, ctx, db, writer, run)
					receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
					require.NoError(t, err)
					require.Len(t, receipts, 1)
					require.NoError(t, tx.Commit())
					require.Error(t, <-done)
					require.NoError(t, writer.Rollback())
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_data WHERE schedule_id=$1`, f.schedule))
				}
			})
		}
	}
	scheduleProfileNoSuccess(t, ctx, db) // low-level Store tests do not fabricate a controller success witness
}

func TestPostgresDeletionEnforcementScheduleEnvelopeWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	for _, mode := range []string{"rewrite", "reparent", "delete"} {
		t.Run(mode, func(t *testing.T) {
			f := newScheduleProfileFixture(t, ctx, db, false)
			scheduleProfileData(t, ctx, db, f, scheduleProfileJSON(f))
			version := scheduleProfileVersion(t, ctx, db, f.schedule)
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &nrQueryBarrier{needle: "SELECT id::text,schedule_id::text,(octet_length", arrived: make(chan struct{}), resume: make(chan struct{})}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			app := enforcementApp(t, ctx, traced)
			done := make(chan error, 1)
			go func() {
				_, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: version, AcknowledgeImpacts: true})
				done <- err
			}()
			select {
			case <-barrier.arrived:
			case err := <-done:
				t.Fatalf("envelope barrier not reached: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch mode {
			case "rewrite":
				enforcementExec(t, ctx, db, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules}','[]') WHERE schedule_id=$1`, f.schedule)
			case "reparent":
				enforcementExec(t, ctx, db, `UPDATE schedule_data SET schedule_id=$2 WHERE schedule_id=$1`, f.schedule, f.otherSchedule)
			case "delete":
				enforcementExec(t, ctx, db, `DELETE FROM schedule_data WHERE schedule_id=$1`, f.schedule)
			}
			close(barrier.resume)
			enforceCode(t, <-done, ds.DeletionDependencyChanged)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
		})
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleManagers(t *testing.T) {
	// Use the actual exported Engine/Cleanup entry points and their transactions,
	// not just a SQL equivalent. Tracing supplies deterministic post-lock barriers.
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	var cfg config.Config
	cfg.Maintenance.ScheduleCleanupDays = 30
	ctx = cfg.Context(ctx)
	for _, kind := range []string{"engine", "engine_notification_migration", "cleanup"} {
		for _, first := range []string{"writer", "delete"} {
			t.Run(kind+"_"+first, func(t *testing.T) {
				f := newScheduleProfileFixture(t, ctx, db, false)
				// Ended raw data produces an actual cleanup/rewrite, without history.
				raw := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}}`, f.now.Add(-3*time.Hour).Format(time.RFC3339Nano), f.now.Add(-2*time.Hour).Format(time.RFC3339Nano), f.now.Add(-3*time.Hour).Format(time.RFC3339Nano), f.now.Add(-2*time.Hour).Format(time.RFC3339Nano), f.user)
				scheduleProfileData(t, ctx, db, f, raw)
				if kind == "engine_notification_migration" {
					oldChannel, newChannel := uuid.New(), uuid.New()
					for _, id := range []uuid.UUID{oldChannel, newChannel} {
						enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, id)
					}
					enforcementExec(t, ctx, db, `INSERT INTO notification_channel_duplicates(old_id,new_id,old_created_at) VALUES($1,$2,now())`, oldChannel, newChannel)
					enforcementExec(t, ctx, db, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,OnCallNotificationRules}',jsonb_build_array(jsonb_build_object('ID',$2::text,'ChannelID',$3::uuid))) WHERE schedule_id=$1`, f.schedule, f.schedule.String()+":0", oldChannel)
				}
				conf, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				needle := "FROM\n    schedule_data\nWHERE"
				if kind == "engine_notification_migration" {
					needle = "jsonb_set(data, '{V1,OnCallNotificationRules}'"
				}
				barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: needle, arrived: make(chan struct{}), resume: make(chan struct{})}}
				if first == "writer" {
					conf.Tracer = barrier
				}
				traced := sql.OpenDB(stdlib.GetConnector(*conf))
				defer traced.Close()
				manager, err := schedulemanager.NewDB(ctx, traced)
				require.NoError(t, err)
				cleanup, err := cleanupmanager.NewDB(ctx, traced, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
				require.NoError(t, err)
				run := func() error {
					if kind == "cleanup" {
						return cleanup.CleanupScheduleData(ctx, &river.Job[cleanupmanager.SchedDataArgs]{Args: cleanupmanager.SchedDataArgs{ScheduleID: f.schedule}})
					}
					return manager.UpdateAll(ctx)
				}
				// Force the real migration stage when requested; ordinary Engine tests
				// start after migration so their barrier is the DataForUpdate row lock.
				state := `{"HasMigratedScheduleData":true}`
				if kind == "engine_notification_migration" {
					state = `{}`
				}
				enforcementExec(t, ctx, db, `UPDATE engine_processing_versions SET state=$1::jsonb WHERE type_id='schedule'`, state)
				version := scheduleProfileVersion(t, ctx, db, f.schedule)
				if first == "writer" {
					done := make(chan error, 1)
					go func() { done <- run() }()
					select {
					case <-barrier.arrived:
					case err := <-done:
						t.Fatalf("manager did not reach row barrier: %v", err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					tx := nrBegin(t, ctx, db)
					_, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					close(barrier.resume)
					require.NoError(t, <-done)
				} else {
					tx := nrBegin(t, ctx, db)
					bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
					done := make(chan error, 1)
					go func() { done <- run() }()
					// Observe a real PostgreSQL wait by the Manager, without timing sleeps.
					for enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%schedule_data%'`) == 0 {
						select {
						case err := <-done:
							t.Fatalf("manager did not block: %v", err)
						default:
						}
						require.NoError(t, ctx.Err())
					}
					app := enforcementApp(t, ctx, db)
					receipts, err := app.ScheduleStore.DeleteManyForAuditTx(bound, tx, []string{f.schedule.String()}, nil)
					require.NoError(t, err)
					require.Len(t, receipts, 1)
					require.NoError(t, tx.Commit())
					// Repeatable-read Engine can safely abort after a concurrent deletion;
					// Cleanup's READ COMMITTED may instead observe a missing envelope.
					err = <-done
					if err != nil {
						require.Contains(t, err.Error(), "could not serialize access")
					}
				}
			})
		}
	}
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleRetainedRuntime(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newScheduleProfileFixture(t, ctx, db, false)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, f.schedule, f.rotation)
	var participant uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM rotation_participants WHERE rotation_id=$1`, f.rotation).Scan(&participant))
	enforcementExec(t, ctx, db, `INSERT INTO rotation_state(rotation_id,rotation_participant_id,shift_start) VALUES($1,$2,now()) ON CONFLICT(rotation_id) DO UPDATE SET shift_start=excluded.shift_start`, f.rotation, participant)
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
	writer := epProfileWriter(t, ctx, db)
	_, err := writer.ExecContext(ctx, `UPDATE rotation_state SET shift_start=shift_start+interval '1 second' WHERE rotation_id=$1`, f.rotation)
	require.NoError(t, err)
	ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, writer.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1 AND rotation_participant_id=$2`, f.rotation, participant))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE id=$1`, participant))
	// Actual Rotation participant writes update the shared Rotation parent.
	// A local conflict is allowed; no unrelated Rotation is fenced.
	g := newScheduleProfileFixture(t, ctx, db, false)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, g.schedule, g.rotation)
	version := scheduleProfileVersion(t, ctx, db, g.schedule)
	for _, first := range []string{"writer", "delete"} {
		writer := epProfileWriter(t, ctx, db)
		run := func() error {
			_, err := writer.ExecContext(ctx, `INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES($1,$2,$3)`, uuid.New(), g.rotation, g.actor)
			return err
		}
		if first == "writer" {
			require.NoError(t, run())
			tx := nrBegin(t, ctx, db)
			_, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(g.schedule), version, true, authorizeDeletionFixture(scheduleProfileRoot(g.schedule)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Rollback())
		} else {
			tx := nrBegin(t, ctx, db)
			_ = scheduleProfileEnforce(t, ctx, tx, g.schedule, version)
			done := serviceProfileWait(t, ctx, db, writer, run)
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
			require.NoError(t, writer.Rollback())
		}
	}
	// Ordinary read-only generated queries still resolve retained targets.
	_, err = gadb.New(db).SchedMgrRules(ctx)
	require.NoError(t, err)
}

func TestPostgresDeletionEnforcementScheduleJSONPeriods(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, shift := range []time.Duration{-5 * time.Hour, -150 * time.Minute, 0} {
		f := newScheduleProfileFixture(t, ctx, db, false)
		f.now = f.now.Add(shift)
		scheduleProfileData(t, ctx, db, f, scheduleProfileJSON(f))
		confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
		ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT jsonb_array_length(effects) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.schedule))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	}
}

func TestPostgresDeletionEnforcementScheduleOnCallRules(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newScheduleProfileFixture(t, ctx, db, true)
	scheduleProfileData(t, ctx, db, f, scheduleProfileJSON(f))
	for _, id := range []uuid.UUID{f.channel, uuid.New()} {
		enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text)`, id)
		old := scheduleProfileVersion(t, ctx, db, f.schedule)
		require.NoError(t, app.ScheduleStore.SetOnCallNotificationRulesScoped(ctx, nil, f.schedule, []schedule.OnCallNotificationRule{{ChannelID: id}}, &f.org))
		tx := nrBegin(t, ctx, db)
		_, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), old, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
		enforceCode(t, err, ds.DeletionDependencyChanged)
		require.NoError(t, tx.Rollback())
	}
	old := scheduleProfileVersion(t, ctx, db, f.schedule)
	require.NoError(t, app.ScheduleStore.SetOnCallNotificationRulesScoped(ctx, nil, f.schedule, []schedule.OnCallNotificationRule{}, &f.org))
	tx := nrBegin(t, ctx, db)
	_, err := collector.Enforce(ctx, tx, scheduleProfileSelectors(f.schedule), old, true, authorizeDeletionFixture(scheduleProfileRoot(f.schedule)))
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.NoError(t, tx.Rollback())
	// A timed rule has the same ownership. Its exact safe configuration is
	// captured by frozen B2; the channel is retained.
	enforcementExec(t, ctx, db, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,OnCallNotificationRules}',jsonb_build_array(jsonb_build_object('ID',$2::text,'ChannelID',$3::uuid,'Time','09:00:00','WeekdayFilter','1111111'))) WHERE schedule_id=$1`, f.schedule, f.schedule.String()+":0", f.channel)
	confirm := enforcementPreview(t, ctx, app, scheduleProfilePreviewInput(f.schedule)...)
	ok, err := app.Mutation().DeleteAll(ctx, scheduleProfileInput(f.schedule), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events e CROSS JOIN LATERAL jsonb_array_elements(e.effects) f WHERE root_id=$1 AND f->>'resource_type'='on_call_notification_rule' AND f#>>'{on_call_rule,time}'='09:00:00' AND f#>>'{on_call_rule,weekdays}'='1111111'`, f.schedule))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM notification_channels WHERE id=$1`, f.channel))
}

func TestPostgresDeletionEnforcementScheduleWitnessTamper(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ScheduleProfileTest")
	f := newScheduleProfileFixture(t, ctx, db, true)
	version := scheduleProfileVersion(t, ctx, db, f.schedule)
	for _, change := range []string{`nonce=gen_random_uuid()`, `profile='service-only-v1'`, `xid='foreign'`, `raw_hash=decode('00','hex')`, `effective_hash=decode('00','hex')`} {
		tx := nrBegin(t, ctx, db)
		bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
		_, err := tx.ExecContext(ctx, `SAVEPOINT original_witness`)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `UPDATE pg_temp.d09_nr_deletion_witness SET `+change+` WHERE phase='certified'`)
		require.NoError(t, err)
		_, err = guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		_, err = tx.ExecContext(ctx, `ROLLBACK TO original_witness`)
		require.NoError(t, err)
		_, err = guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	// A Schedule carrier never becomes a child-root/retained-root capability.
	app := enforcementApp(t, ctx, db)
	tx := nrBegin(t, ctx, db)
	bound := scheduleProfileEnforce(t, ctx, tx, f.schedule, version)
	for _, call := range []func() error{func() error { return app.OverrideStore.DeleteUserOverrideTx(bound, tx, f.override.String()) }, func() error { return app.UserStore.DeleteManyTx(bound, tx, []string{f.user.String()}) }, func() error { return app.RotationStore.DeleteManyTx(bound, tx, []string{f.rotation.String()}, nil) }} {
		enforceCode(t, call(), ds.DeletionUnavailable)
	}
	require.NoError(t, tx.Rollback())
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementScheduleScope(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "ScheduleProfileTest")
	app := enforcementApp(t, sys, db)
	f, foreign := newScheduleProfileFixture(t, ctx, db, true), newScheduleProfileFixture(t, ctx, db, false)
	human := previewAdmit(t, ctx, db, f.actor)
	enforcementExec(t, ctx, db, `UPDATE schedule_rules SET tgt_user_id=$2 WHERE id=$1`, f.rule, foreign.user)
	_, err := app.Mutation().DeleteAll(human, scheduleProfileInput(f.schedule), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, foreign.user)
	_, err = app.Mutation().DeleteAll(sys, scheduleProfileInput(f.schedule), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	// Reparented/retargeted roots and children stay in their real organization.
	enforcementExec(t, ctx, db, `UPDATE schedule_rules SET tgt_user_id=$2 WHERE id=$1`, f.rule, f.user)
	confirm := enforcementPreview(t, human, app, scheduleProfilePreviewInput(f.schedule)...)
	enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, f.schedule, foreign.org)
	_, err = app.Mutation().DeleteAll(human, scheduleProfileInput(f.schedule), confirm)
	enforceCode(t, err, ds.DeletionUnavailable)
	// The frozen dependency parser must retain both add and remove identities.
	enforcementExec(t, ctx, db, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, f.schedule, f.org)
	facts, err := collectDeletion(t, sys, db, scheduleProfileRoot(f.schedule), collector.Limits{})
	require.NoError(t, err)
	for _, rel := range []ds.RelationshipKind{ds.RelationshipOverrideAddUser, ds.RelationshipOverrideRemoveUser} {
		require.True(t, slices.ContainsFunc(facts.Collection.Dependencies, func(d ds.Dependency) bool { return d.Relationship == rel }))
	}
	scheduleProfileNoSuccess(t, sys, db)
}
