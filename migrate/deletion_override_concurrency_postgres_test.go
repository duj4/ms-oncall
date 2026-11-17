package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/override"
	"github.com/target/goalert/permission"
)

func overrideWait(t *testing.T, ctx context.Context, db *sql.DB, pid int, done <-chan error) {
	t.Helper()
	for {
		var blocked bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked))
		if blocked {
			return
		}
		select {
		case err := <-done:
			require.FailNow(t, "writer did not block", "%v", err)
		default:
		}
		require.NoError(t, ctx.Err())
	}
}

func TestPostgresDeletionEnforcementOverrideWriters(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	kinds := []string{"create", "update", "foreign_override", "find_for_update", "find_unscoped", "unscoped_reparent", "delete", "reparent", "add_user", "remove_user", "start", "end", "ended_to_future", "active_to_ended", "schedule_delete", "schedule_scope", "user_role", "assignment", "assignment_scope", "remove_assignment_scope", "organization", "normal_organization", "cleanup"}
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range kinds {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := overrideProfileFixture(t, ctx, db)
				other := overrideProfileFixture(t, ctx, db)
				if kind == "cleanup" {
					enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`, f.override, f.now.Add(-49*time.Hour), f.now.Add(-48*time.Hour))
				}
				if kind == "active_to_ended" {
					enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`, f.override, f.now.Add(-time.Hour), f.now.Add(time.Hour))
				}
				store, err := override.NewStore(ctx, db)
				require.NoError(t, err)
				writer := epProfileWriter(t, ctx, db)
				defer func() { _ = writer.Rollback() }()
				var pid int
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				run := func() error {
					var q string
					args := []any{f.override}
					switch kind {
					case "create":
						_, err := store.CreateUserOverrideTxScoped(ctx, writer, &override.UserOverride{Target: assignment.ScheduleTarget(f.schedule.String()), AddUserID: f.user.String(), Start: f.now.Add(4 * time.Hour), End: f.now.Add(5 * time.Hour)}, &f.org)
						return err
					case "update":
						return store.UpdateUserOverrideTxScoped(ctx, writer, &override.UserOverride{ID: f.override.String(), Target: assignment.ScheduleTarget(f.schedule.String()), AddUserID: f.user.String(), RemoveUserID: f.actor.String(), Start: f.now.Add(-4 * time.Hour), End: f.now.Add(2 * time.Hour)}, &f.org)
					case "foreign_override":
						return store.UpdateUserOverrideTxScoped(ctx, writer, &override.UserOverride{ID: other.override.String(), Target: assignment.ScheduleTarget(other.schedule.String()), AddUserID: other.user.String(), RemoveUserID: other.actor.String(), Start: other.now.Add(time.Hour), End: other.now.Add(2 * time.Hour)}, &other.org)
					case "find_for_update":
						_, err := store.FindOneUserOverrideTxScoped(ctx, writer, f.override.String(), true, &f.org)
						return err
					case "find_unscoped":
						_, err := store.FindOneUserOverrideTx(ctx, writer, f.override.String(), false)
						return err
					case "unscoped_reparent":
						return store.UpdateUserOverrideTx(ctx, writer, &override.UserOverride{ID: f.override.String(), Target: assignment.ScheduleTarget(f.otherSchedule.String()), AddUserID: f.user.String(), RemoveUserID: f.actor.String(), Start: f.now.Add(time.Hour), End: f.now.Add(2 * time.Hour)})
					case "delete":
						q = `DELETE FROM user_overrides WHERE id=$1`
					case "reparent":
						q = `UPDATE user_overrides SET tgt_schedule_id=$2 WHERE id=$1`
						args = append(args, f.otherSchedule)
					case "add_user":
						q = `UPDATE user_overrides SET add_user_id=NULL WHERE id=$1`
					case "remove_user":
						q = `UPDATE user_overrides SET remove_user_id=NULL WHERE id=$1`
					case "start":
						q = `UPDATE user_overrides SET start_time=start_time-'1 minute'::interval WHERE id=$1`
					case "end":
						q = `UPDATE user_overrides SET end_time=end_time+'1 minute'::interval WHERE id=$1`
					case "ended_to_future":
						q = `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`
						args = append(args, f.now.Add(time.Hour), f.now.Add(2*time.Hour))
					case "active_to_ended":
						q = `UPDATE user_overrides SET end_time=$2 WHERE id=$1`
						args = append(args, f.now.Add(-time.Minute))
					case "schedule_delete":
						q = `DELETE FROM schedules WHERE id=$1`
						args = []any{f.schedule}
					case "schedule_scope":
						q = `UPDATE schedules SET organization_id=$2 WHERE id=$1`
						args = []any{f.schedule, other.org}
					case "user_role":
						q = `UPDATE users SET role='unknown' WHERE id=$1`
						args = []any{f.user}
					case "assignment":
						q = `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`
						args = []any{f.user}
					case "assignment_scope", "remove_assignment_scope":
						q = `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`
						user := f.user
						if kind == "remove_assignment_scope" {
							user = f.actor
						}
						args = []any{user, other.org}
					case "organization":
						q = `UPDATE organizations SET display_name=display_name WHERE id=$1`
						args = []any{f.org}
					case "normal_organization":
						q = `UPDATE normal_organizations SET organization_id=organization_id WHERE organization_id=$1`
						args = []any{f.org}
					case "cleanup":
						_, err := gadb.New(writer).CleanupMgrDeleteOldOverrides(ctx, 1)
						return err
					}
					_, err := writer.ExecContext(ctx, q, args...)
					return err
				}
				app := enforcementApp(t, ctx, db)
				confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
				if first == "writer" {
					require.NoError(t, run())
					_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
					enforceCode(t, err, ds.DeletionUnavailable)
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.override))
					require.NoError(t, writer.Commit())
					_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
					switch kind {
					case "create", "foreign_override", "find_for_update", "find_unscoped", "assignment", "organization", "normal_organization":
						require.NoError(t, err)
					case "schedule_scope", "user_role", "assignment_scope", "remove_assignment_scope":
						enforceCode(t, err, ds.DeletionUnavailable)
					default:
						enforceCode(t, err, ds.DeletionDependencyChanged)
					}
					if kind != "schedule_scope" && kind != "user_role" && kind != "assignment_scope" && kind != "remove_assignment_scope" && kind != "delete" && kind != "schedule_delete" && kind != "cleanup" && kind != "create" && kind != "foreign_override" && kind != "find_for_update" && kind != "find_unscoped" && kind != "assignment" && kind != "organization" && kind != "normal_organization" {
						fresh := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
						_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), fresh)
						require.NoError(t, err)
					}
				} else {
					traced, barrier := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
					app = enforcementApp(t, ctx, traced)
					deleted := make(chan error, 1)
					go func() {
						_, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
						deleted <- err
					}()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					done := make(chan error, 1)
					go func() { done <- run() }()
					overrideWait(t, ctx, db, pid, done)
					close(barrier.resume)
					require.NoError(t, <-deleted)
					writerErr := <-done
					if kind == "update" {
						require.ErrorContains(t, writerErr, "user override not found")
						require.NoError(t, writer.Rollback())
					} else {
						require.NoError(t, writerErr)
						require.NoError(t, writer.Commit())
					}
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.override))
				}
			})
		}
	}
}

func TestPostgresDeletionEnforcementOverrideInvalidAndMixed(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"foreign_add", "foreign_remove", "missing_assignment", "unknown_user", "invalid_time", "infinite_time", "equal_users", "missing_schedule", "missing_user"} {
		t.Run(kind, func(t *testing.T) {
			f, other := overrideProfileFixture(t, ctx, db), overrideProfileFixture(t, ctx, db)
			tx := nrBegin(t, ctx, db)
			var q string
			args := []any{f.override}
			switch kind {
			case "foreign_add":
				q = `UPDATE user_overrides SET add_user_id=$2 WHERE id=$1`
				args = append(args, other.user)
			case "foreign_remove":
				q = `UPDATE user_overrides SET remove_user_id=$2 WHERE id=$1`
				args = append(args, other.user)
			case "missing_assignment":
				q = `DELETE FROM user_organization_assignments WHERE user_id=$1`
				args = []any{f.user}
			case "unknown_user":
				q = `UPDATE users SET role='unknown' WHERE id=$1`
				args = []any{f.user}
			case "invalid_time":
				q = `UPDATE user_overrides SET start_time=end_time WHERE id=$1`
			case "infinite_time":
				q = `UPDATE user_overrides SET end_time='infinity' WHERE id=$1`
			case "equal_users":
				q = `UPDATE user_overrides SET remove_user_id=add_user_id WHERE id=$1`
			case "missing_schedule", "missing_user":
				// Simulate pre-existing legacy corruption only in this rolled-back test tx.
				_, err := tx.ExecContext(ctx, `SET LOCAL session_replication_role='replica'`)
				require.NoError(t, err)
				if kind == "missing_schedule" {
					q = `UPDATE user_overrides SET tgt_schedule_id=$2 WHERE id=$1`
				} else {
					q = `UPDATE user_overrides SET add_user_id=$2 WHERE id=$1`
				}
				args = append(args, uuid.New())
			}
			_, err := tx.ExecContext(ctx, q, args...)
			if err != nil { // Existing CHECK/trigger rejection is stronger than admission.
				require.NoError(t, tx.Rollback())
				return
			}
			_, err = collector.Enforce(ctx, tx, overrideProfileSelectors(f.override), "", true, authorizeDeletionFixture(overrideProfileRoot(f.override)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
		})
	}
	f := overrideProfileFixture(t, ctx, db)
	for _, typ := range []assignment.TargetType{assignment.TargetTypeSchedule, assignment.TargetTypeUser, assignment.TargetTypeRotation, assignment.TargetTypeService, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule} {
		raw := append(overrideProfileInput(f.override), assignment.RawTarget{Type: typ, ID: uuid.NewString()})
		_, err := app.Mutation().DeleteAll(ctx, raw, nil)
		require.Error(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
	}
	require.Contains(t, enforcementHTTP(t, ctx, app, overrideProfileInput(f.override), nil, true), `"deleteAll":true`)
	// Ended roots need no warning confirmation on the original GraphQL API.
	overrideProfileRetained(t, ctx, db, f)
}

func TestPostgresDeletionEnforcementOverrideWitnessTamper(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	f := overrideProfileFixture(t, ctx, db)
	version := overrideProfileVersion(t, ctx, db, f.override)
	for _, change := range []string{`nonce=gen_random_uuid()`, `profile='schedule-only-v1'`, `xid='foreign'`, `raw_hash=decode('00','hex')`, `effective_hash=decode('00','hex')`} {
		tx := nrBegin(t, ctx, db)
		bound := overrideProfileEnforce(t, ctx, tx, f.override, version)
		_, err := tx.ExecContext(ctx, `SAVEPOINT original_witness`)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `UPDATE pg_temp.d09_nr_deletion_witness SET `+change+` WHERE phase='certified'`)
		require.NoError(t, err)
		_, err = guard.ConsumeUserOverride(bound, tx, []string{f.override.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		_, err = tx.ExecContext(ctx, `ROLLBACK TO original_witness`)
		require.NoError(t, err)
		_, err = guard.ConsumeUserOverride(bound, tx, []string{f.override.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	app := enforcementApp(t, ctx, db)
	tx := nrBegin(t, ctx, db)
	bound := overrideProfileEnforce(t, ctx, tx, f.override, version)
	for _, consume := range []func(context.Context, *sql.Tx, []string) ([]string, error){guard.ConsumeNR, guard.ConsumeCM, guard.ConsumeService, guard.ConsumeEP, guard.ConsumeSchedule, guard.ConsumeRotation} {
		_, err := consume(bound, tx, []string{f.override.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	require.NoError(t, tx.Rollback())
	// A Schedule capability for an owned CASCADE cannot be used as an explicit root.
	tx = nrBegin(t, ctx, db)
	v := scheduleProfileVersion(t, ctx, db, f.schedule)
	parent := scheduleProfileEnforce(t, ctx, tx, f.schedule, v)
	_, err := app.OverrideStore.DeleteUserOverrideForAuditTx(parent, tx, []string{f.override.String()}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	overrideProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementOverrideObservation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	for _, boundary := range []string{"start", "end"} {
		t.Run(boundary, func(t *testing.T) {
			f := overrideProfileFixture(t, ctx, db)
			// The database defines the interval. Waiting observes SQL clock_timestamp,
			// never sleeps or reads a Go wall clock to guess transaction ordering.
			if boundary == "start" {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=clock_timestamp()+'300 milliseconds'::interval,end_time=clock_timestamp()+'1 hour'::interval WHERE id=$1`, f.override)
			} else {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=clock_timestamp()-'1 hour'::interval,end_time=clock_timestamp()+'300 milliseconds'::interval WHERE id=$1`, f.override)
			}
			old := overrideProfileVersion(t, ctx, db, f.override)
			tx := nrBegin(t, ctx, db)
			checked, _, err := guard.StabilizeUserOverride(ctx, tx, overrideProfileSelectors(f.override))
			require.NoError(t, err)
			root := overrideProfileRoot(f.override)
			first, err := collector.Collect(checked, tx, root, collector.Recheck, collector.Limits{}, authorizeDeletionFixture(root))
			require.NoError(t, err)
			for {
				var reached bool
				q := fmt.Sprintf(`SELECT clock_timestamp()>%s_time FROM user_overrides WHERE id=$1`, boundary)
				require.NoError(t, db.QueryRowContext(ctx, q, f.override).Scan(&reached))
				if reached {
					break
				}
				require.NoError(t, ctx.Err())
			}
			second, err := collector.Collect(checked, tx, root, collector.Recheck, collector.Limits{}, authorizeDeletionFixture(root))
			require.NoError(t, err)
			require.Equal(t, first.ObservedAt, second.ObservedAt)
			require.Equal(t, deletionPlan(t, root, first).ImpactVersion(), deletionPlan(t, root, second).ImpactVersion())
			// Domain exact [start,end) edges against this actual DB observation.
			observed := first.ObservedAt
			state, err := ds.ClassifyPeriod(observed, observed.Add(time.Hour), observed)
			require.NoError(t, err)
			require.Equal(t, ds.PeriodActive, state)
			state, err = ds.ClassifyPeriod(observed.Add(-time.Hour), observed, observed)
			require.NoError(t, err)
			require.Equal(t, ds.PeriodEnded, state)
			require.NoError(t, tx.Rollback())
			fresh := overrideProfileVersion(t, ctx, db, f.override)
			require.NotEqual(t, old, fresh)
			app := enforcementApp(t, ctx, db)
			_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: old, AcknowledgeImpacts: true})
			enforceCode(t, err, ds.DeletionDependencyChanged)
		})
	}
}

func TestPostgresDeletionEnforcementOverrideControllerMissingInsert(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	f := overrideProfileFixture(t, ctx, db)
	missing := uuid.New()
	traced, b := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
	app := enforcementApp(t, ctx, traced)
	confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
	deleted := make(chan error, 1)
	go func() {
		_, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override, missing, uuid.Nil), confirm)
		deleted <- err
	}()
	select {
	case <-b.arrived:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	writer := epProfileWriter(t, ctx, db)
	done := nrWaiter(t, ctx, db, writer, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5)`, missing, f.schedule, f.user, f.now.Add(4*time.Hour), f.now.Add(5*time.Hour))
	close(b.resume)
	require.NoError(t, <-deleted)
	require.NoError(t, <-done)
	require.NoError(t, writer.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, missing))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE outcome='committed' AND root_id=$1`, f.override))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE outcome='committed' AND root_id=$1`, missing))
	overrideProfileRetained(t, ctx, db, f)
}

func TestPostgresDeletionEnforcementOverrideBudgetAndCancellation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	f := overrideProfileFixture(t, ctx, db)
	for _, dimension := range []string{"rows", "queries"} {
		limits := collector.DefaultLimits()
		if dimension == "rows" {
			limits.MaxRows = 1
		} else {
			limits.MaxQueries = 1
		}
		_, err := collectDeletion(t, ctx, db, overrideProfileRoot(f.override), limits)
		enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	}
	for _, after := range []bool{false, true} {
		child, cancel := context.WithCancel(ctx)
		tx := nrBegin(t, ctx, db)
		store, err := override.NewStore(ctx, db)
		require.NoError(t, err)
		if after {
			bound := overrideProfileEnforce(t, child, tx, f.override, overrideProfileVersion(t, ctx, db, f.override))
			cancel()
			_, err = store.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String()}, nil)
			require.Error(t, err)
		} else {
			cancel()
			_, err = collector.Enforce(child, tx, overrideProfileSelectors(f.override), "", true, authorizeDeletionFixture(overrideProfileRoot(f.override)))
			require.Error(t, err)
		}
		require.NoError(t, tx.Rollback())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
	}
	overrideProfileNoSuccess(t, ctx, db)
}
