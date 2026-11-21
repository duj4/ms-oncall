package migrate

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
)

func rotationUpdateBlocked(t *testing.T, ctx context.Context, db *sql.DB, blocker uint32, done <-chan error) {
	t.Helper()
	for {
		var blocked bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&blocked))
		if blocked {
			return
		}
		select {
		case err := <-done:
			require.FailNow(t, "operation did not reach real lock wait", "%v", err)
		default:
		}
		require.NoError(t, ctx.Err())
	}
}

func TestPostgresRotationUpdateSafetyConcurrency(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	for _, mode := range []string{"same_update", "rotation_delete", "participant", "state", "user", "user_scope", "schedule", "ep", "incoming_fk", "json"} {
		t.Run(mode, func(t *testing.T) {
			base, cancel := context.WithTimeout(base, 12*time.Second)
			defer cancel()
			ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
			app := updateNativeApp(t, ctx, db)
			f := rotationUpdateFixture(t, ctx, db)
			// Obtain an actually executable Root Delete confirmation, not one
			// already refused due to surviving Schedule/EP references.
			if mode == "rotation_delete" {
				enforcementExec(t, ctx, db, `DELETE FROM schedule_rules WHERE tgt_rotation_id=$1`, f.root)
				enforcementExec(t, ctx, db, `DELETE FROM escalation_policy_actions WHERE rotation_id=$1`, f.root)
			}
			input := rotationUpdateInput(f, 2)
			p, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			rootConfirmation := input.Confirmation
			if mode == "rotation_delete" {
				rootConfirmation = enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
			}
			barrier := &updateNativeBarrier{prefix: "delete from rotation_participants", ready: make(chan uint32, 1), release: make(chan struct{})}
			cfg, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			cfg.Tracer = barrier
			ownerDB := stdlib.OpenDB(*cfg)
			t.Cleanup(func() { require.NoError(t, ownerDB.Close()) })
			owner := updateNativeApp(t, ctx, ownerDB)
			var once sync.Once
			release := func() { once.Do(func() { close(barrier.release) }) }
			t.Cleanup(release)
			done := make(chan error, 1)
			barrier.armed.Store(true)
			go func() { _, err := owner.Mutation().UpdateRotation(ctx, input); done <- err }()
			var ownerPID uint32
			select {
			case ownerPID = <-barrier.ready:
			case err := <-done:
				require.FailNow(t, "did not reach DML after enforcement", "%v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch mode {
			case "rotation_delete":
				_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), rootConfirmation)
				require.Error(t, err)
			case "json":
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				err = app.ScheduleStore.SetOnCallNotificationRules(ctx, writer, f.schedule, nil)
				require.NoError(t, err, "JSON has no Participant/Rotation references and safely commutes")
				require.NoError(t, writer.Commit())
			case "same_update":
				second := make(chan error, 1)
				go func() { _, err := app.Mutation().UpdateRotation(ctx, input); second <- err }()
				rotationUpdateBlocked(t, ctx, db, ownerPID, second)
				release()
				require.NoError(t, <-done)
				enforceCode(t, <-second, ds.DeletionDependencyChanged)
				return
			default:
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				q, id := `UPDATE rotation_participants SET user_id=user_id WHERE rotation_id=$1 AND position=0`, f.root
				switch mode {
				case "state":
					q = `UPDATE rotation_state SET shift_start=shift_start WHERE rotation_id=$1`
				case "user":
					q, id = `UPDATE users SET role=role WHERE id=$1`, f.user
				case "user_scope":
					q, id = `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`, f.user
				case "schedule":
					q = `UPDATE schedule_rules SET start_time=start_time WHERE tgt_rotation_id=$1`
				case "ep":
					q = `UPDATE escalation_policy_actions SET rotation_id=rotation_id WHERE rotation_id=$1`
				case "incoming_fk":
					q = `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) SELECT gen_random_uuid(),schedule_id,tgt_rotation_id FROM schedule_rules WHERE tgt_rotation_id=$1`
				}
				waiting := serviceProfileWait(t, ctx, db, writer, func() error { _, err := writer.ExecContext(ctx, q, id); return err })
				rotationUpdateBlocked(t, ctx, db, ownerPID, waiting)
				release()
				require.NoError(t, <-done)
				require.NoError(t, <-waiting)
				require.NoError(t, writer.Commit())
				return
			}
			release()
			require.NoError(t, <-done)
		})
	}
}

func TestPostgresRotationUpdateSafetyWriterFirstRecheck(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"participant", "dependency", "user"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			f := rotationUpdateFixture(t, ctx, db)
			input := rotationUpdateInput(f, 2)
			p, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			var pid uint32
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			q, id := `UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=2`, f.root
			if mode == "dependency" {
				q, id = `UPDATE schedule_rules SET start_time='03:00' WHERE tgt_rotation_id=$1 AND $2::uuid IS NOT NULL`, f.root
			}
			if mode == "user" {
				q, id = `UPDATE users SET role='admin' WHERE id=$1 AND $2::uuid IS NOT NULL`, f.user
			}
			_, err = writer.ExecContext(ctx, q, id, f.actor)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().UpdateRotation(ctx, input); done <- err }()
			if mode == "participant" {
				rotationUpdateBlocked(t, ctx, db, pid, done)
				require.NoError(t, writer.Commit())
				enforceCode(t, <-done, ds.DeletionDependencyChanged)
			} else {
				enforceCode(t, <-done, ds.DeletionUnavailable)
				require.NoError(t, writer.Commit())
			}
			require.Equal(t, 4, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.root))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed'`, f.root))
		})
	}
}
