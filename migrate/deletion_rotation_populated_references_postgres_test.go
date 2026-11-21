package migrate

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
)

// Full controller outcomes complement the Store-level writer matrix. Trace
// completed lock/certification SQL and observe pg_blocking_pids, never sleeps.
func TestPostgresDeletionEnforcementRotationPopulatedReferences(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"rule", "action"} {
			for _, change := range []string{"create", "to", "away", "remove"} {
				t.Run(first+"_"+kind+"_"+change, func(t *testing.T) {
					f := rotationPopulated(t, ctx, db, 2, 1)
					app := enforcementApp(t, ctx, db)
					id := uuid.New()
					table, target := "schedule_rules", "tgt_rotation_id"
					if kind == "action" {
						table, target = "escalation_policy_actions", "rotation_id"
						enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
					}
					insert := `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`
					parent := f.schedule
					if kind == "action" {
						insert = `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,rotation_id) VALUES($1,$2,$3)`
						parent = f.step
					}
					incoming := change == "away" || change == "remove"
					if change != "create" {
						dest := f.rotation
						if incoming {
							dest = f.root
						}
						enforcementExec(t, ctx, db, insert, id, parent, dest)
					}
					confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
					writer := epProfileWriter(t, ctx, db)
					run := func() error {
						var err error
						switch change {
						case "create":
							_, err = writer.ExecContext(ctx, insert, id, parent, f.root)
						case "to":
							_, err = writer.ExecContext(ctx, `UPDATE `+table+` SET `+target+`=$2 WHERE id=$1`, id, f.root)
						case "away":
							_, err = writer.ExecContext(ctx, `UPDATE `+table+` SET `+target+`=$2 WHERE id=$1`, id, f.rotation)
						case "remove":
							_, err = writer.ExecContext(ctx, `DELETE FROM `+table+` WHERE id=$1`, id)
						}
						return err
					}
					if first == "writer" {
						require.NoError(t, run())
						_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
						enforceCode(t, err, ds.DeletionUnavailable)
						require.NoError(t, writer.Commit())
					} else {
						traced, barrier := rotationPopulatedBarrier(t, ctx, uri)
						if incoming {
							barrier.needle = "VALUES($1,'locked'"
						}
						done := make(chan error, 1)
						go func() { _, err := traced.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm); done <- err }()
						select {
						case <-barrier.arrived:
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
						waiting := serviceProfileWait(t, ctx, db, writer, run)
						close(barrier.resume)
						if incoming {
							enforceCode(t, <-done, ds.DeletionBlocked)
							require.NoError(t, <-waiting)
							require.NoError(t, writer.Commit())
						} else {
							require.NoError(t, <-done)
							require.Error(t, <-waiting)
							require.NoError(t, writer.Rollback())
							require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
							require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root))
							return
						}
					}
					_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
					if incoming {
						enforceCode(t, err, ds.DeletionDependencyChanged)
						state, parts := rotationPopulatedBefore(t, ctx, db, f.root)
						fresh := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
						_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), fresh)
						require.NoError(t, err)
						rotationPopulatedCommitted(t, ctx, db, f, state, parts)
					} else {
						enforceCode(t, err, ds.DeletionBlocked)
						require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
						require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root))
					}
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
				})
			}
		}
	}
}
