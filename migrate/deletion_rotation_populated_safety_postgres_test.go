package migrate

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
)

func TestPostgresDeletionEnforcementRotationPopulatedInvalid(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"foreign_participant", "reverse_foreign_state", "missing_participant", "position", "missing_user", "missing_assignment", "foreign_user", "missing_state", "count", "legacy_version", "unknown_version", "infinite_shift", "state_identity", "participant_identity"} {
		t.Run(kind, func(t *testing.T) {
			f := rotationPopulated(t, ctx, db, 2, 1)
			other := rotationPopulated(t, ctx, db, 1, 0)
			confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
			switch kind {
			case "foreign_participant":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET rotation_participant_id=(SELECT id FROM rotation_participants WHERE rotation_id=$2 AND position=0) WHERE rotation_id=$1`, f.root, other.root)
			case "reverse_foreign_state":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET rotation_participant_id=(SELECT id FROM rotation_participants WHERE rotation_id=$1 AND position=0) WHERE rotation_id=$2`, f.root, other.root)
			case "missing_participant":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET rotation_participant_id=$2 WHERE rotation_id=$1`, f.root, uuid.New())
			case "position":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET position=0 WHERE rotation_id=$1`, f.root)
			case "missing_user":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=0`, f.root, uuid.New())
			case "missing_assignment":
				enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, f.user)
			case "foreign_user":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=0`, f.root, other.user)
			case "missing_state":
				corruptDeletionFixture(t, ctx, db, `DELETE FROM rotation_state WHERE rotation_id=$1`, f.root)
			case "count":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotations SET participant_count=99 WHERE id=$1`, f.root)
			case "legacy_version":
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET version=1 WHERE rotation_id=$1`, f.root)
			case "unknown_version":
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET version=3 WHERE rotation_id=$1`, f.root)
			case "infinite_shift":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET shift_start='infinity' WHERE rotation_id=$1`, f.root)
			case "state_identity":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_state SET id=-id WHERE rotation_id=$1`, f.root)
			case "participant_identity":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotation_participants SET id='00000000-0000-0000-0000-000000000000' WHERE rotation_id=$1 AND position=0`, f.root)
			}
			before := rotationStateContractInventory(t, ctx, db)
			facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(f.root), collector.Limits{})
			require.Error(t, err)
			require.Empty(t, facts.Collection.Dependencies)
			require.Empty(t, facts.Collection.Checked)
			_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.Equal(t, before, rotationStateContractInventory(t, ctx, db))
		})
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationPopulatedVersions(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	app := enforcementApp(t, ctx, db)
	f := rotationPopulated(t, ctx, db, 5, 2)
	parts, err := app.RotationStore.FindAllParticipants(ctx, f.root.String())
	require.NoError(t, err)
	for _, kind := range []string{"active", "shift", "user", "reorder", "add", "delete", "state_identity"} {
		t.Run(kind, func(t *testing.T) {
			old := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
			switch kind {
			case "active":
				require.NoError(t, app.RotationStore.SetActiveIndexTx(ctx, nil, f.root.String(), 4))
			case "shift":
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET shift_start=shift_start+interval '0.000001 second' WHERE rotation_id=$1`, f.root)
			case "user":
				require.NoError(t, app.RotationStore.UpdateParticipantUserIDTx(ctx, nil, parts[0].ID, f.actor.String()))
			case "reorder":
				tx := epProfileWriter(t, ctx, db)
				_, err = tx.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `SELECT move_rotation_position($1,3)`, parts[0].ID)
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
			case "add":
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), []string{f.user.String()}))
			case "delete":
				enforcementExec(t, ctx, db, `DELETE FROM rotation_participants WHERE id=$1`, parts[1].ID)
			case "state_identity":
				current, err := app.RotationStore.FindAllParticipants(ctx, f.root.String())
				require.NoError(t, err)
				ids := make([]string, len(current))
				for i, p := range current {
					ids[i] = p.ID
				}
				for _, id := range ids {
					enforcementExec(t, ctx, db, `DELETE FROM rotation_participants WHERE id=$1`, id)
				}
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), []string{f.user.String(), f.actor.String()}))
			}
			fresh := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
			require.NotEqual(t, old.ExpectedImpactVersion, fresh.ExpectedImpactVersion)
			_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), old)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
		})
	}
	rotationProfileNoSuccess(t, ctx, db)
	state, inventory := rotationPopulatedBefore(t, ctx, db, f.root)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	require.NoError(t, err)
	rotationPopulatedCommitted(t, ctx, db, f, state, inventory)
}

func TestPostgresDeletionEnforcementRotationPopulatedWriters(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"add", "delete", "user", "reorder", "active", "shift", "runtime", "update"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := rotationPopulated(t, ctx, db, 5, 2)
				app := enforcementApp(t, ctx, db)
				parts, err := app.RotationStore.FindAllParticipants(ctx, f.root.String())
				require.NoError(t, err)
				r, err := app.RotationStore.FindRotation(ctx, f.root.String(), nil)
				require.NoError(t, err)
				writer := epProfileWriter(t, ctx, db)
				run := func() error {
					switch kind {
					case "add":
						return app.RotationStore.AddRotationUsersTx(ctx, writer, f.root.String(), []string{f.user.String()})
					case "delete":
						_, err := writer.ExecContext(ctx, `DELETE FROM rotation_participants WHERE id=$1`, parts[0].ID)
						return err
					case "user":
						return app.RotationStore.UpdateParticipantUserIDTx(ctx, writer, parts[0].ID, f.actor.String())
					case "reorder":
						if _, err := writer.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`); err != nil {
							return err
						}
						_, err := writer.ExecContext(ctx, `SELECT move_rotation_position($1,4)`, parts[0].ID)
						return err
					case "active":
						return app.RotationStore.SetActiveIndexTx(ctx, writer, f.root.String(), 4)
					case "shift":
						_, err := writer.ExecContext(ctx, `UPDATE rotation_state SET shift_start=shift_start+interval '1 second' WHERE rotation_id=$1`, f.root)
						return err
					case "runtime":
						_, err := writer.ExecContext(ctx, `UPDATE rotation_state SET version=1 WHERE rotation_id=$1`, f.root)
						return err
					default:
						return app.RotationStore.UpdateRotationTx(ctx, writer, r, nil)
					}
				}
				confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
				if first == "writer" {
					require.NoError(t, run())
					_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, writer.Commit())
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root))
					if kind == "runtime" {
						_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
						enforceCode(t, err, ds.DeletionUnavailable)
						enforcementExec(t, ctx, db, `UPDATE rotation_state SET version=2 WHERE rotation_id=$1`, f.root)
					} else {
						_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
						enforceCode(t, err, ds.DeletionDependencyChanged)
					}
					state, inventory := rotationPopulatedBefore(t, ctx, db, f.root)
					confirm = enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
					_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
					require.NoError(t, err)
					rotationPopulatedCommitted(t, ctx, db, f, state, inventory)
				} else {
					state, inventory := rotationPopulatedBefore(t, ctx, db, f.root)
					traced, barrier := rotationPopulatedBarrier(t, ctx, uri)
					done := make(chan error, 1)
					go func() { _, err := traced.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm); done <- err }()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					waiting := serviceProfileWait(t, ctx, db, writer, run)
					close(barrier.resume)
					require.NoError(t, <-done)
					<-waiting // A late writer may fail its FK, or affect zero rows; neither changes the committed deletion.
					require.NoError(t, writer.Rollback())
					rotationPopulatedCommitted(t, ctx, db, f, state, inventory)
				}
			})
		}
	}
}

func TestPostgresDeletionEnforcementRotationPopulatedCancelTimeout(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	f := rotationPopulated(t, ctx, db, 2, 1)
	app := enforcementApp(t, ctx, db)
	before := rotationStateContractInventory(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := app.Mutation().DeleteAll(cancelled, rotationProfileInput(f.root), confirm)
	require.Error(t, err)
	holder := nrBegin(t, ctx, db)
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	conf.RuntimeParams["lock_timeout"] = "100ms"
	limited := stdlib.OpenDB(*conf)
	defer limited.Close()
	_, err = enforcementApp(t, ctx, limited).Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	require.Error(t, err)
	require.NoError(t, holder.Rollback())
	require.Equal(t, before, rotationStateContractInventory(t, ctx, db))
	rotationProfileNoSuccess(t, ctx, db)
	// Cancellation after certification releases all locks and rolls back without a successful event.
	traced, barrier := rotationPopulatedBarrier(t, ctx, uri)
	active, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := traced.Mutation().DeleteAll(active, rotationProfileInput(f.root), confirm)
		done <- err
	}()
	select {
	case <-barrier.arrived:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stop()
	close(barrier.resume)
	require.Error(t, <-done)
	require.Equal(t, before, rotationStateContractInventory(t, ctx, db))
	rotationProfileNoSuccess(t, ctx, db)
	state, parts := rotationPopulatedBefore(t, ctx, db, f.root)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	require.NoError(t, err)
	rotationPopulatedCommitted(t, ctx, db, f, state, parts)
}

func TestPostgresDeletionEnforcementRotationPopulatedBudget(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	f := rotationPopulated(t, ctx, db, 5, 2)
	for _, limit := range []collector.Limits{
		{PageSize: 1, MaxRows: 2, MaxQueries: 512, MaxJSONBytes: 1024, MaxFragments: 100, Timeout: time.Minute},
		{PageSize: 1, MaxRows: 100, MaxQueries: 2, MaxJSONBytes: 1024, MaxFragments: 100, Timeout: time.Minute},
		{PageSize: 1, MaxRows: 100, MaxQueries: 3, MaxJSONBytes: 1024, MaxFragments: 100, Timeout: time.Minute},
	} {
		facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(f.root), limit)
		enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
		require.Empty(t, facts.Collection.Dependencies)
		require.Empty(t, facts.Collection.Checked)
	}
	require.Equal(t, 5, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.root))
	rotationProfileNoSuccess(t, ctx, db)
}
