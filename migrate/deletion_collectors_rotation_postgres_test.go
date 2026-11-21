package migrate

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
)

func TestPostgresDeletionCollectorsRotationStateBoundary(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionCollectorsTest")
	rotation := uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, rotation, f.org)
	require.NoError(t, err)
	root := ds.Resource{Kind: ds.ResourceRotation, ID: rotation.String()}
	result, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	require.Empty(t, result.Collection.Dependencies)
	require.True(t, deletionPlan(t, root, result).CanProceed())
	// Use the normal lifecycle: State and Participant must be collected together.
	app := enforcementApp(t, ctx, db)
	require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, rotation.String(), []string{f.user.String()}))
	result, err = collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	require.Equal(t, ds.DependenciesComplete, result.Collection.Completeness)
	plan := deletionPlan(t, root, result)
	require.True(t, plan.CanProceed())
	require.Len(t, plan.Changes(), 3)
	for _, change := range plan.Changes() {
		require.NotEqual(t, ds.ResourceUser, change.Resource.Kind)
	}
	// Both FKs can be valid while a state row names another Rotation's
	// Participant. Do not mark its retained outgoing reference complete.
	other := uuid.New()
	_, err = db.ExecContext(ctx, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, other, f.org)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO rotation_state(rotation_id,rotation_participant_id,shift_start,position) VALUES($1,$2,$3,0)`, other, f.participant, f.now)
	require.NoError(t, err)
	result, err = collectDeletion(t, ctx, db, ds.Resource{Kind: ds.ResourceRotation, ID: other.String()}, collector.Limits{})
	require.Error(t, err)
	require.Equal(t, ds.DependenciesIncomplete, result.Collection.Completeness)
}
