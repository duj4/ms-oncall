package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

func rotationPopulated(t *testing.T, ctx context.Context, db *sql.DB, count, active int) rotationProfileFixture {
	t.Helper()
	ctx = permission.SystemContext(ctx, "RotationPopulatedFixture")
	f := newRotationProfileFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	users := make([]string, count)
	for i := range users {
		users[i] = f.user.String()
		if i%2 == 1 {
			users[i] = f.actor.String()
		}
	}
	require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), users))
	require.NoError(t, app.RotationStore.SetActiveIndexTx(ctx, nil, f.root.String(), active))
	return f
}

func rotationPopulatedBefore(t *testing.T, ctx context.Context, db *sql.DB, root uuid.UUID) (sraudit.RotationState, map[uuid.UUID]sraudit.ParticipantDetail) {
	t.Helper()
	var state sraudit.RotationState
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id,rotation_participant_id,position,shift_start,version FROM rotation_state WHERE rotation_id=$1`, root).Scan(&state.ID, &state.ParticipantID, &state.Position, &state.ShiftStart, &state.Version))
	rows, err := db.QueryContext(ctx, `SELECT id,user_id,position FROM rotation_participants WHERE rotation_id=$1`, root)
	require.NoError(t, err)
	defer rows.Close()
	parts := map[uuid.UUID]sraudit.ParticipantDetail{}
	for rows.Next() {
		var id uuid.UUID
		var p sraudit.ParticipantDetail
		require.NoError(t, rows.Scan(&id, &p.UserID, &p.Position))
		parts[id] = p
	}
	require.NoError(t, rows.Err())
	return state, parts
}

func rotationPopulatedCommitted(t *testing.T, ctx context.Context, db *sql.DB, f rotationProfileFixture, state sraudit.RotationState, parts map[uuid.UUID]sraudit.ParticipantDetail) sraudit.Event {
	t.Helper()
	for _, table := range []string{"rotations", "rotation_state", "rotation_participants"} {
		column := "rotation_id"
		if table == "rotations" {
			column = "id"
		}
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, f.root))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects`))
	var e sraudit.Event
	var raw, snapshot []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT schema_version,event_id,request_id,execution_id,attempt_id,record_kind,root_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,cause,actor_kind,coalesce(actor_id,'00000000-0000-0000-0000-000000000000'),coalesce(home_organization_id,'00000000-0000-0000-0000-000000000000'),authority_source,authority_role,organization_role,outcome,reason_code,occurred_at,effects_version,effects,root_type,operation,before_state FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root).Scan(&e.SchemaVersion, &e.EventID, &e.RequestID, &e.ExecutionID, &e.AttemptID, &e.RecordKind, &e.RootID, &e.TargetOrganizationID, &e.TargetOrgResolution, &e.Provenance, &e.DeletionMechanism, &e.Cause, &e.ActorKind, &e.ActorID, &e.HomeOrganizationID, &e.AuthoritySource, &e.AuthorityRole, &e.OrganizationRole, &e.Outcome, &e.Reason, &e.OccurredAt, &e.EffectsVersion, &raw, &e.RootType, &e.Operation, &snapshot))
	require.NoError(t, json.Unmarshal(raw, &e.Effects))
	require.NoError(t, json.Unmarshal(snapshot, &e.BeforeState))
	require.NoError(t, e.Validate(), "persisted real event must pass Go validator too")
	require.Equal(t, state, *e.BeforeState)
	var safe map[string]any
	require.NoError(t, json.Unmarshal(snapshot, &safe))
	require.Len(t, safe, 5)
	require.Len(t, e.Effects, len(parts))
	seen := map[uuid.UUID]bool{}
	for _, effect := range e.Effects {
		require.Equal(t, sraudit.Participant, effect.ResourceType)
		require.NotNil(t, effect.ResourceUUID)
		id := *effect.ResourceUUID
		require.False(t, seen[id])
		seen[id] = true
		p, ok := parts[id]
		require.True(t, ok)
		require.Equal(t, p, *effect.Participant)
		require.Equal(t, f.root, effect.RootID)
		require.Equal(t, f.org, effect.TargetOrganizationID)
		require.Equal(t, "relationship_removed", effect.Change)
		require.Equal(t, "CASCADE", effect.Provenance)
		require.Equal(t, "fk_cascade", effect.DeletionMechanism)
		require.Equal(t, "rotation_delete", effect.Cause)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, p.UserID))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.rotation))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1 AND user_id=$2`, f.rotation, f.user))
	return e
}

func TestPostgresDeletionEnforcementRotationPopulatedCommit(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	base := ctx
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	app := enforcementApp(t, ctx, db)
	for _, count := range []int{1, 2, 5} {
		for active := range count {
			t.Run(fmt.Sprintf("count=%d/active=%d", count, active), func(t *testing.T) {
				f := rotationPopulated(t, ctx, db, count, active)
				shift := time.Date(2026, 11, 1+active, 2, count, 6, 123456000, time.UTC)
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET shift_start=$2 WHERE rotation_id=$1`, f.root, shift)
				state, parts := rotationPopulatedBefore(t, ctx, db, f.root)
				retained := rotationCascadeRetainedInventory(t, ctx, db, f.root)
				facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(f.root), collector.Limits{PageSize: 1, MaxRows: 1000, MaxQueries: 512, MaxJSONBytes: 1 << 20, MaxFragments: 1000, Timeout: time.Minute})
				require.NoError(t, err)
				require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
				plan := deletionPlan(t, rotationProfileRoot(f.root), facts)
				require.Len(t, plan.Changes(), count+2)
				human := previewAdmit(t, base, db, f.actor)
				confirm := enforcementPreview(t, human, app, rotationProfilePreviewInput(f.root)...)
				ok, err := app.Mutation().DeleteAll(human, rotationProfileInput(f.root, f.root, uuid.New()), confirm)
				require.NoError(t, err)
				require.True(t, ok)
				rotationPopulatedCommitted(t, ctx, db, f, state, parts)
				require.Equal(t, retained, rotationCascadeRetainedInventory(t, ctx, db, f.root))
			})
		}
	}
}

func TestPostgresDeletionEnforcementRotationPopulatedAuditRollback(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	f := rotationPopulated(t, ctx, db, 5, 3)
	app := enforcementApp(t, ctx, db)
	state, parts := rotationPopulatedBefore(t, ctx, db, f.root)
	before := rotationStateContractInventory(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
	enforcementExec(t, ctx, db, `CREATE SEQUENCE synthetic_fix3_deleted`)
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_fix3_sink_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN IF EXISTS(SELECT FROM rotations WHERE id=NEW.root_id) OR EXISTS(SELECT FROM rotation_participants WHERE rotation_id=NEW.root_id) OR EXISTS(SELECT FROM rotation_state WHERE rotation_id=NEW.root_id) THEN RAISE EXCEPTION 'delete not complete'; END IF; PERFORM nextval('synthetic_fix3_deleted'); RAISE EXCEPTION 'synthetic populated audit failure'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_fix3_sink_failure BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_fix3_sink_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	require.Error(t, err)
	var reached bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT is_called FROM synthetic_fix3_deleted`).Scan(&reached))
	require.True(t, reached, "nontransactional marker proves all three actual deletes preceded failed audit append")
	require.Equal(t, before, rotationStateContractInventory(t, ctx, db))
	rotationProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_fix3_sink_failure ON schedule_rotation_delete_audit_events`)
	ok, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	rotationPopulatedCommitted(t, ctx, db, f, state, parts)
}

func rotationPopulatedBarrier(t *testing.T, ctx context.Context, uri string) (*graphqlapp.App, *serviceProfileCertificationBarrier) {
	t.Helper()
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	b := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
	conf.Tracer = b
	db := sql.OpenDB(stdlib.GetConnector(*conf))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return enforcementApp(t, ctx, db), b
}

func TestPostgresDeletionEnforcementRotationPopulatedBatchContext(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationPopulatedTest")
	app := enforcementApp(t, ctx, db)
	f, g := rotationPopulated(t, ctx, db, 1, 0), rotationPopulated(t, ctx, db, 5, 4)
	fs, fp := rotationPopulatedBefore(t, ctx, db, f.root)
	gs, gp := rotationPopulatedBefore(t, ctx, db, g.root)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root, g.root)...)
	_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root, g.root, f.root, uuid.New()), confirm)
	require.NoError(t, err)
	fe := rotationPopulatedCommitted(t, ctx, db, f, fs, fp)
	ge := rotationPopulatedCommitted(t, ctx, db, g, gs, gp)
	require.Equal(t, fe.ExecutionID, ge.ExecutionID)
	require.Equal(t, fe.AttemptID, ge.AttemptID)
	require.Equal(t, fe.RequestID, ge.RequestID)
	require.NotEqual(t, fe.EventID, ge.EventID)
	require.NoError(t, sraudit.ValidateBatch([]sraudit.Event{fe, ge}))
}
