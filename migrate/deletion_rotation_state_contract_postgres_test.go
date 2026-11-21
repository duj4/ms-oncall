package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// This is a contract investigation, not an executable deletion profile. No
// trigger, FK, policy, audit validator, or production Store is changed here.
func TestPostgresDeletionEnforcementRotationStateFix1Contract(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationStateFix1Contract")
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	for _, check := range []struct {
		name, definition string
		deferred         bool
	}{
		{"rotation_state_rotation_participant_id_fkey", "FOREIGN KEY (rotation_participant_id) REFERENCES rotation_participants(id) DEFERRABLE", true},
		{"rotation_state_rotation_id_fkey", "FOREIGN KEY (rotation_id) REFERENCES rotations(id) ON DELETE CASCADE", false},
		{"rotation_participants_rotation_id_fkey", "FOREIGN KEY (rotation_id) REFERENCES rotations(id) ON DELETE CASCADE", false},
		{"rotation_participants_user_id_fkey", "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE", false},
	} {
		var def string
		var deferrable, initiallyDeferred bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_constraintdef(oid),condeferrable,condeferred FROM pg_constraint WHERE conname=$1`, check.name).Scan(&def, &deferrable, &initiallyDeferred))
		require.Equal(t, check.definition, def)
		require.Equal(t, check.deferred, deferrable)
		require.False(t, initiallyDeferred)
		t.Log(check.name, def)
	}
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_trigger WHERE tgrelid IN ('rotation_participants'::regclass,'rotation_state'::regclass,'rotations'::regclass) AND tgenabled<>'O'`))

	app := enforcementApp(t, ctx, db)
	for _, count := range []int{1, 2, 5} {
		for active := range count {
			t.Run(fmt.Sprintf("participants-%d/active-%d", count, active), func(t *testing.T) {
				f := newRotationProfileFixture(t, ctx, db)
				users := make([]string, count)
				for i := range users {
					// The same real retained User also participates in f.rotation.
					users[i] = f.user.String()
				}
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), users))
				require.NoError(t, app.RotationStore.SetActiveIndexTx(ctx, nil, f.root.String(), active))
				before := rotationStateContractInventory(t, ctx, db)
				// FIX3 admits this closure, but still requires confirmation.
				// Keep the original truthful explicit-child audit rejection proof.
				_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), nil)
				enforceCode(t, err, ds.DeletionConfirmationRequired)
				require.Equal(t, before, rotationStateContractInventory(t, ctx, db))

				tx := nrBegin(t, ctx, db)
				locked, _, err := guard.StabilizeRotation(ctx, tx, rotationProfileSelectors(f.root))
				require.NoError(t, err)
				// Intentionally inspect the gate without cleaning State first.
				facts, err := collector.Collect(locked, tx, rotationProfileRoot(f.root), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(rotationProfileRoot(f.root)))
				require.NoError(t, err)
				require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
				e := rotationStateContractEvent(f.root, f.org)
				s := &sraudit.RotationState{}
				var rotationID uuid.UUID
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT id,rotation_id,rotation_participant_id,position,version,shift_start FROM rotation_state WHERE rotation_id=$1`, f.root).Scan(&s.ID, &rotationID, &s.ParticipantID, &s.Position, &s.Version, &s.ShiftStart))
				require.Equal(t, f.root, rotationID)
				require.EqualValues(t, active, s.Position)
				require.EqualValues(t, 2, s.Version)
				e.BeforeState = s
				// The State has a distinct physical ID and is attributed to the
				// event's actual Rotation root, not to its retained User.
				var removed sraudit.RotationState
				require.NoError(t, tx.QueryRowContext(ctx, `DELETE FROM rotation_state WHERE rotation_id=$1 RETURNING id,rotation_participant_id,position,version,shift_start`, f.root).Scan(&removed.ID, &removed.ParticipantID, &removed.Position, &removed.Version, &removed.ShiftStart))
				require.Equal(t, *s, removed)
				// Real receipts from explicit child DML; no predicted/captured
				// inventory is substituted for DELETE RETURNING.
				rows, err := tx.QueryContext(ctx, `DELETE FROM rotation_participants WHERE rotation_id=$1 RETURNING id,rotation_id,user_id,position`, f.root)
				require.NoError(t, err)
				for rows.Next() {
					var id, root, user uuid.UUID
					var position int32
					require.NoError(t, rows.Scan(&id, &root, &user, &position))
					require.Equal(t, f.root, root)
					e.Effects = append(e.Effects, sraudit.Effect{EffectID: uuid.New(), ResourceType: sraudit.Participant, RootID: root, TargetOrganizationID: f.org, ResourceUUID: &id,
						Relation: "rotation.participant", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "explicit_sql", Cause: "rotation_delete",
						Participant: &sraudit.ParticipantDetail{UserID: user, Position: position}})
				}
				require.NoError(t, rows.Err())
				require.NoError(t, rows.Close())
				require.Len(t, e.Effects, count)
				var receipt sraudit.Receipt
				require.NoError(t, tx.QueryRowContext(ctx, `DELETE FROM rotations WHERE id=$1 RETURNING id,organization_id`, f.root).Scan(&receipt.ID, &receipt.OrganizationID))
				require.Equal(t, sraudit.Receipt{ID: f.root, OrganizationID: f.org}, receipt)
				var roots, parts, states, retained int
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM rotations WHERE id=$1),(SELECT count(*) FROM rotation_participants WHERE rotation_id=$1),(SELECT count(*) FROM rotation_state WHERE rotation_id=$1),(SELECT count(*) FROM users WHERE id=$2)`, f.root, f.user).Scan(&roots, &parts, &states, &retained))
				require.Zero(t, roots)
				require.Zero(t, parts)
				require.Zero(t, states)
				require.Equal(t, 1, retained)
				// The original two-table protocol remains held; State is not
				// recreated by the participant delete/reorder/count triggers.
				require.ErrorIs(t, sraudit.Append(ctx, tx, e), sraudit.ErrInvalid)
				raw, err := json.Marshal(e.Effects)
				require.NoError(t, err)
				state, err := json.Marshal(s)
				require.NoError(t, err)
				var valid bool
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT schedule_rotation_delete_effects_valid($1::jsonb,$2::jsonb,$3,$4,'rotation',false)`, string(raw), string(state), f.root, f.org).Scan(&valid))
				require.False(t, valid, "database also rejects the truthful explicit child mechanism")
				// Isolate the contract gap to the physical mechanism. This
				// counterfactual is validated only, never appended or committed.
				counterfactual := e
				counterfactual.Effects = slices.Clone(e.Effects)
				for i := range counterfactual.Effects {
					counterfactual.Effects[i].DeletionMechanism = "fk_cascade"
				}
				require.NoError(t, counterfactual.Validate())
				otherRaw, err := json.Marshal(counterfactual.Effects)
				require.NoError(t, err)
				require.NoError(t, tx.QueryRowContext(ctx, `SELECT schedule_rotation_delete_effects_valid($1::jsonb,$2::jsonb,$3,$4,'rotation',false)`, string(otherRaw), string(state), f.root, f.org).Scan(&valid))
				require.True(t, valid, "State and participant identities fit the existing closed schema")
				// A real audit INSERT after all three deletes must fail even if
				// Go validation is bypassed. Never relabel explicit child DML
				// as fk_cascade just to make this append succeed.
				_, err = tx.ExecContext(ctx, `INSERT INTO schedule_rotation_delete_audit_events
				 (event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,target_organization_id,target_org_resolution,effects,before_state,provenance,deletion_mechanism,cause,actor_kind,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at)
				 VALUES($1,$2,$3,$4,'success_witness','rotation.delete','rotation',$5,$6,'known_normal',$7::jsonb,$8::jsonb,'EXPLICIT','explicit_sql','explicit_target','internal_system','trusted_internal_system','internal_system','unknown','committed','deleted',$9)`, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, f.root, f.org, string(raw), string(state), e.OccurredAt)
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "23514", pg.Code)
				require.NoError(t, tx.Rollback())
				require.Equal(t, before, rotationStateContractInventory(t, ctx, db), "all business rows restored exactly after native audit rejection")
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE outcome='committed'`))
				t.Log("State -> Participants RETURNING -> Root RETURNING completed; truthful B2 rejected by Go and PostgreSQL; complete rollback confirmed")
			})
		}
	}
}

func rotationStateContractEvent(root, org uuid.UUID) sraudit.Event {
	return sraudit.Event{SchemaVersion: 1, EffectsVersion: 1, RootType: sraudit.Rotation, Operation: "rotation.delete", EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RootID: root, TargetOrganizationID: org,
		TargetOrgResolution: "known_normal", RecordKind: "success_witness", Outcome: "committed", Reason: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target",
		ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", OccurredAt: time.Now().UTC()}
}

// Compare all rotations, children, Users and assignments, including retained
// other-Rotation state. Only safe identities/configuration are projected.
func rotationStateContractInventory(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var inventory string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object(
	 'rotations',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM rotations r),
	 'participants',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM rotation_participants p),
	 'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM rotation_state s),
	 'users',(SELECT jsonb_agg(id ORDER BY id) FROM users),
	 'assignments',(SELECT jsonb_agg(jsonb_build_object('user',user_id,'org',effective_organization_id,'role',organization_role) ORDER BY user_id) FROM user_organization_assignments))::text`).Scan(&inventory))
	return inventory
}
