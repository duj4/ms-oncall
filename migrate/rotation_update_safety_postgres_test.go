package migrate

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func rotationUpdateFixture(t *testing.T, ctx context.Context, db *sql.DB) rotationProfileFixture {
	t.Helper()
	f := rotationPopulated(t, ctx, db, 4, 3)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.root)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,rotation_id) VALUES($1,$2,$3)`, uuid.New(), f.step, f.root)
	enforcementExec(t, ctx, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,now()-interval '2 hour',now()-interval '1 hour')`, f.schedule, f.user)
	enforcementExec(t, ctx, db, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time,end_time) VALUES($1,$2,now()-interval '2 hour',now()-interval '1 hour')`, f.step, f.user)
	return f
}

// Compare all relevant committed business rows and successful audit counts,
// independently of the transaction being tested. Failure observations may grow.
func rotationUpdateInventory(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var data string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM rotations r),
 (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM rotation_participants p),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM rotation_state s),
 (SELECT jsonb_agg(jsonb_build_array(id,role) ORDER BY id) FROM users),
 (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM schedule_rules r),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM escalation_policy_actions a),
 (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM schedule_on_call_users h),
 (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM ep_step_on_call_users h),
 (SELECT count(*) FROM schedule_rotation_update_audit_events WHERE outcome='committed'),
 (SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE outcome='committed'),
 (SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'))::text`).Scan(&data))
	return data
}

func rotationUpdateSnapshot(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var state string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array(
 ARRAY(SELECT id FROM rotation_participants WHERE rotation_id=$1 ORDER BY position),
 ARRAY(SELECT user_id FROM rotation_participants WHERE rotation_id=$1 ORDER BY position),
 ARRAY(SELECT position FROM rotation_participants WHERE rotation_id=$1 ORDER BY position),
 (SELECT participant_count FROM rotations WHERE id=$1),
 (SELECT jsonb_build_array(id,position,rotation_participant_id,shift_start,version) FROM rotation_state WHERE rotation_id=$1))::text`, id).Scan(&state))
	return state
}

func rotationUpdateInput(f rotationProfileFixture, count int) graphql2.UpdateRotationInput {
	users := make([]string, count)
	for n := range users {
		users[n] = f.user.String()
		if n%2 == 1 {
			users[n] = f.actor.String()
		}
	}
	return graphql2.UpdateRotationInput{ID: f.root.String(), UserIDs: users}
}

func TestPostgresRotationUpdateSafetyBusiness(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	require.Equal(t, len(Names()), enforcementCount(t, ctx, db, `SELECT count(*) FROM gorp_migrations`))
	for _, kind := range []string{"scalar", "same", "add", "reorder", "replace_only", "one", "many", "clear", "mixed", "duplicate", "explicit_active"} {
		t.Run(kind, func(t *testing.T) {
			f := rotationUpdateFixture(t, ctx, db)
			input := rotationUpdateInput(f, 4)
			text := "Synthetic configured description"
			switch kind {
			case "scalar":
				input.UserIDs = nil
				input.Description = &text
			case "add":
				input.UserIDs = append(input.UserIDs, f.user.String())
			case "reorder":
				slices.Reverse(input.UserIDs)
			case "replace_only":
				input.UserIDs[0] = f.actor.String()
			case "one":
				input.UserIDs = input.UserIDs[:3]
			case "many", "mixed", "explicit_active":
				input.UserIDs = input.UserIDs[:2]
			case "clear":
				input.UserIDs = []string{}
			case "duplicate":
				input.UserIDs = []string{f.user.String(), f.user.String()}
			}
			if kind == "mixed" {
				input.UserIDs[0] = f.actor.String()
				input.Description = &text
			}
			if kind == "explicit_active" {
				active := 1
				input.ActiveUserIndex = &active
			}
			parts, err := app.RotationStore.FindAllParticipants(ctx, input.ID)
			require.NoError(t, err)
			beforeSnapshot := rotationUpdateSnapshot(t, ctx, db, f.root)
			before := rotationUpdateInventory(t, ctx, db)
			p, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.NoError(t, err)
			require.True(t, p.CanProceed)
			require.True(t, p.Complete)
			require.Equal(t, graphql2.DeletionOperationUpdateRotation, p.Operation)
			require.Equal(t, before, rotationUpdateInventory(t, ctx, db), "Preview is business/audit read-only")
			destructive := input.UserIDs != nil && len(input.UserIDs) < len(parts)
			require.Equal(t, destructive, p.RequiresConfirmation)
			var expected []string
			if destructive {
				for _, part := range parts[len(input.UserIDs):] {
					expected = append(expected, part.ID)
				}
				var removed []string
				for _, r := range p.Removed {
					if r.Type == "ROTATION_PARTICIPANT" {
						removed = append(removed, r.ID)
					} else {
						require.Equal(t, "ROTATION_STATE", r.Type)
						require.Empty(t, input.UserIDs)
					}
				}
				require.ElementsMatch(t, expected, removed)
				for _, c := range []*graphql2.DeletionSafetyConfirmationInput{nil, {AcknowledgeImpacts: true}, {ExpectedImpactVersion: p.ImpactVersion}, {ExpectedImpactVersion: "forged", AcknowledgeImpacts: true}, {ExpectedImpactVersion: p.ImpactVersion + "x", AcknowledgeImpacts: true}} {
					input.Confirmation = c
					ok, err := app.Mutation().UpdateRotation(ctx, input)
					require.Error(t, err)
					require.False(t, ok)
					require.Equal(t, before, rotationUpdateInventory(t, ctx, db))
				}
				input.Confirmation = updateNativeConfirmation(p)
			} else {
				require.Empty(t, p.Removed)
			}
			ok, err := app.Mutation().UpdateRotation(ctx, input)
			require.NoError(t, err)
			require.True(t, ok)
			current, err := app.RotationStore.FindAllParticipants(ctx, input.ID)
			require.NoError(t, err)
			if input.UserIDs != nil {
				require.Len(t, current, len(input.UserIDs))
				for n, part := range current {
					require.Equal(t, input.UserIDs[n], part.Target.TargetID())
					if n < len(parts) {
						require.Equal(t, parts[n].ID, part.ID, "position retains Participant identity")
					}
				}
			}
			var beforeIDs, afterIDs []string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT before_participant_ids,after_participant_ids FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed'`, f.root).Scan(pq.Array(&beforeIDs), pq.Array(&afterIDs)))
			var auditedBefore, auditedAfter string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array(before_participant_ids,before_user_ids,before_positions,before_participant_count,
 CASE WHEN before_state_id IS NULL THEN null ELSE jsonb_build_array(before_state_id,before_state_position,before_state_participant_id,before_shift_start,before_state_version) END)::text,
 jsonb_build_array(after_participant_ids,after_user_ids,after_positions,after_participant_count,
 CASE WHEN after_state_id IS NULL THEN null ELSE jsonb_build_array(after_state_id,after_state_position,after_state_participant_id,after_shift_start,after_state_version) END)::text
 FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed'`, f.root).Scan(&auditedBefore, &auditedAfter))
			require.JSONEq(t, beforeSnapshot, auditedBefore)
			require.JSONEq(t, rotationUpdateSnapshot(t, ctx, db, f.root), auditedAfter)
			var actual []string
			for _, id := range beforeIDs {
				if !slices.Contains(afterIDs, id) {
					actual = append(actual, id)
				}
			}
			require.ElementsMatch(t, expected, actual, "sole U04 witness equals confirmed deletion identities")
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed'`, f.root))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=ANY($1::uuid[])`, pq.Array([]string{f.user.String(), f.actor.String()})))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, f.root))
			if kind == "clear" {
				require.Len(t, p.Removed, len(parts)+1)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.root))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND before_state_id IS NOT NULL AND after_state_id IS NULL`, f.root))
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE tgt_rotation_id=$1`, f.root))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE rotation_id=$1`, f.root))
			require.Positive(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.rotation))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2`, f.schedule, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1 AND user_id=$2`, f.step, f.user))
		})
	}
}

func TestPostgresRotationUpdateSafetyDrift(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"intent", "add", "retarget", "remove", "state", "config", "user", "rule", "action", "scope"} {
		t.Run(mode, func(t *testing.T) {
			f := rotationUpdateFixture(t, ctx, db)
			input := rotationUpdateInput(f, 2)
			p, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.NoError(t, err)
			switch mode {
			case "intent":
				input.UserIDs = input.UserIDs[:1]
			case "add":
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, input.ID, []string{f.user.String()}))
			case "retarget":
				enforcementExec(t, ctx, db, `UPDATE rotation_participants SET user_id=$2 WHERE rotation_id=$1 AND position=2`, f.root, f.actor)
			case "remove":
				enforcementExec(t, ctx, db, `DELETE FROM rotation_participants WHERE rotation_id=$1 AND position=2`, f.root)
			case "state":
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET shift_start=shift_start+interval '1 second' WHERE rotation_id=$1`, f.root)
			case "config":
				enforcementExec(t, ctx, db, `UPDATE rotations SET shift_length=2 WHERE id=$1`, f.root)
			case "user":
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.user)
			case "rule":
				enforcementExec(t, ctx, db, `UPDATE schedule_rules SET start_time='02:00' WHERE tgt_rotation_id=$1`, f.root)
			case "action":
				enforcementExec(t, ctx, db, `DELETE FROM escalation_policy_actions WHERE rotation_id=$1`, f.root)
			case "scope":
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.user)
			}
			before := rotationUpdateInventory(t, ctx, db)
			input.Confirmation = updateNativeConfirmation(p)
			_, err = app.Mutation().UpdateRotation(ctx, input)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			require.Equal(t, before, rotationUpdateInventory(t, ctx, db))
		})
	}
}

func TestPostgresRotationUpdateSafetyUnsupportedAndStore(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"v1", "missing_state", "foreign", "missing_user", "invalid_user", "participant_as_user", "missing_rotation", "invalid_rotation"} {
		t.Run(mode, func(t *testing.T) {
			f := rotationUpdateFixture(t, ctx, db)
			input := rotationUpdateInput(f, 2)
			switch mode {
			case "v1":
				enforcementExec(t, ctx, db, `UPDATE rotation_state SET version=1 WHERE rotation_id=$1`, f.root)
			case "missing_state":
				enforcementExec(t, ctx, db, `DELETE FROM rotation_state WHERE rotation_id=$1`, f.root)
			case "foreign":
				other := rotationUpdateFixture(t, ctx, db)
				input.UserIDs[0] = other.user.String()
			case "missing_user":
				input.UserIDs[0] = uuid.NewString()
			case "invalid_user":
				input.UserIDs[0] = "invalid"
			case "participant_as_user":
				parts, err := app.RotationStore.FindAllParticipants(ctx, input.ID)
				require.NoError(t, err)
				input.UserIDs[0] = parts[0].ID
			case "missing_rotation":
				input.ID = uuid.NewString()
			case "invalid_rotation":
				input.ID = "invalid"
			}
			before := rotationUpdateInventory(t, ctx, db)
			_, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.Error(t, err)
			_, err = app.Mutation().UpdateRotation(ctx, input)
			require.Error(t, err)
			require.Equal(t, before, rotationUpdateInventory(t, ctx, db))
			if mode == "v1" || mode == "missing_state" {
				text := "Ordinary legacy configuration remains supported"
				ok, err := app.Mutation().UpdateRotation(ctx, graphql2.UpdateRotationInput{ID: f.root.String(), Description: &text})
				require.NoError(t, err)
				require.True(t, ok)
			}
		})
	}
	f := rotationUpdateFixture(t, ctx, db)
	parts, err := app.RotationStore.FindAllParticipants(ctx, f.root.String())
	require.NoError(t, err)
	before := rotationUpdateInventory(t, ctx, db)
	for _, withTx := range []bool{false, true} {
		var tx *sql.Tx
		if withTx {
			tx, err = db.BeginTx(ctx, nil)
			require.NoError(t, err)
		}
		enforceCode(t, app.RotationStore.DeleteRotationParticipantsTx(ctx, tx, []string{parts[0].ID}), ds.DeletionUnavailable)
		_, err = app.RotationStore.DeleteRotationParticipantsReceiptTx(ctx, tx, []string{parts[0].ID})
		enforceCode(t, err, ds.DeletionUnavailable)
		enforceCode(t, app.RotationStore.DeleteStateTx(ctx, tx, f.root.String()), ds.DeletionUnavailable)
		require.NoError(t, app.RotationStore.DeleteRotationParticipantsTx(ctx, tx, nil))
		if withTx {
			require.NoError(t, tx.Commit(), "a caught refusal must have staged no deletion")
		}
	}
	require.Equal(t, before, rotationUpdateInventory(t, ctx, db))
}

func TestPostgresRotationUpdateSafetyAtomicity(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "RotationUpdateSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"delete", "header", "snapshot_detail", "commit", "missing_receipt", "extra_effect", "state_recheck", "retarget_survivor"} {
		t.Run(mode, func(t *testing.T) {
			f := rotationUpdateFixture(t, ctx, db)
			input := rotationUpdateInput(f, 2)
			text := "Synthetic atomic scalar update"
			input.Description = &text
			p, err := app.Query().PreviewUpdateRotation(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			before := rotationUpdateInventory(t, ctx, db)
			table := "rotation_participants"
			timing, constraint, deferred := "BEFORE DELETE", "", ""
			body := `IF OLD.rotation_id='` + f.root.String() + `' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='synthetic rotation update fault'; END IF; RETURN OLD;`
			switch mode {
			case "header", "commit":
				table, timing = boundedAuditTable, "BEFORE INSERT"
				body = `IF NEW.target_id='` + f.root.String() + `' AND NEW.outcome='committed' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='synthetic rotation audit fault'; END IF; RETURN NEW;`
				if mode == "commit" {
					timing, constraint, deferred = "AFTER INSERT", "CONSTRAINT ", "DEFERRABLE INITIALLY DEFERRED"
				}
			case "missing_receipt":
				body = `IF OLD.rotation_id='` + f.root.String() + `' THEN RETURN NULL; END IF; RETURN OLD;`
			case "extra_effect":
				// An unapproved extra row cannot hide behind a valid requested receipt.
				body = `IF OLD.rotation_id='` + f.root.String() + `' AND OLD.position>=2 THEN DELETE FROM rotation_participants WHERE rotation_id=OLD.rotation_id AND position=1; END IF; RETURN OLD;`
			case "state_recheck":
				body = `IF OLD.rotation_id='` + f.root.String() + `' THEN UPDATE rotation_state SET version=1 WHERE rotation_id=OLD.rotation_id; END IF; RETURN OLD;`
			case "retarget_survivor":
				body = `IF OLD.rotation_id='` + f.root.String() + `' THEN UPDATE rotation_participants SET user_id='` + f.actor.String() + `' WHERE rotation_id=OLD.rotation_id AND position=0; END IF; RETURN OLD;`
			}
			if mode == "snapshot_detail" {
				enforcementExec(t, ctx, db, `ALTER TABLE schedule_rotation_update_audit_events ADD CONSTRAINT rotation_safety_fault CHECK(outcome<>'committed' OR target_id<>'`+f.root.String()+`' OR before_participant_count=after_participant_count)`)
				t.Cleanup(func() {
					enforcementExec(t, ctx, db, `ALTER TABLE schedule_rotation_update_audit_events DROP CONSTRAINT rotation_safety_fault`)
				})
			} else {
				enforcementExec(t, ctx, db, `CREATE FUNCTION rotation_safety_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$`)
				enforcementExec(t, ctx, db, `CREATE `+constraint+`TRIGGER rotation_safety_fault `+timing+` ON `+table+` `+deferred+` FOR EACH ROW EXECUTE FUNCTION rotation_safety_fault()`)
				t.Cleanup(func() {
					enforcementExec(t, ctx, db, `DROP TRIGGER rotation_safety_fault ON `+table)
					enforcementExec(t, ctx, db, `DROP FUNCTION rotation_safety_fault()`)
				})
			}
			ok, err := app.Mutation().UpdateRotation(ctx, input)
			require.Error(t, err)
			require.False(t, ok)
			if mode == "header" || mode == "snapshot_detail" || mode == "commit" || mode == "delete" {
				want := "audit_write_failed"
				if mode == "commit" {
					want = "commit_rejected"
				}
				if mode == "delete" {
					want = "write_failed"
				}
				var reason string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT reason_code FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome<>'committed' ORDER BY occurred_at DESC LIMIT 1`, f.root).Scan(&reason))
				require.Equal(t, want, reason, "must reach the specified native fault stage")
			}
			require.Equal(t, before, rotationUpdateInventory(t, ctx, db))
			// A subsequent independent transaction can take every relevant lock.
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE NOWAIT`)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())
		})
	}
}
