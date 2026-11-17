package migrate

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
)

// This matrix executes real production-table SQL, distinct from the normal
// Store lifecycle and Controller tests. Blocking is observed in PostgreSQL;
// there is no elapsed-time guess about when the writer reached its lock.
func TestPostgresDeletionEnforcementUserWriters(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	db.SetMaxOpenConns(8)
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"user_update", "user_role", "assignment_update", "assignment_delete", "session_create", "session_update", "session_delete", "subject_create", "subject_delete", "basic_create", "basic_update", "basic_delete", "cm_create", "cm_update", "cm_delete", "nr_create", "nr_update", "nr_delete", "action_create", "action_retarget", "rule_create", "rule_retarget", "participant_create", "participant_retarget", "override_create", "override_retarget"} {
			t.Run(first+"/"+kind, func(t *testing.T) {
				f := userNativeLifecycle(t, ctx, db, 1, 1, true)
				p := userNativeParentRows(t, ctx, db, f)
				other := userNativeLifecycle(t, ctx, db, 0, 0, false)
				var query string
				args := []any{f.user}
				switch kind {
				case "user_update":
					query = `UPDATE users SET name='native concurrent update' WHERE id=$1`
				case "user_role":
					query = `UPDATE users SET role='admin' WHERE id=$1`
				case "assignment_update":
					query = `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`
				case "assignment_delete":
					query = `DELETE FROM user_organization_assignments WHERE user_id=$1`
				case "session_create":
					query = `INSERT INTO auth_user_sessions(id,user_id) VALUES(gen_random_uuid(),$1)`
				case "session_update":
					query = `UPDATE auth_user_sessions SET last_access_at=now() WHERE user_id=$1`
				case "session_delete":
					query = `DELETE FROM auth_user_sessions WHERE user_id=$1`
				case "subject_create":
					query = `INSERT INTO auth_subjects(provider_id,subject_id,user_id) VALUES('synthetic',$2,$1)`
					args = append(args, uuid.NewString())
				case "subject_delete":
					enforcementExec(t, ctx, db, `INSERT INTO auth_subjects(provider_id,subject_id,user_id) VALUES('synthetic',$2,$1)`, f.user, uuid.NewString())
					query = `DELETE FROM auth_subjects WHERE user_id=$1`
				case "basic_create":
					query = `INSERT INTO auth_basic_users(user_id,username,password_hash) VALUES($1,$2,'SYNTHETIC_NOT_A_PASSWORD')`
					args = append(args, uuid.NewString())
				case "basic_update", "basic_delete":
					enforcementExec(t, ctx, db, `INSERT INTO auth_basic_users(user_id,username,password_hash) VALUES($1,$2,'SYNTHETIC_NOT_A_PASSWORD')`, f.user, uuid.NewString())
					query = `UPDATE auth_basic_users SET password_hash='SYNTHETIC_CHANGED' WHERE user_id=$1`
					if kind == "basic_delete" {
						query = `DELETE FROM auth_basic_users WHERE user_id=$1`
					}
				case "cm_create":
					query = `INSERT INTO user_contact_methods(id,user_id,name,type,value,dest) VALUES(gen_random_uuid(),$1,'native','WEBHOOK',$2,jsonb_build_object('type','synthetic','id',$2::text))`
					args = append(args, uuid.NewString())
				case "cm_update":
					query = `UPDATE user_contact_methods SET name='native update' WHERE user_id=$1`
				case "cm_delete":
					query = `DELETE FROM user_contact_methods WHERE user_id=$1`
				case "nr_create":
					query = `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,5)`
					args = append(args, f.cms[0])
				case "nr_update":
					query = `UPDATE user_notification_rules SET delay_minutes=5 WHERE user_id=$1`
				case "nr_delete":
					query = `DELETE FROM user_notification_rules WHERE user_id=$1`
				case "action_create":
					query = `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($2,$3,$1)`
					args = append(args, p.action, p.step)
				case "action_retarget":
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, p.action, p.step, other.user)
					query = `UPDATE escalation_policy_actions SET user_id=$1 WHERE id=$2`
					args = append(args, p.action)
				case "rule_create":
					query = `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($2,$3,$1)`
					args = append(args, p.rule, p.schedule)
				case "rule_retarget":
					enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, p.rule, p.schedule, other.user)
					query = `UPDATE schedule_rules SET tgt_user_id=$1 WHERE id=$2`
					args = append(args, p.rule)
				case "participant_create":
					query = `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($2,$3,$1,0)`
					args = append(args, p.participant, p.rotation)
				case "participant_retarget":
					enforcementExec(t, ctx, db, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0)`, p.participant, p.rotation, other.user)
					query = `UPDATE rotation_participants SET user_id=$1 WHERE id=$2`
					args = append(args, p.participant)
				case "override_create":
					query = `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($2,$3,$1,now()+'1h'::interval,now()+'2h'::interval)`
					args = append(args, p.override, p.schedule)
				case "override_retarget":
					enforcementExec(t, ctx, db, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,now()+'1h'::interval,now()+'2h'::interval)`, p.override, p.schedule, other.user)
					query = `UPDATE user_overrides SET add_user_id=$1 WHERE id=$2`
					args = append(args, p.override)
				}
				app := enforcementApp(t, ctx, db)
				confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
				writer := epProfileWriter(t, ctx, db)
				defer func() { _ = writer.Rollback() }()
				if first == "writer" {
					_, err := writer.ExecContext(ctx, query, args...)
					require.NoError(t, err)
					tx := userPhaseATx(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, userProfileSelectors(f.user), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(userProfileRoot(f.user)))
					require.Error(t, err)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
					// Latest committed facts must govern the original Controller.
					_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
					if err == nil {
						require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
					} else {
						require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
						require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.user))
					}
					return
				}
				traced, b := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
				controller := enforcementApp(t, ctx, traced)
				deleted := make(chan error, 1)
				go func() {
					_, err := controller.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
					deleted <- err
				}()
				select {
				case <-b.arrived:
				case err := <-deleted:
					require.NoError(t, err)
					t.Fatal("controller did not reach certification")
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				var pid int
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				written := make(chan error, 1)
				go func() { _, err := writer.ExecContext(ctx, query, args...); written <- err }()
				overrideWait(t, ctx, db, pid, written)
				close(b.resume)
				require.NoError(t, <-deleted)
				writeErr := <-written
				if writeErr == nil {
					require.NoError(t, writer.Commit())
				} else {
					require.NoError(t, writer.Rollback())
				}
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				for _, table := range []string{"auth_user_sessions", "auth_subjects", "auth_basic_users", "user_contact_methods", "user_notification_rules", "rotation_participants", "notification_policy_cycles"} {
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE user_id=$1`, f.user))
				}
			})
		}
	}
}

func TestPostgresDeletionEnforcementUserBlockedWriters(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UserNative")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"action_delete", "rule_delete", "participant_delete", "participant_reorder", "participant_user_update", "override_delete", "override_update"} {
			t.Run(first+"/"+kind, func(t *testing.T) {
				f := userNativeLifecycle(t, ctx, db, 1, 1, true)
				p := userNativeParentRows(t, ctx, db, f)
				var query string
				var id uuid.UUID
				switch kind {
				case "action_delete":
					userNativeAddReference(t, ctx, db, f, p, "action")
					query = `DELETE FROM escalation_policy_actions WHERE id=$1`
					id = p.action
				case "rule_delete":
					userNativeAddReference(t, ctx, db, f, p, "rule")
					query = `DELETE FROM schedule_rules WHERE id=$1`
					id = p.rule
				case "participant_delete", "participant_reorder", "participant_user_update":
					userNativeAddReference(t, ctx, db, f, p, "participant")
					id = p.participant
					query = `DELETE FROM rotation_participants WHERE id=$1`
					if kind == "participant_reorder" {
						enforcementExec(t, ctx, db, `INSERT INTO rotation_participants(rotation_id,user_id,position) VALUES($1,$2,1)`, p.rotation, f.user)
						query = `UPDATE rotation_participants SET position=1-position WHERE rotation_id=(SELECT rotation_id FROM rotation_participants WHERE id=$1)`
					}
					if kind == "participant_user_update" {
						query = `UPDATE rotation_participants SET user_id=user_id WHERE id=$1`
					}
				case "override_delete", "override_update":
					userNativeAddReference(t, ctx, db, f, p, "future_override")
					id = p.override
					query = `DELETE FROM user_overrides WHERE id=$1`
					if kind == "override_update" {
						query = `UPDATE user_overrides SET end_time=end_time+'1h'::interval WHERE id=$1`
					}
				}
				app := enforcementApp(t, ctx, db)
				confirm := enforcementPreview(t, ctx, app, userProfilePreview(f.user)...)
				_, err := app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
				enforceCode(t, err, ds.DeletionBlocked)
				tx, writer := userPhaseATx(t, ctx, db), epProfileWriter(t, ctx, db)
				if first == "writer" {
					_, err = writer.ExecContext(ctx, query, id)
					require.NoError(t, err)
					_, _, err = guard.StabilizeUser(ctx, tx, userProfileSelectors(f.user))
					require.Error(t, err)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
				} else {
					_, _, err = guard.StabilizeUser(ctx, tx, userProfileSelectors(f.user))
					require.NoError(t, err)
					var pid int
					require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
					done := make(chan error, 1)
					go func() { _, err := writer.ExecContext(ctx, query, id); done <- err }()
					overrideWait(t, ctx, db, pid, done)
					require.NoError(t, tx.Rollback())
					require.NoError(t, <-done)
					require.NoError(t, writer.Commit())
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				if kind == "action_delete" || kind == "rule_delete" || kind == "participant_delete" || kind == "override_delete" {
					_, err = app.Mutation().DeleteAll(ctx, userProfileInput(f.user), confirm)
					enforceCode(t, err, ds.DeletionDependencyChanged)
				}
			})
		}
	}
}
