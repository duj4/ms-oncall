package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUODeleteAuditLockWaitSnapshots(t *testing.T) {
	for _, mode := range []string{"update", "reparent", "parent_org", "delete", "schedule_delete_first"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			db := h.App().DB()
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			other := sd6Root(t, h, "schedule", h.UUID("org-b"))
			id := sd7Root(t, h, s)
			u := sd7User(t, h)
			sd8Assign(t, h, u, harness.SmokeOrganizationID)
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, id)}
			confirmation := smokePlanConfirmation(t, h, sd3System(), input)
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var pid int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
			_, err = tx.Exec(`LOCK user_overrides IN ROW EXCLUSIVE MODE`)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
			defer cancel()
			ok, err := sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
			require.Error(t, err, "Override table stabilization is NOWAIT")
			require.False(t, ok)
			require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", id))
			require.Zero(t, sd7Count(t, h))
			switch mode {
			case "update":
				_, err = tx.Exec(`UPDATE user_overrides SET add_user_id=$2,start_time='2021-01-02',end_time='2021-01-04' WHERE id=$1`, id, u)
			case "reparent":
				_, err = tx.Exec(`UPDATE user_overrides SET tgt_schedule_id=$2 WHERE id=$1`, id, other)
			case "parent_org":
				_, err = tx.Exec(`UPDATE schedules SET organization_id=$2 WHERE id=$1`, s, h.UUID("org-b"))
			case "delete":
				_, err = tx.Exec(`DELETE FROM user_overrides WHERE id=$1`, id)
			case "schedule_delete_first":
				_, err = tx.Exec(`DELETE FROM schedules WHERE id=$1`, s)
			}
			require.NoError(t, err)
			if mode == "reparent" || mode == "parent_org" {
				// Keep the retained endpoint in its actual Schedule's scope.
				_, err = tx.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=(SELECT add_user_id FROM user_overrides WHERE id=$1)`, id, h.UUID("org-b"))
				require.NoError(t, err)
			}
			require.NoError(t, tx.Commit())
			current, currentErr := smokeDeletionPreview(t, h, sd3System(), input)
			if currentErr != nil || current == nil || current.ImpactVersion != confirmation.ExpectedImpactVersion {
				ok, err = sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
				smokeDeletionCode(t, err, ds.DeletionDependencyChanged)
				require.False(t, ok)
			} else {
				require.True(t, current.CanProceed)
				require.Equal(t, confirmation.ExpectedImpactVersion, current.ImpactVersion, "System non-User scope-only changes keep the same plan version")
			}
			require.Zero(t, sd7Count(t, h))
			if mode == "delete" || mode == "schedule_delete_first" {
				require.Zero(t, sd7Count(t, h))
				return
			}
			smokeDeleteFencesWriter(t, h, sd7App(h), input, "user_overrides", id)
			var raw []byte
			var before uoaudit.Before
			require.NoError(t, db.QueryRow(`SELECT before_context FROM user_override_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, id).Scan(&raw))
			require.NoError(t, json.Unmarshal(raw, &before))
			if mode == "update" {
				require.Equal(t, u, before.AddUserID.String())
				require.Equal(t, 2021, before.Start.Year())
				require.Equal(t, 3, before.End.Day())
			}
			if mode == "reparent" {
				require.Equal(t, other, before.ParentScheduleID.String())
			}
			if mode == "reparent" || mode == "parent_org" {
				require.Equal(t, h.UUID("org-b"), before.TargetOrganizationID.String())
			}
		})
	}
}

func TestUODeleteAuditScheduleWaitsAndLateWrites(t *testing.T) {
	for _, mode := range []string{"schedule_delete", "override_update", "late_insert", "referenced_user_delete"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			db := h.App().DB()
			s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
			id := sd7Root(t, h, s)
			before := sd7Before(t, h, id)
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, id)}
			scheduleInput := []assignment.RawTarget{sd3Target(assignment.TargetTypeSchedule, s)}
			ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
			defer cancel()
			confirmation, err := smokeDeletionConfirmation(t, h, ctx, input)
			require.NoError(t, err)
			scheduleConfirmation, err := smokeDeletionConfirmation(t, h, ctx, scheduleInput)
			require.NoError(t, err)
			original, auditBefore := smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
			// The historical direct Store call is no longer an executable capability.
			unguarded, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			result, err := h.App().OverrideStore.DeleteUserOverrideForAuditTx(ctx, unguarded, []string{id}, nil)
			smokeDeletionCode(t, err, ds.DeletionUnavailable)
			require.Empty(t, result.Receipts)
			require.NoError(t, unguarded.Rollback())
			require.Equal(t, original, smokeUserBusinessState(t, h))
			require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
			// Preserve NOWAIT refusal independently from the post-admission fence.
			old, err := sd5ExternalDB(t, h, "").BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = old.Rollback() }()
			_, err = old.Exec(`LOCK user_overrides IN ROW EXCLUSIVE MODE`)
			require.NoError(t, err)
			smokeContract4LockPID(t, h, old)
			ok, err := sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
			smokeDeletionCode(t, err, ds.DeletionUnavailable)
			require.False(t, ok)
			require.Equal(t, original, smokeUserBusinessState(t, h))
			require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
			require.NoError(t, old.Rollback())
			gate, err := db.Conn(ctx)
			require.NoError(t, err)
			defer gate.Close()
			var gatePID int
			require.NoError(t, gate.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&gatePID))
			_, err = gate.ExecContext(ctx, `SELECT pg_advisory_lock(990099,$1)`, gatePID)
			require.NoError(t, err)
			sd8Exec(t, h, fmt.Sprintf(`CREATE SEQUENCE safety_override_hits;
  CREATE FUNCTION safety_override_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('safety_override_hits'); PERFORM pg_advisory_xact_lock(990099,%d); RETURN OLD; END $$;
  CREATE TRIGGER safety_override_gate BEFORE DELETE ON user_overrides FOR EACH ROW EXECUTE FUNCTION safety_override_gate()`, gatePID))
			done, finished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(finished)
				ok, e := sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
				if e == nil && !ok {
					e = fmt.Errorf("override mutation returned false")
				}
				done <- e
			}()
			defer func() {
				_, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990099,$1)`, gatePID)
				cancel()
				select {
				case <-finished:
				case <-time.After(5 * time.Second):
					t.Error("override mutation did not finish")
				}
			}()
			sd3WaitBlocked(t, db, gatePID)
			var deletePID int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&deletePID))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT last_value FROM safety_override_hits WHERE is_called`))
			late := uuid.NewString()
			writer := sd5ExternalDB(t, h, "")
			written, writerFinished := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(writerFinished)
				var e error
				switch mode {
				case "schedule_delete":
					_, e = sd7App(h).Mutation().DeleteAll(ctx, scheduleInput, scheduleConfirmation)
				case "override_update":
					r, execErr := writer.ExecContext(ctx, `UPDATE user_overrides SET end_time=end_time+interval '1 day' WHERE id=$1`, id)
					e = execErr
					if e == nil {
						n, countErr := r.RowsAffected()
						e = countErr
						if e == nil && n != 0 {
							e = fmt.Errorf("late update affected deleted root")
						}
					}
				case "late_insert":
					_, e = writer.ExecContext(ctx, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, late, s, before.AddUserID)
				case "referenced_user_delete":
					_, e = writer.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, before.AddUserID)
				}
				written <- e
			}()
			defer func() {
				cancel()
				select {
				case <-writerFinished:
				case <-time.After(5 * time.Second):
					t.Error("late writer did not finish")
				}
			}()
			var writerPID int
			require.Eventually(t, func() bool {
				return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, deletePID).Scan(&writerPID) == nil
			}, 5*time.Second, 10*time.Millisecond)
			require.Equal(t, original, smokeUserBusinessState(t, h))
			require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
			_, err = gate.ExecContext(ctx, `SELECT pg_advisory_unlock(990099,$1)`, gatePID)
			require.NoError(t, err)
			require.NoError(t, <-done)
			writerErr := <-written
			<-finished
			<-writerFinished
			if mode == "schedule_delete" {
				smokeDeletionCode(t, writerErr, ds.DeletionDependencyChanged)
			} else {
				require.NoError(t, writerErr)
			}
			require.Equal(t, 1, sd7Count(t, h))
			require.Zero(t, serviceManagementCount(t, h, "user_overrides", id))
			var raw []byte
			var recorded uoaudit.Before
			var root, parent, org, provenance, effects string
			require.NoError(t, db.QueryRow(`SELECT before_context,root_id,parent_schedule_id,target_organization_id,provenance,effects::text FROM user_override_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, id).Scan(&raw, &root, &parent, &org, &provenance, &effects))
			require.NoError(t, json.Unmarshal(raw, &recorded))
			require.Equal(t, before, recorded)
			require.Equal(t, id, root)
			require.Equal(t, s, parent)
			require.Equal(t, harness.SmokeOrganizationID, org)
			require.Equal(t, "EXPLICIT", provenance)
			require.JSONEq(t, `[]`, effects)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT last_value FROM safety_override_hits`))
			if mode == "schedule_delete" {
				require.Equal(t, 1, serviceManagementCount(t, h, "schedules", s))
				ok, err = smokeDeleteAll(t, h, sd7App(h), ctx, scheduleInput)
				require.NoError(t, err)
				require.True(t, ok)
				require.Empty(t, sd6Effects(t, h, s))
			}
			if mode == "late_insert" {
				require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", late))
				state, audits := smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
				ok, err = sd7App(h).Mutation().DeleteAll(ctx, scheduleInput, scheduleConfirmation)
				smokeDeletionCode(t, err, ds.DeletionDependencyChanged)
				require.False(t, ok)
				require.Equal(t, state, smokeUserBusinessState(t, h))
				require.Equal(t, audits, safetySmokeSuccessState(t, h))
			}
			if mode == "referenced_user_delete" {
				require.Zero(t, serviceManagementCount(t, h, "users", before.AddUserID.String()))
			}
			t.Logf("mode=%s Guarded DELETE PID=%d hit=1; external writer PID=%d blocked via pg_blocking_pids then completed; fresh Override before_context and atomic B2 verified", mode, deletePID, writerPID)
		})
	}
}
