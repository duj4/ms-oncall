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
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var pid int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
			_, err = tx.Exec(`LOCK user_overrides IN ROW EXCLUSIVE MODE`)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := sd7App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeUserOverride, id)})
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
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
			require.NoError(t, tx.Commit())
			require.NoError(t, <-done)
			if mode == "delete" || mode == "schedule_delete_first" {
				require.Zero(t, sd7Count(t, h))
				return
			}
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
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var pid int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
			result, err := h.App().OverrideStore.DeleteUserOverrideForAuditTx(sd3System(), tx, []string{id}, nil)
			require.NoError(t, err)
			require.Len(t, result.Receipts, 1)
			ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
			defer cancel()
			done := make(chan error, 1)
			late := uuid.NewString()
			go func() {
				var err error
				switch mode {
				case "schedule_delete":
					_, err = sd7App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeSchedule, s)})
				case "override_update":
					var n int64
					r, e := db.ExecContext(ctx, `UPDATE user_overrides SET end_time=end_time+interval '1 day' WHERE id=$1`, id)
					err = e
					if e == nil {
						n, err = r.RowsAffected()
						if n != 0 {
							err = fmt.Errorf("late update affected deleted root")
						}
					}
				case "late_insert":
					_, err = db.ExecContext(ctx, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, late, s, before.AddUserID)
				case "referenced_user_delete":
					_, err = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, before.AddUserID)
				}
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
			e := uoaudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user_override.delete", RootType: "user_override", RootID: before.RootID, ParentScheduleID: before.ParentScheduleID, TargetOrganizationID: before.TargetOrganizationID, TargetOrgResolution: "known_normal", BeforeContext: &before, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
			require.NoError(t, uoaudit.Append(ctx, tx, e))
			require.NoError(t, tx.Commit())
			require.NoError(t, <-done)
			require.Equal(t, 1, sd7Count(t, h))
			if mode == "schedule_delete" {
				require.Empty(t, sd6Effects(t, h, s))
			}
			if mode == "late_insert" {
				require.Equal(t, 1, serviceManagementCount(t, h, "user_overrides", late))
			}
		})
	}
}
