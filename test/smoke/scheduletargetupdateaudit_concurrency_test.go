package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/schedule/rule"
)

// PostgreSQL's observed blocker graph is the barrier; elapsed sleep is never
// taken as evidence that a row/root lock has been acquired.
func u03WaitBlock(t *testing.T, db *sql.DB, blocker int) int {
	t.Helper()
	var pid int
	var query, event string
	require.Eventually(t, func() bool {
		return db.QueryRow(`SELECT pid,query,coalesce(wait_event,'') FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) ORDER BY pid LIMIT 1`, blocker).Scan(&pid, &query, &event) == nil
	}, 10*time.Second, 10*time.Millisecond)
	t.Logf("actual lock graph: waiter=%d blocker=%d wait_event=%s SQL=%s", pid, blocker, event, query)
	return pid
}

func TestScheduleTargetUpdateNativeWaitedRuleWriters(t *testing.T) {
	for _, mode := range []string{"retarget_into", "retarget_out", "move_schedule_out", "delete_many"} {
		t.Run(mode, func(t *testing.T) {
			h := u03Harness(t)
			db := h.App().DB()
			root, other := h.UUID("schedule-a"), h.UUID("schedule-c")
			target, different := u03Target(t, h, "user"), u03Target(t, h, "rotation")
			initial := target
			if mode == "retarget_into" {
				initial = different
			}
			id := u03Rule(t, h, root, initial, 0)
			writer, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			var writerPID int
			require.NoError(t, writer.QueryRow(`SELECT pg_backend_pid() FROM schedule_rules WHERE id=$1 FOR UPDATE`, id).Scan(&writerPID))
			ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := u03App(h).Mutation().UpdateScheduleTarget(ctx, graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
				done <- err
			}()
			u03WaitBlock(t, db, writerPID)
			require.Zero(t, u03Count(t, h))
			if mode == "delete_many" {
				err = u03App(h).RuleStore.DeleteManyTx(sd3System(), writer, []string{id})
			} else {
				updated := rule.NewAlwaysActive(root, &target)
				updated.ID = id
				if mode == "retarget_out" {
					updated.Target = &different
				}
				if mode == "move_schedule_out" {
					updated.ScheduleID = other
				}
				err = u03App(h).RuleStore.UpdateTx(sd3System(), writer, updated)
			}
			require.NoError(t, err)
			require.NoError(t, writer.Commit())
			require.NoError(t, <-done)
			if mode == "retarget_into" {
				u03AssertEffects(t, h, root, target, []string{id})
			} else {
				require.Zero(t, u03Count(t, h), "post-wait fresh read must not invent a selected-target deletion")
				if mode != "delete_many" {
					require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
				} else {
					require.NotContains(t, u03IDs(t, h, "schedule_rules"), id)
				}
			}
		})
	}
}

func TestScheduleTargetUpdateNativeCapturedLocks(t *testing.T) {
	for _, mode := range []string{"insert", "target_only", "schedule_move", "delete_many", "schedule_root_delete", "user_root_delete", "rotation_root_delete"} {
		t.Run(mode, func(t *testing.T) {
			h := u03Harness(t)
			db := h.App().DB()
			root, other := h.UUID("schedule-a"), h.UUID("schedule-c")
			kind := "user"
			if mode == "rotation_root_delete" {
				kind = "rotation"
			}
			target, different := u03Target(t, h, kind), u03Target(t, h, "rotation")
			deleted := u03Rule(t, h, root, target, 0)
			keep := u03Rule(t, h, root, different, 0)
			// Store prepared statements and the writer Tx must share the same
			// sql.DB handle; Conn/BeginTx still create independent PG sessions.
			writers := db
			gate, err := writers.Conn(t.Context())
			require.NoError(t, err)
			defer gate.Close()
			var gatePID int
			require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID))
			_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_lock(990306,$1)`, gatePID)
			require.NoError(t, err)
			defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990306,$1)`, gatePID) }()
			_, err = db.Exec(fmt.Sprintf(`CREATE FUNCTION u03_delete_gate() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(990306,%d); RETURN OLD; END$$; CREATE TRIGGER u03_delete_gate BEFORE DELETE ON schedule_rules FOR EACH ROW EXECUTE FUNCTION u03_delete_gate()`, gatePID))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(sd3System(), 25*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := u03App(h).Mutation().UpdateScheduleTarget(ctx, graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
				done <- err
			}()
			updatePID := u03WaitBlock(t, db, gatePID)
			require.Zero(t, u03Count(t, h), "success witness is not visible before business commit")
			writer, err := writers.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			var writerPID int
			require.NoError(t, writer.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
			writerDone := make(chan error, 1)
			go func() {
				var err error
				r := rule.NewAlwaysActive(root, &target)
				r.ID = keep
				switch mode {
				case "insert":
					_, err = u03App(h).RuleStore.CreateRuleTx(ctx, writer, r)
				case "target_only":
					err = u03App(h).RuleStore.UpdateTx(ctx, writer, r)
				case "schedule_move":
					r.ScheduleID = other
					r.Target = &different
					err = u03App(h).RuleStore.UpdateTx(ctx, writer, r)
				case "delete_many":
					err = u03App(h).RuleStore.DeleteManyTx(ctx, writer, []string{keep})
				case "schedule_root_delete":
					_, err = writer.ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, root)
				case "user_root_delete":
					_, err = writer.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, target.ID)
				case "rotation_root_delete":
					_, err = writer.ExecContext(ctx, `DELETE FROM rotations WHERE id=$1`, target.ID)
				}
				writerDone <- err
			}()
			blockedPID := u03WaitBlock(t, db, updatePID)
			require.Equal(t, writerPID, blockedPID)
			_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_unlock(990306,$1)`, gatePID)
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.NoError(t, <-writerDone)
			// Roll back the competing writer after its real statement completes;
			// its pending deletes/retargets must not contaminate Update's receipt.
			require.NoError(t, writer.Rollback())
			require.Equal(t, 1, u03Count(t, h))
			u03AssertEffects(t, h, root, target, []string{deleted})
			require.Contains(t, u03IDs(t, h, "schedule_rules"), keep)
			t.Log("Update committed; competing native Store/FK statement completed and explicitly rolled back")
		})
	}
}

func TestScheduleTargetUpdateNativeScheduleDeleteWins(t *testing.T) {
	h := u03Harness(t)
	db := h.App().DB()
	root := h.UUID("schedule-a")
	target := u03Target(t, h, "user")
	u03Rule(t, h, root, target, 0)
	tx, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid() FROM schedules WHERE id=$1 FOR UPDATE`, root).Scan(&pid))
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := u03App(h).Mutation().UpdateScheduleTarget(ctx, graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
		done <- err
	}()
	u03WaitBlock(t, db, pid)
	_, err = tx.Exec(`DELETE FROM schedules WHERE id=$1`, root)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.Error(t, <-done)
	require.Zero(t, u03Count(t, h))
	var raw string
	require.NoError(t, db.QueryRow(`SELECT effects::text FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget'`).Scan(&raw))
	require.Equal(t, "[]", raw)
}
