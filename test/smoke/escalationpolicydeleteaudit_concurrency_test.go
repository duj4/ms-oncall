package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/test/smoke/harness"
)

func sd5ExternalDB(t *testing.T, h *harness.Harness, isolation string) *sql.DB {
	t.Helper()
	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	cfg, err := pgx.ParseConfig(harness.DBURL(database))
	require.NoError(t, err)
	if isolation != "" {
		cfg.RuntimeParams["default_transaction_isolation"] = isolation
	}
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestEscalationPolicyDeleteAuditCapturedLocks(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	writers := sd5ExternalDB(t, h, "")
	root, other := sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
	step, otherStep := sd5Step(t, h, root), sd5Step(t, h, other)
	action := uuid.NewString()
	_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, h.UUID("user-a"), root)
	require.NoError(t, err)
	owner := uuid.NewString()
	_, err = db.Exec(`INSERT INTO users(id,name) VALUES($1,'SD5 late favorite')`, owner)
	require.NoError(t, err)
	gate, err := writers.Conn(t.Context())
	require.NoError(t, err)
	defer gate.Close()
	var gatePID int
	require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID))
	_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_lock(990095,$1)`, gatePID)
	require.NoError(t, err)
	defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990095,$1)`, gatePID) }()
	_, err = db.Exec(fmt.Sprintf(`CREATE FUNCTION sd5_capture_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(990095,%d); RETURN OLD; END $$; CREATE TRIGGER sd5_capture_gate BEFORE DELETE ON escalation_policies FOR EACH ROW EXECUTE FUNCTION sd5_capture_gate()`, gatePID))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd5App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, gatePID)
	for _, tc := range []struct {
		name, q string
		args    []any
	}{
		{"EP delete", `DELETE FROM escalation_policies WHERE id=$1`, []any{root}},
		{"step insert", `INSERT INTO escalation_policy_steps(escalation_policy_id) VALUES($1)`, []any{root}},
		{"step update", `UPDATE escalation_policy_steps SET delay=delay+1 WHERE id=$1`, []any{step}},
		{"step delete", `DELETE FROM escalation_policy_steps WHERE id=$1`, []any{step}},
		{"action insert", `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, []any{step, owner}},
		{"action delete", `DELETE FROM escalation_policy_actions WHERE id=$1`, []any{action}},
		{"action retarget", `UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, []any{action, otherStep}},
		{"favorite insert", `INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, []any{owner, root}},
		{"favorite unset", `DELETE FROM user_favorites WHERE user_id=$1 AND tgt_escalation_policy_id=$2`, []any{h.UUID("user-a"), root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := writers.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			_, err = tx.Exec(`SET LOCAL lock_timeout='80ms'`)
			require.NoError(t, err)
			_, err = tx.Exec(tc.q, tc.args...)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "55P03", pg.Code)
		})
	}
	_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_unlock(990095,$1)`, gatePID)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.Len(t, sd5Effects(t, h, root), 3)
	require.Equal(t, 1, sd5Count(t, h))
	require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", otherStep))
}

func TestEscalationPolicyDeleteAuditActionWaitAndIsolation(t *testing.T) {
	t.Parallel()
	for _, isolation := range []string{"read committed", "repeatable read", "serializable"} {
		t.Run(isolation, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, root)
			writers := sd5ExternalDB(t, h, "")
			tx, err := writers.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var pid int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
			// No parent update: RR can retain an old child snapshot while waiting on
			// the root. PostgreSQL FK cascade crosschecks must abort such a delete.
			_, err = tx.Exec(`SELECT id FROM escalation_policies WHERE id=$1 FOR NO KEY UPDATE`, root)
			require.NoError(t, err)
			app := sd5App(h)
			app.DB = sd5ExternalDB(t, h, isolation)
			ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
			action := uuid.NewString()
			_, err = tx.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
			require.NoError(t, err)
			require.NoError(t, tx.Commit())
			require.NoError(t, <-done)
			effects := sd5Effects(t, h, root)
			require.Len(t, effects, 2)
			found := false
			for _, f := range effects {
				if f.ResourceUUID != nil && f.ResourceUUID.String() == action {
					found = true
				}
			}
			require.True(t, found, "committed concurrent action cannot be silently omitted under an old snapshot")
			require.Equal(t, 1, sd5Count(t, h))
		})
	}
}

func TestEscalationPolicyDeleteAuditTriggerDeadlock(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	root := sd5EP(t, h, harness.SmokeOrganizationID)
	_ = sd5Step(t, h, root)
	writers := sd5ExternalDB(t, h, "")
	tx, err := writers.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`LOCK escalation_policy_steps IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd5App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	// Actual cycle: EP delete owns Root and waits for Step table; this session
	// owns the trigger's table lock and now waits for Root. Either native victim
	// is valid. The audit must still match the sole committed business delete.
	_, lockErr := tx.ExecContext(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, root)
	if lockErr != nil {
		var pg *pgconn.PgError
		require.ErrorAs(t, lockErr, &pg)
		require.Equal(t, "40P01", pg.Code)
	}
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.Equal(t, 1, sd5Count(t, h))
	require.Len(t, sd5Effects(t, h, root), 1)
	var observations int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM escalation_policy_delete_audit_events WHERE record_kind='attempt_observation'`).Scan(&observations))
	require.True(t, lockErr != nil || observations > 0, "native deadlock victim must be evidenced")
	t.Logf("native Step/Root deadlock: external victim=%t, business observations=%d", lockErr != nil, observations)
}

func TestEscalationPolicyDeleteAuditChildMembershipAfterWait(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	root, other := sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
	step, otherStep := sd5Step(t, h, root), sd5Step(t, h, other)
	action := uuid.NewString()
	_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, h.UUID("user-a"), root)
	require.NoError(t, err)
	tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, action, otherStep)
	require.NoError(t, err)
	_, err = tx.Exec(`DELETE FROM user_favorites WHERE user_id=$1 AND tgt_escalation_policy_id=$2`, h.UUID("user-a"), root)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd5App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	require.Len(t, sd5Effects(t, h, root), 1, "moved Action and pre-deleted Favorite are not this EP's cascade")
	var parent string
	require.NoError(t, db.QueryRow(`SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE id=$1`, action).Scan(&parent))
	require.Equal(t, otherStep, parent)
}
