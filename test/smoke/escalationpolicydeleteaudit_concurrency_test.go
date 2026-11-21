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
	ds "github.com/target/goalert/deletionsafety"
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
		_, err := smokeDeleteAll(t, h, sd5App(h), ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)})
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
			input := []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)}
			confirmation := smokePlanConfirmation(t, h, sd3System(), input)
			app := sd5App(h)
			app.DB = sd5ExternalDB(t, h, isolation)
			var actual string
			require.NoError(t, app.DB.QueryRow(`SHOW transaction_isolation`).Scan(&actual))
			require.Equal(t, isolation, actual)
			tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			_, err = tx.Exec(`SELECT id FROM escalation_policies WHERE id=$1 FOR NO KEY UPDATE`, root)
			require.NoError(t, err)
			smokeContract4LockPID(t, h, tx)
			if isolation == "read committed" {
				smokeContract4Reject(t, h, app, sd3System(), input, confirmation, ds.DeletionUnavailable)
			} else {
				smokeContract4IsolationReject(t, h, app, input, confirmation)
			}
			action := uuid.NewString()
			_, err = tx.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
			require.NoError(t, err)
			require.NoError(t, tx.Commit())
			if isolation == "read committed" {
				smokeContract4Reject(t, h, app, sd3System(), input, confirmation, ds.DeletionDependencyChanged)
			} else {
				smokeContract4IsolationReject(t, h, app, input, confirmation)
			}
			if isolation != "read committed" {
				fresh, err := smokeDeletionConfirmation(t, h, sd3System(), input)
				require.NoError(t, err)
				smokeContract4IsolationReject(t, h, app, input, fresh)
			}
			// An explicit independent READ COMMITTED execution preserves the committed
			// Action's B2 receipt. No production isolation support or implicit retry changes.
			smokeContract4Gate(t, h, sd5App(h), sd3System(), input, "escalation_policies", false, func(ctx context.Context, pid int) {
				require.Positive(t, pid)
				var count int
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, action).Scan(&count))
				require.Equal(t, 1, count)
			})
			effects := sd5Effects(t, h, root)
			require.Len(t, effects, 2)
			found := false
			for _, f := range effects {
				if f.ResourceUUID != nil && f.ResourceUUID.String() == action {
					found = true
				}
			}
			require.True(t, found, "committed concurrent Action cannot be omitted")
			require.Equal(t, 1, sd5Count(t, h))
			require.Zero(t, serviceManagementCount(t, h, "escalation_policy_actions", action))
			t.Log("legacy root wait and RR/Serializable success NOT REACHABLE; RC committed child projection and Audit visibility verified")
		})
	}
}

func TestEscalationPolicyDeleteAuditTriggerDeadlock(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	root := sd5EP(t, h, harness.SmokeOrganizationID)
	step := sd5Step(t, h, root)
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)}
	confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	writers := sd5ExternalDB(t, h, "")
	old, err := writers.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = old.Rollback() }()
	_, err = old.Exec(`LOCK escalation_policy_steps IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, old)
	smokeContract4Reject(t, h, sd5App(h), sd3System(), input, confirmation, ds.DeletionUnavailable)
	require.NoError(t, old.Rollback())
	// The original Step/Root cycle is prevented by early EXCLUSIVE NOWAIT.
	// A task-owned BEFORE DELETE hook creates a real native deadlock only after
	// legal admission, without changing any Guard or production lock statement.
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	tx, err := writers.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SET LOCAL deadlock_timeout='50ms'`)
	require.NoError(t, err)
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`SELECT pg_advisory_xact_lock(990097,$1)`, pid)
	require.NoError(t, err)
	sd8Exec(t, h, fmt.Sprintf(`CREATE SEQUENCE contract4_deadlock_hits; CREATE FUNCTION contract4_deadlock() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contract4_deadlock_hits'); PERFORM pg_advisory_xact_lock(990097,%d); RETURN OLD; END $$;CREATE TRIGGER contract4_deadlock BEFORE DELETE ON escalation_policies FOR EACH ROW EXECUTE FUNCTION contract4_deadlock()`, pid))
	before, audit := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := sd5App(h).Mutation().DeleteAll(ctx, input, confirmation)
		done <- err
	}()
	defer func() {
		_ = tx.Rollback()
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("deadlock mutation did not finish")
		}
	}()
	sd3WaitBlocked(t, db, pid)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM contract4_deadlock_hits WHERE is_called`))
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	require.Equal(t, audit, smokeContract4SuccessState(t, h))
	// The opposite edge waits for the real Root lock held by the admitted delete.
	_, lockErr := tx.ExecContext(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, root)
	var pg *pgconn.PgError
	require.ErrorAs(t, lockErr, &pg)
	require.Equal(t, "40P01", pg.Code, "native deadlock detector must actually choose a victim")
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	<-finished
	require.Equal(t, 1, sd5Count(t, h))
	require.Len(t, sd5Effects(t, h, root), 1)
	require.Zero(t, serviceManagementCount(t, h, "escalation_policies", root))
	require.Zero(t, serviceManagementCount(t, h, "escalation_policy_steps", step))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT last_value FROM contract4_deadlock_hits`))
	t.Log("legacy Step/Root cycle NOT REACHABLE; legal BEFORE DELETE native cycle hit once, external victim SQLSTATE 40P01, sole delete and complete Audit committed atomically")
}

func TestEscalationPolicyDeleteAuditChildMembershipAfterWait(t *testing.T) {
	t.Parallel()
	h := sd1Harness(t)
	db := h.App().DB()
	smokeContract4Blocked(t, h, sd5App(h), []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, h.UUID("policy-b"))})
	root, other := sd5EP(t, h, harness.SmokeOrganizationID), sd5EP(t, h, harness.SmokeOrganizationID)
	step, otherStep := sd5Step(t, h, root), sd5Step(t, h, other)
	action := uuid.NewString()
	sd8Exec(t, h, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
	sd8Exec(t, h, `INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, h.UUID("user-a"), root)
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeEscalationPolicy, root)}
	confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, action, otherStep)
	require.NoError(t, err)
	_, err = tx.Exec(`DELETE FROM user_favorites WHERE user_id=$1 AND tgt_escalation_policy_id=$2`, h.UUID("user-a"), root)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, tx)
	smokeContract4Reject(t, h, sd5App(h), sd3System(), input, confirmation, ds.DeletionUnavailable)
	require.NoError(t, tx.Commit())
	smokeContract4Reject(t, h, sd5App(h), sd3System(), input, confirmation, ds.DeletionDependencyChanged)
	smokeContract4Gate(t, h, sd5App(h), sd3System(), input, "escalation_policies", false, func(ctx context.Context, pid int) {
		writer := sd5ExternalDB(t, h, "")
		lock, err := writer.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = lock.Rollback() }()
		_, err = lock.ExecContext(ctx, `SET LOCAL lock_timeout='80ms'`)
		require.NoError(t, err)
		_, err = lock.ExecContext(ctx, `SELECT id FROM escalation_policy_steps WHERE id=$1 FOR UPDATE NOWAIT`, step)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55P03", pg.Code)
		require.Positive(t, pid)
	})
	require.Len(t, sd5Effects(t, h, root), 1, "moved Action and pre-deleted Favorite are not this EP's cascade")
	require.Equal(t, 1, sd5Count(t, h))
	require.Zero(t, serviceManagementCount(t, h, "escalation_policies", root))
	var parent string
	require.NoError(t, db.QueryRow(`SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE id=$1`, action).Scan(&parent))
	require.Equal(t, otherStep, parent)
	t.Log("legacy child wait NOT REACHABLE; actual writer committed retarget/removal, stale confirmation rejected, fresh Guard/DELETE/Audit completed with exact B2 membership")
}
