package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditFreshOrganizationAndRetarget(t *testing.T) {
	for _, mode := range []string{"organization_and_retarget", "metadata_only"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			u := smokeOwnedUser(t, h)
			cm, nr := sd8CMNR(t, h, u)
			otherCM, _ := sd8CMNR(t, h, u)
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			ctx, cancel := context.WithTimeout(permission.SystemContext(t.Context(), "Engine"), 20*time.Second)
			defer cancel()
			confirmation, err := smokeDeletionConfirmation(t, h, ctx, input)
			require.NoError(t, err)
			require.NotNil(t, confirmation)
			before, auditBefore := smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
			tx, err := sd5ExternalDB(t, h, "").BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			writerPID := smokeContract4LockPID(t, h, tx)
			target, actualCM := harness.SmokeOrganizationID, cm
			if mode == "organization_and_retarget" {
				target, actualCM = h.UUID("org-b"), otherCM
				_, err = tx.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, u, target)
				require.NoError(t, err)
			}
			_, err = tx.ExecContext(ctx, `UPDATE user_notification_rules SET contact_method_id=$2,delay_minutes=7 WHERE id=$1`, nr, actualCM)
			require.NoError(t, err)
			var newVersion string
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT xmin::text FROM user_notification_rules WHERE id=$1`, nr).Scan(&newVersion))
			ok, err := sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
			smokeDeletionCode(t, err, ds.DeletionUnavailable)
			require.False(t, ok, "current NOWAIT refuses rather than taking the legacy wait path")
			require.Equal(t, before, smokeUserBusinessState(t, h))
			require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
			require.NoError(t, tx.Commit())
			current, err := smokeDeletionPreview(t, h, ctx, input)
			require.NoError(t, err)
			require.True(t, current.Complete && current.CanProceed)
			if mode == "organization_and_retarget" {
				require.NotEqual(t, confirmation.ExpectedImpactVersion, current.ImpactVersion, "User target scope is part of its own fingerprint")
				afterWriter := smokeUserBusinessState(t, h)
				ok, err = sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
				smokeDeletionCode(t, err, ds.DeletionDependencyChanged)
				require.False(t, ok)
				require.Equal(t, afterWriter, smokeUserBusinessState(t, h))
				require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
				confirmation, err = smokeDeletionConfirmation(t, h, ctx, input)
				require.NoError(t, err)
			} else {
				require.Equal(t, confirmation.ExpectedImpactVersion, current.ImpactVersion, "delay-only metadata does not change the destructive graph")
			}
			ok, err = sd7App(h).Mutation().DeleteAll(ctx, input, confirmation)
			require.NoError(t, err)
			require.True(t, ok)
			var auditOrg, parent, version string
			var delay int
			require.NoError(t, db.QueryRow(`SELECT target_organization_id FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u).Scan(&auditOrg))
			require.Equal(t, target, auditOrg)
			require.NoError(t, db.QueryRow(`SELECT payload->'before'->>'parent_cm_id',(payload->'before'->>'delay_minutes')::integer,payload->'before'->>'row_version' FROM user_delete_audit_effects WHERE resource_type='notification_rule' AND resource_key=$1`, nr).Scan(&parent, &delay, &version))
			require.Equal(t, actualCM, parent)
			require.Equal(t, 7, delay)
			require.Equal(t, newVersion, version)
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.Equal(t, sd8Scalar(t, h, `SELECT effect_count FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u), sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
			t.Logf("writer PID=%d mode=%s: NOWAIT refusal preserved business/Audit; writer committed; fresh User scope/NR parent/delay/xmin recorded", writerPID, mode)
		})
	}
}

func TestUserDeleteAuditExternalDeadlock(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	u := sd7User(t, h)
	cm, nr := sd8CMNR(t, h, u)
	input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
	before, auditBefore := smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
	_, err := smokeDeletionPreview(t, h, sd3System(), input)
	smokeDeletionCode(t, err, ds.DeletionUnavailable)
	ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, nil)
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, before, smokeUserBusinessState(t, h))
	require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
	sd8Assign(t, h, u, harness.SmokeOrganizationID)
	// Preserve the original CM-first contention after fixing only identity.
	confirmation, err := smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	writers := sd5ExternalDB(t, h, "")
	old, err := writers.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = old.Rollback() }()
	var locked string
	require.NoError(t, old.QueryRow(`SELECT id FROM user_contact_methods WHERE id=$1 FOR UPDATE`, cm).Scan(&locked))
	smokeContract4LockPID(t, h, old)
	before, auditBefore = smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
	ok, err = sd7App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
	smokeDeletionCode(t, err, ds.DeletionUnavailable)
	require.False(t, ok)
	require.Equal(t, before, smokeUserBusinessState(t, h))
	require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
	require.NoError(t, old.Rollback())
	var sessionSafe uuid.UUID
	require.NoError(t, db.QueryRow(`INSERT INTO auth_user_sessions(id,user_id,user_agent) VALUES($1,$2,'SYNTHETIC_PRIVATE') RETURNING audit_resource_id`, uuid.New(), u).Scan(&sessionSafe))
	confirmation, err = smokeDeletionConfirmation(t, h, sd3System(), input)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(permission.SystemContext(t.Context(), "Engine"), 20*time.Second)
	defer cancel()
	tx, err := writers.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SET LOCAL deadlock_timeout='500ms'`)
	require.NoError(t, err)
	writerPID := smokeContract4LockPID(t, h, tx)
	_, err = tx.Exec(`SELECT pg_advisory_xact_lock(990098,$1)`, writerPID)
	require.NoError(t, err)
	sd8Exec(t, h, fmt.Sprintf(`CREATE SEQUENCE safety_user_deadlock_hits;
 CREATE FUNCTION safety_user_deadlock() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('safety_user_deadlock_hits'); PERFORM pg_advisory_xact_lock(990098,%d); RETURN OLD; END $$;
 CREATE TRIGGER safety_user_deadlock BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION safety_user_deadlock()`, writerPID))
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	connector, err := sd8PGConnector(harness.DBURL(name))
	require.NoError(t, err)
	connector.beforeDelete = func(ctx context.Context, c driver.Conn) error {
		_, e := c.(driver.ExecerContext).ExecContext(ctx, `SET LOCAL deadlock_timeout='10s'`, nil)
		return e
	}
	controlled := sql.OpenDB(connector)
	defer controlled.Close()
	app := sd7App(h)
	app.DB = controlled
	before, auditBefore = smokeUserBusinessState(t, h), safetySmokeSuccessState(t, h)
	done, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		ok, e := app.Mutation().DeleteAll(ctx, input, confirmation)
		if e == nil && !ok {
			e = fmt.Errorf("guarded delete returned false")
		}
		done <- e
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
	sd3WaitBlocked(t, db, writerPID)
	var deletePID int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, writerPID).Scan(&deletePID))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT last_value FROM safety_user_deadlock_hits WHERE is_called`))
	require.Equal(t, before, smokeUserBusinessState(t, h))
	require.Equal(t, auditBefore, safetySmokeSuccessState(t, h))
	writerDone := make(chan error, 1)
	go func() {
		_, e := tx.ExecContext(ctx, `UPDATE users SET name='SYNTHETIC_WRITER_ROLLBACK' WHERE id=$1`, u)
		writerDone <- e
	}()
	require.Eventually(t, func() bool {
		var cycle bool
		e := db.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2)) AND $2=ANY(pg_blocking_pids($1))`, writerPID, deletePID).Scan(&cycle)
		return e == nil && cycle
	}, 400*time.Millisecond, 5*time.Millisecond, "both native edges must exist before PostgreSQL chooses the external victim")
	var pg *pgconn.PgError
	require.ErrorAs(t, <-writerDone, &pg)
	require.Equal(t, "40P01", pg.Code)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	<-finished
	require.EqualValues(t, 1, connector.begins.Load(), "external victim requires no business replay")
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, cm))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE audit_resource_id=$1`, sessionSafe))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_session' AND resource_key=$1`, sessionSafe.String()))
	require.Equal(t, sd8Scalar(t, h, `SELECT effect_count FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u), sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE payload::text LIKE '%SYNTHETIC_%'`))
	t.Logf("legacy CM/User cycle NOT REACHABLE under NOWAIT; native cycle delete PID=%d -> writer PID=%d (advisory), writer -> delete (User row), both pg_blocking_pids edges observed; external victim SQLSTATE=40P01 rolled back; DELETE hit=1, Begin=1, User/CM/NR/Session and B2 committed atomically", deletePID, writerPID)
}
