package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditFreshOrganizationAndRetarget(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	u := sd7User(t, h)
	sd8Assign(t, h, u, harness.SmokeOrganizationID)
	cm, nr := sd8CMNR(t, h, u)
	otherCM, _ := sd8CMNR(t, h, u)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer writer.Close()
	tx, err := writer.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, u, h.UUID("org-b"))
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `UPDATE user_notification_rules SET contact_method_id=$2,delay_minutes=7 WHERE id=$1`, nr, otherCM)
	require.NoError(t, err)
	var newVersion string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT xmin::text FROM user_notification_rules WHERE id=$1`, nr).Scan(&newVersion))
	var writerPID int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
	done := make(chan error, 1)
	go func() {
		_, err := sd7App(h).Mutation().DeleteAll(permission.SystemContext(ctx, "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
		done <- err
	}()
	var deletePID int
	require.Eventually(t, func() bool {
		return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) LIMIT 1`, writerPID).Scan(&deletePID) == nil
	}, 5*time.Second, 10*time.Millisecond)
	sd8WaitLock(t, db, deletePID, writerPID)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	var target, actualParent, version string
	var delay int
	require.NoError(t, db.QueryRow(`SELECT target_organization_id FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u).Scan(&target))
	require.Equal(t, h.UUID("org-b"), target)
	require.NoError(t, db.QueryRow(`SELECT payload->'before'->>'parent_cm_id',(payload->'before'->>'delay_minutes')::integer,payload->'before'->>'row_version' FROM user_delete_audit_effects WHERE resource_type='notification_rule' AND resource_key=$1`, nr).Scan(&actualParent, &delay, &version))
	require.Equal(t, otherCM, actualParent)
	require.NotEqual(t, cm, actualParent)
	require.Equal(t, 7, delay)
	require.Equal(t, newVersion, version)
}

func TestUserDeleteAuditExternalDeadlock(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	u := sd7User(t, h)
	cm, _ := sd8CMNR(t, h, u)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	connector, err := sd8PGConnector(harness.DBURL(name))
	require.NoError(t, err)
	controlled := sql.OpenDB(connector)
	defer controlled.Close()
	app := sd7App(h)
	app.DB = controlled
	pidCh := make(chan int, 5)
	connector.afterEntry = func(ctx context.Context, c driver.Conn) error {
		pid, err := sd8NativePID(ctx, c)
		if err == nil {
			pidCh <- pid
		}
		return err
	}
	writer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer writer.Close()
	tx, err := writer.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var writerPID int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
	var locked uuid.UUID
	require.NoError(t, tx.QueryRow(`SELECT id FROM user_contact_methods WHERE id=$1 FOR UPDATE`, cm).Scan(&locked))
	done := make(chan error, 1)
	go func() {
		_, err := app.Mutation().DeleteAll(permission.SystemContext(ctx, "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
		done <- err
	}()
	var deletePID int
	select {
	case deletePID = <-pidCh:
	case <-ctx.Done():
		t.Fatal("delete entry not observed")
	}
	sd8WaitLock(t, db, deletePID, writerPID)
	_, writerErr := tx.ExecContext(ctx, `UPDATE users SET name='SYNTHETIC_PRIVATE' WHERE id=$1`, u)
	if writerErr == nil {
		require.NoError(t, tx.Commit())
	} else {
		var pg *pgconn.PgError
		require.True(t, errors.As(writerErr, &pg))
		require.Equal(t, "40P01", pg.Code)
		require.NoError(t, tx.Rollback())
		t.Log("external writer known SQLSTATE", pg.Code)
	}
	require.NoError(t, <-done)
	require.LessOrEqual(t, connector.begins.Load(), int64(6))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE payload::text LIKE '%SYNTHETIC_PRIVATE%'`))
	t.Log("native attempts including failure writer", connector.begins.Load())
}
