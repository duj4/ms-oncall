package smoke

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestServiceCascadePG07LateExplicitKey(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	credential := uuid.New()
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE`, root)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, credential.String()), sd3Target(assignment.TargetTypeService, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	var safe uuid.UUID
	require.NoError(t, tx.QueryRow(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SD3 late','generic') RETURNING audit_resource_id`, credential, root).Scan(&safe))
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 1)
	f := effects[0]
	require.Equal(t, safe, *f.ResourceUUID)
	require.Equal(t, "EXPLICIT", f.Provenance)
	require.Equal(t, "fk_cascade", f.DeletionMechanism)
	require.Equal(t, "service_delete", f.Cause)
}

func sd3WaitExactBlock(t *testing.T, observer *sql.Conn, blocker, waiter int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var blocked bool
		err := observer.QueryRowContext(t.Context(), `SELECT $1=ANY(pg_blocking_pids($2))`, blocker, waiter).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond)
}

func TestServiceCascadePG05PG06CapturedLocksFenceExternalWrites(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	// These represent external sessions. Using the application's underlying
	// bounded pool for every waiter would measure pool starvation instead of
	// PostgreSQL row locks and prevent the application from completing.
	var database string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&database))
	cfg, err := pgx.ParseConfig(harness.DBURL(database))
	require.NoError(t, err)
	writers := stdlib.OpenDB(*cfg)
	defer writers.Close()
	writers.SetMaxOpenConns(4)
	root := h.UUID("service-b")
	credential, _ := sd3Key(t, h, root)
	alert := sd3Alert(t, h, root, "triggered")
	var favorite int64
	require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, h.UUID("user-a"), root).Scan(&favorite))
	gate, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer gate.Close()
	var gatePID int
	require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID))
	_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_lock(990093)`)
	require.NoError(t, err)
	defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990093)`) }()
	_, err = db.Exec(`CREATE FUNCTION sd3_after_capture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(990093); RETURN OLD; END $$; CREATE TRIGGER sd3_after_capture BEFORE DELETE ON services FOR EACH ROW EXECUTE FUNCTION sd3_after_capture()`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, gatePID)
	var businessPID int
	require.NoError(t, db.QueryRow(`SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&businessPID))
	type operation struct {
		q         string
		args      []any
		insertion bool
	}
	operations := []operation{
		{`UPDATE integration_keys SET service_id=$2 WHERE id=$1`, []any{credential, h.UUID("service-a")}, false},
		{`DELETE FROM alerts WHERE id=$1`, []any{alert}, false},
		{`UPDATE user_favorites SET tgt_service_id=$2 WHERE id=$1`, []any{favorite, h.UUID("service-a")}, false},
		{`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SD3 fenced','generic')`, []any{uuid.New(), root}, true},
	}
	type pending struct {
		conn      *sql.Conn
		done      chan error
		insertion bool
	}
	var waits []pending
	for i, op := range operations {
		conn, err := writers.Conn(ctx)
		require.NoError(t, err)
		defer conn.Close()
		var pid int
		require.NoError(t, conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
		finished := make(chan error, 1)
		go func(op operation, c *sql.Conn) { _, err := c.ExecContext(ctx, op.q, op.args...); finished <- err }(op, conn)
		t.Logf("checking PostgreSQL retained lock for external operation %d", i)
		sd3WaitExactBlock(t, gate, businessPID, pid)
		waits = append(waits, pending{conn, finished, op.insertion})
	}
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_unlock(990093)`)
	require.NoError(t, err)
	require.NoError(t, <-done)
	for _, w := range waits {
		err := <-w.done
		if w.insertion {
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23503", pg.Code)
		} else {
			require.NoError(t, err)
		}
	}
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 3)
	types := map[string]bool{}
	for _, f := range effects {
		types[f.ResourceType] = true
	}
	require.Equal(t, map[string]bool{deleteaudit.IntegrationKey: true, deleteaudit.Alert: true, deleteaudit.ServiceFavorite: true}, types)
}

func TestServiceCascadePG10OwnerAssignmentWaitUsesFreshSnapshot(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := h.UUID("service-b")
	owner := h.UUID("user-a")
	_, err := db.Exec(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2)`, owner, root)
	require.NoError(t, err)
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	defer conn.Close()
	tx, err := conn.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	_, err = tx.Exec(`SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE`, owner)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sd3App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, pid)
	_, err = tx.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, owner, h.UUID("org-c"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	require.NoError(t, <-done)
	f := sd3Effects(t, h, root)[0]
	require.Equal(t, h.UUID("org-c"), f.OwnerOrganizationID.String())
	require.Equal(t, h.UUID("org-b"), f.TargetOrganizationID.String())
}
