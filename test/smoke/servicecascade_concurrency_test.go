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
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

// CONTRACT ADAPTATION / NEW LEGAL EQUIVALENT COVERAGE: preserve mixed
// refusal and NOWAIT; a later committed Key must stale the original Preview.
func TestServiceCascadePG07LateExplicitKey(t *testing.T) {
	h := sd1Harness(t)
	root := h.UUID("service-b")
	credential := uuid.New()
	app := sd3App(h)
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
	stale := smokePlanConfirmation(t, h, sd3System(), input)
	smokeContract4Reject(t, h, app, sd3System(), []assignment.RawTarget{sd3Target(assignment.TargetTypeIntegrationKey, credential.String()), input[0]}, nil, ds.DeletionUnavailable)
	tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE`, root)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, tx)
	smokeContract4Reject(t, h, app, sd3System(), input, stale, ds.DeletionUnavailable)
	var safe uuid.UUID
	require.NoError(t, tx.QueryRow(`INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SD3 late','generic') RETURNING audit_resource_id`, credential, root).Scan(&safe))
	require.NoError(t, tx.Commit())
	smokeContract4Reject(t, h, app, sd3System(), input, stale, ds.DeletionDependencyChanged)
	smokeContract4Gate(t, h, app, sd3System(), input, "services", false, func(_ context.Context, pid int) { require.Positive(t, pid) })
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 1)
	f := effects[0]
	require.Equal(t, safe, *f.ResourceUUID)
	require.Equal(t, "CASCADE", f.Provenance)
	require.Equal(t, "fk_cascade", f.DeletionMechanism)
	require.Equal(t, "service_delete", f.Cause)
	t.Log("PARTIAL LEGAL COVERAGE: real writer/late Key/version recheck and legal DELETE barrier restored; mixed late EXPLICIT Key / old waiting semantics NOT REACHABLE")
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
	blocked := sd3Alert(t, h, root, "triggered")
	var blockedFavorite int64
	require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, h.UUID("user-a"), root).Scan(&blockedFavorite))
	smokeContract4Blocked(t, h, sd3App(h), []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
	blockedRoot, blockedCredential := root, credential
	root = smokeContract4Service(t, h, false)
	credential, safe := sd3Key(t, h, root)
	alert := sd3Alert(t, h, root, "closed")
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
	_, err = db.Exec(`CREATE SEQUENCE contract4_capture_hits; CREATE FUNCTION sd3_after_capture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contract4_capture_hits'); PERFORM pg_advisory_xact_lock(990093); RETURN OLD; END $$; CREATE TRIGGER sd3_after_capture BEFORE DELETE ON services FOR EACH ROW EXECUTE FUNCTION sd3_after_capture()`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := smokeDeleteAll(t, h, sd3App(h), ctx, []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)})
		done <- err
	}()
	sd3WaitBlocked(t, db, gatePID)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM contract4_capture_hits WHERE is_called`))
	require.Equal(t, 1, serviceManagementCount(t, h, "services", root))
	require.Zero(t, sd1Count(t, h, "committed"))
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
		require.Equal(t, "CASCADE", f.Provenance)
		switch f.ResourceType {
		case deleteaudit.IntegrationKey:
			require.Equal(t, safe, *f.ResourceUUID)
		case deleteaudit.Alert:
			require.Equal(t, alert, *f.ResourceNumericID)
		case deleteaudit.ServiceFavorite:
			require.Equal(t, favorite, *f.ResourceNumericID)
		}
	}
	require.Equal(t, map[string]bool{deleteaudit.IntegrationKey: true, deleteaudit.Alert: true, deleteaudit.ServiceFavorite: true}, types)
	require.Equal(t, 1, serviceManagementCount(t, h, "services", blockedRoot))
	require.Equal(t, 1, serviceManagementCount(t, h, "integration_keys", blockedCredential.String()))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM alerts WHERE id=$1 AND service_id=$2 AND status='triggered'`, blocked, blockedRoot))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_favorites WHERE id=$1 AND tgt_service_id=$2`, blockedFavorite, blockedRoot))
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	require.Zero(t, serviceManagementCount(t, h, "services", root))
	t.Log("independent lawful Fixture reached real DELETE and four native writer fences; original triggered Alert/Key/Favorite relation preserved")
}

func TestServiceCascadePG10OwnerAssignmentWaitUsesFreshSnapshot(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root, owner := h.UUID("service-b"), h.UUID("user-a")
	sd8Exec(t, h, `INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2)`, owner, root)
	input := []assignment.RawTarget{sd3Target(assignment.TargetTypeService, root)}
	confirmation := smokePlanConfirmation(t, h, sd3System(), input)
	tx, err := sd5ExternalDB(t, h, "").BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE`, owner)
	require.NoError(t, err)
	smokeContract4LockPID(t, h, tx)
	smokeContract4Reject(t, h, sd3App(h), sd3System(), input, confirmation, ds.DeletionUnavailable)
	_, err = tx.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, owner, h.UUID("org-c"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	fresh, err := smokeDeletionPreview(t, h, sd3System(), input)
	require.NoError(t, err)
	require.True(t, fresh.CanProceed)
	require.Equal(t, confirmation.ExpectedImpactVersion, fresh.ImpactVersion, "System favorite-owner scope metadata does not change the destructive dependency graph")
	smokeContract4Gate(t, h, sd3App(h), sd3System(), input, "services", false, func(ctx context.Context, pid int) {
		writer, err := sd5ExternalDB(t, h, "").BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = writer.Rollback() }()
		_, err = writer.ExecContext(ctx, `SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE NOWAIT`, owner)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55P03", pg.Code)
		require.Positive(t, pid)
	}, confirmation)
	effects := sd3Effects(t, h, root)
	require.Len(t, effects, 1)
	f := effects[0]
	require.Equal(t, owner, f.OwnerUserID.String())
	require.Equal(t, h.UUID("org-c"), f.OwnerOrganizationID.String())
	require.Equal(t, h.UUID("org-b"), f.TargetOrganizationID.String())
	require.Equal(t, 1, sd1Count(t, h, "committed"))
	require.Zero(t, serviceManagementCount(t, h, "services", root))
	require.NoError(t, db.Ping())
	t.Log("legacy assignment wait NOT REACHABLE; actual original ImpactVersion remained current after metadata-only scope change; fresh RC capture fenced later assignment writer and preserved independent Owner/Target organizations")
}
