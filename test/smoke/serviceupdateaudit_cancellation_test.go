package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

// Adapted from the independent R1 RED probe. Only timing/acknowledgement is a
// driver seam; transactions, locks, persisted rows and the single-connection
// pool are real PostgreSQL. This is not a network-disconnect experiment.
type serviceAuditCancelConnector struct {
	base                           driver.Connector
	cancel                         context.CancelFunc
	mode                           string
	release, started, finished     chan struct{}
	once                           sync.Once
	begins, businessCommits        atomic.Int64
	released, failureBeforeRelease atomic.Bool
}

func (c *serviceAuditCancelConnector) unblock() {
	c.once.Do(func() { c.released.Store(true); close(c.release) })
}
func (c *serviceAuditCancelConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *serviceAuditCancelConnector) Connect(ctx context.Context) (driver.Conn, error) {
	x, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &serviceAuditCancelConn{Conn: x, c: c}, nil
}

type serviceAuditCancelConn struct {
	driver.Conn
	c     *serviceAuditCancelConnector
	first bool
}

func (c *serviceAuditCancelConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	x, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	c.first = c.c.begins.Add(1) == 1
	return &serviceAuditCancelTx{Tx: x, c: c.c, first: c.first}, nil
}
func (c *serviceAuditCancelConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	s, err := c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return &serviceAuditCancelStmt{Stmt: s, c: c, q: q}, nil
}

type serviceAuditCancelStmt struct {
	driver.Stmt
	c *serviceAuditCancelConn
	q string
}

func (s *serviceAuditCancelStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	r, err := s.Stmt.(driver.StmtExecContext).ExecContext(ctx, args)
	if err == nil && s.c.first && s.c.c.mode == "cancel_after_write" && strings.Contains(s.q, "UPDATE services") {
		s.c.c.cancel()
	}
	return r, err
}
func (s *serviceAuditCancelStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
}
func (c *serviceAuditCancelConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *serviceAuditCancelConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(q, "INSERT INTO service_update_audit_events") && len(args) == 15 && args[12].Value != "committed" && !c.c.released.Load() {
		c.c.failureBeforeRelease.Store(true)
	}
	r, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err == nil && c.first && c.c.mode != "commit_started" && c.c.mode != "commit_stalled" {
		if strings.Contains(q, "INSERT INTO service_update_audit_events") || c.c.mode == "cancel_after_write" && strings.Contains(q, "UPDATE services") {
			c.c.cancel()
		}
	}
	return r, err
}

type serviceAuditCancelTx struct {
	driver.Tx
	c     *serviceAuditCancelConnector
	first bool
}

func (t *serviceAuditCancelTx) Commit() error {
	if !t.first {
		return t.Tx.Commit()
	}
	t.c.businessCommits.Add(1)
	if t.c.mode == "commit_started" {
		// Real COMMIT precedes the synthetic lost/delayed acknowledgement.
		if err := t.Tx.Commit(); err != nil {
			return err
		}
		close(t.c.started)
		<-t.c.release
		close(t.c.finished)
		return errors.New("SYNTHETIC_DELAYED_COMMIT_ACK")
	}
	if t.c.mode == "commit_stalled" {
		close(t.c.started)
		<-t.c.release
		defer close(t.c.finished)
		if err := t.Tx.Rollback(); err != nil {
			return err
		}
		return errors.New("SYNTHETIC_STALLED_COMMIT")
	}
	return t.Tx.Commit()
}
func (t *serviceAuditCancelTx) Rollback() error {
	if t.first {
		close(t.c.started)
		<-t.c.release
		defer close(t.c.finished)
	}
	return t.Tx.Rollback()
}

type serviceAuditCancelResult struct {
	ok  bool
	err error
}

func serviceAuditCancellationApp(t *testing.T, mode string, max int) (*harness.Harness, *graphqlapp.App, context.Context, context.CancelFunc, *serviceAuditCancelConnector, *sql.DB) {
	t.Helper()
	h := serviceAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(servicePlatformAdminContext(t, h))
	c := &serviceAuditCancelConnector{base: stdlib.GetConnector(*cfg), cancel: cancel, mode: mode, release: make(chan struct{}), started: make(chan struct{}), finished: make(chan struct{})}
	db := sql.OpenDB(c)
	db.SetMaxOpenConns(max)
	t.Cleanup(func() {
		cancel()
		c.unblock()
		select {
		case <-c.finished:
		case <-time.After(5 * time.Second):
			t.Error("test transaction did not finish")
		}
		require.Eventually(t, func() bool { return db.Stats().InUse == 0 }, 5*time.Second, time.Millisecond)
		require.NoError(t, db.Close())
	})
	store, err := service.NewStore(context.Background(), db)
	require.NoError(t, err)
	return h, &graphqlapp.App{DB: db, ServiceStore: store}, ctx, cancel, c, db
}

func serviceAuditStartCancellation(a *graphqlapp.App, ctx context.Context, id string) <-chan serviceAuditCancelResult {
	done := make(chan serviceAuditCancelResult, 1)
	go func() {
		description := "synthetic cancellation update"
		ok, err := a.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: id, Description: &description})
		done <- serviceAuditCancelResult{ok, err}
	}()
	return done
}

func serviceAuditWaitStarted(t *testing.T, c *serviceAuditCancelConnector) {
	t.Helper()
	select {
	case <-c.started:
	case <-time.After(5 * time.Second):
		t.Fatal("driver finalization not entered")
	}
}

func serviceAuditAssertLocked(t *testing.T, h *harness.Harness) {
	t.Helper()
	probe, err := h.App().DB().Begin()
	require.NoError(t, err)
	_, err = probe.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("service-b"))
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	require.Equal(t, "55P03", pg.Code)
	require.NoError(t, probe.Rollback())
}

func TestServiceUpdateAuditCancellationReleaseBarrier(t *testing.T) {
	for _, tc := range []struct {
		mode string
		max  int
	}{{"cancel_staged", 1}, {"cancel_staged", 4}, {"cancel_after_write", 1}} {
		t.Run(tc.mode+"_pool"+string(rune('0'+tc.max)), func(t *testing.T) {
			h, a, ctx, _, c, db := serviceAuditCancellationApp(t, tc.mode, tc.max)
			done := serviceAuditStartCancellation(a, ctx, h.UUID("service-b"))
			serviceAuditWaitStarted(t, c)
			select {
			case <-done:
				t.Fatal("returned before connection-release barrier")
			case <-time.After(80 * time.Millisecond):
			}
			require.EqualValues(t, 1, c.begins.Load(), "no independent failure transaction before release, even with spare connections")
			require.Equal(t, 1, db.Stats().InUse)
			serviceAuditAssertLocked(t, h)
			require.Zero(t, serviceAuditCount(t, h))
			if tc.max > 1 {
				// An unrelated mutation can use spare capacity, but this attempt's
				// failure append must still wait for its own connection's release.
				description := "concurrent unrelated update"
				ok, err := a.Mutation().UpdateService(servicePlatformAdminContext(t, h), graphql2.UpdateServiceInput{ID: h.UUID("service-c"), Description: &description})
				require.NoError(t, err)
				require.True(t, ok)
			}
			c.unblock()
			select {
			case r := <-done:
				require.False(t, r.ok)
				require.Error(t, r.err)
				require.NotContains(t, r.err.Error(), "audit persistence unavailable")
			case <-time.After(5 * time.Second):
				t.Fatal("failure append did not complete after rollback")
			}
			require.False(t, c.failureBeforeRelease.Load())
			require.Zero(t, c.businessCommits.Load(), "cancelled business transaction must never enter driver Commit")
			var committed, failed int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome<>'committed') FROM service_update_audit_events WHERE service_id=$1`, h.UUID("service-b")).Scan(&committed, &failed))
			require.Zero(t, committed)
			require.Equal(t, 1, failed)
			var description string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&description))
			require.Empty(t, description)
			t.Log("GREEN: real PostgreSQL rollback releases connection before durable failure append; cancelled business write and staged success witness absent")
		})
	}
}

func TestServiceUpdateAuditCancellationReleaseTimeout(t *testing.T) {
	h, a, ctx, _, c, _ := serviceAuditCancellationApp(t, "cancel_staged", 4)
	var out bytes.Buffer
	logger := log.NewLogger()
	logger.SetOutput(&out)
	ctx = log.WithLogger(ctx, logger)
	start := time.Now()
	done := serviceAuditStartCancellation(a, ctx, h.UUID("service-b"))
	serviceAuditWaitStarted(t, c)
	select {
	case r := <-done:
		require.False(t, r.ok)
		require.ErrorContains(t, r.err, "audit persistence unavailable")
	case <-time.After(4 * time.Second):
		t.Fatal("resource wait was not bounded")
	}
	require.Less(t, time.Since(start), 4*time.Second)
	require.Contains(t, out.String(), "resource_release_unconfirmed")
	require.EqualValues(t, 1, c.begins.Load(), "do not append ahead of an unconfirmed release even with spare connections")
	require.Zero(t, serviceAuditCount(t, h))
	serviceAuditAssertLocked(t, h)
	c.unblock()
	// No retry/replay or claim of a durable failure record after timeout.
}

func TestServiceUpdateAuditCommitAlreadyStartedCancellation(t *testing.T) {
	h, a, ctx, cancel, c, _ := serviceAuditCancellationApp(t, "commit_started", 1)
	done := serviceAuditStartCancellation(a, ctx, h.UUID("service-b"))
	serviceAuditWaitStarted(t, c)
	cancel()
	select {
	case <-done:
		t.Fatal("failure append bypassed in-flight Commit")
	case <-time.After(80 * time.Millisecond):
	}
	require.EqualValues(t, 1, c.begins.Load())
	c.unblock()
	select {
	case r := <-done:
		require.False(t, r.ok)
		require.Error(t, r.err)
		require.NotContains(t, r.err.Error(), "audit persistence unavailable")
	case <-time.After(5 * time.Second):
		t.Fatal("Commit finalization did not finish")
	}
	var committed, unknown int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome='commit_unknown') FROM service_update_audit_events`).Scan(&committed, &unknown))
	require.Equal(t, 1, committed)
	require.Equal(t, 1, unknown)
	require.EqualValues(t, 1, c.businessCommits.Load())
	require.False(t, c.failureBeforeRelease.Load())
	t.Log("real COMMIT began and completed before cancellation; delayed acknowledgement is a seam, uncertainty never replays the mutation")
}

func TestServiceUpdateAuditCommitWaitBound(t *testing.T) {
	h, a, ctx, _, c, _ := serviceAuditCancellationApp(t, "commit_stalled", 1)
	start := time.Now()
	done := serviceAuditStartCancellation(a, ctx, h.UUID("service-b"))
	serviceAuditWaitStarted(t, c)
	select {
	case r := <-done:
		require.False(t, r.ok)
		require.ErrorContains(t, r.err, "audit persistence unavailable")
	case <-time.After(6 * time.Second):
		t.Fatal("stalled Commit wait was not bounded")
	}
	require.Less(t, time.Since(start), 6*time.Second)
	require.EqualValues(t, 1, c.begins.Load())
	require.Zero(t, serviceAuditCount(t, h))
	serviceAuditAssertLocked(t, h)
	c.unblock()
}
