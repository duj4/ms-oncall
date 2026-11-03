package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/service"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

// Adapted from the independent R2-F01-01 probe. Only physical driver Close
// timing is simulated; PostgreSQL Commit and its successful ACK are unaltered.
// This does not simulate a production network failure.
type serviceAuditCloseConnector struct {
	base                       driver.Connector
	armed                      atomic.Bool
	begins, commits, commitOK  atomic.Int64
	started, release, finished chan struct{}
	once                       sync.Once
}

func (c *serviceAuditCloseConnector) unblock()              { c.once.Do(func() { close(c.release) }) }
func (c *serviceAuditCloseConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *serviceAuditCloseConnector) Connect(ctx context.Context) (driver.Conn, error) {
	x, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &serviceAuditCloseConn{Conn: x, c: c}, nil
}

type serviceAuditCloseConn struct {
	driver.Conn
	c *serviceAuditCloseConnector
}

func (c *serviceAuditCloseConn) Close() error {
	if c.c.armed.CompareAndSwap(true, false) {
		close(c.c.started)
		<-c.c.release
		defer close(c.c.finished)
	}
	return c.Conn.Close()
}
func (c *serviceAuditCloseConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	x, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	c.c.begins.Add(1)
	return &serviceAuditCloseTx{Tx: x, c: c.c}, nil
}
func (c *serviceAuditCloseConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}
func (c *serviceAuditCloseConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *serviceAuditCloseConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

type serviceAuditCloseTx struct {
	driver.Tx
	c *serviceAuditCloseConnector
}

func (tx *serviceAuditCloseTx) Commit() error {
	tx.c.commits.Add(1)
	err := tx.Tx.Commit()
	if err == nil {
		tx.c.commitOK.Add(1)
	}
	return err
}

func TestServiceUpdateAuditAcknowledgedCommitCleanup(t *testing.T) {
	for _, slow := range []bool{false, true} {
		name := "fast_close_control"
		if slow {
			name = "slow_close_after_ack"
		}
		t.Run(name, func(t *testing.T) {
			h := serviceAuditHarness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			var dbName string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&dbName))
			cfg, err := pgx.ParseConfig(harness.DBURL(dbName))
			require.NoError(t, err)
			c := &serviceAuditCloseConnector{base: stdlib.GetConnector(*cfg), started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			db := sql.OpenDB(c)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() {
				c.unblock()
				require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 }, 5*time.Second, time.Millisecond)
				require.NoError(t, db.Close())
			})
			store, err := service.NewStore(context.Background(), db)
			require.NoError(t, err)
			db.SetMaxIdleConns(0) // Supported pool setting forces physical Close.
			c.armed.Store(slow)
			logger := log.NewLogger()
			logger.EnableJSON()
			var captured bytes.Buffer
			logger.SetOutput(&captured)
			ctx := log.SetRequestID(log.WithLogger(servicePlatformAdminContext(t, h), logger))
			description := "SYNTHETIC_POSTCOMMIT_DESCRIPTION"
			private := log.Fields{
				"SessionID":  "SYNTHETIC_POSTCOMMIT_SESSION",
				"SourceInfo": "SYNTHETIC_POSTCOMMIT_SOURCE",
				"Token":      "SYNTHETIC_POSTCOMMIT_TOKEN",
				"SQLDetail":  "SYNTHETIC_POSTCOMMIT_SQL_DETAIL",
			}
			ctx = log.WithFields(ctx, private)
			a := graphqlapp.App{DB: db, ServiceStore: store}
			start := time.Now()
			ok, operationErr := a.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: h.UUID("service-b"), Description: &description})
			elapsed := time.Since(start)
			require.EqualValues(t, 1, c.commits.Load())
			require.EqualValues(t, 1, c.commitOK.Load(), "native Commit returned nil before cleanup")
			var actual string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM services WHERE id=$1`, h.UUID("service-b")).Scan(&actual))
			require.Equal(t, description, actual)
			var committed, failed int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome<>'committed') FROM service_update_audit_events`).Scan(&committed, &failed))
			require.Equal(t, 1, committed)
			require.Zero(t, failed)
			require.EqualValues(t, 1, c.begins.Load(), "no replay or independent failure append")
			if slow {
				select {
				case <-c.started:
				default:
					t.Fatal("driver Close seam was not entered")
				}
				select {
				case <-c.finished:
					t.Fatal("driver Close must still be blocked at the bounded return")
				default:
				}
				require.GreaterOrEqual(t, elapsed, 2*time.Second)
				require.Less(t, elapsed, 4*time.Second)
				probe, err := h.App().DB().Begin()
				require.NoError(t, err)
				_, err = probe.Exec(`SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("service-b"))
				require.NoError(t, err, "independent connection proves business transaction ended")
				require.NoError(t, probe.Rollback())
				// Always release the seam before asserting the API/log contract, so
				// RED runs also leave no test-owned connection or cleanup behind.
				c.unblock()
				select {
				case <-c.finished:
				case <-time.After(5 * time.Second):
					t.Fatal("test Close did not terminate")
				}
				require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 && db.Stats().InUse == 0 }, 5*time.Second, time.Millisecond)
				t.Logf("PG witness: native Commit nil=1, business update=1, committed audit=1, failure/unknown=0, begins=1; elapsed=%s; API=(%t,%v); cleanup exited and pool open/in-use=0", elapsed, ok, operationErr)
				require.NoError(t, operationErr, "acknowledged durable success must survive cleanup timeout")
				require.True(t, ok)
				var fault map[string]any
				require.NoError(t, json.Unmarshal(captured.Bytes(), &fault))
				require.Equal(t, "error", fault["level"])
				require.Equal(t, "resource_release_unconfirmed", fault["AuditFault"])
				require.Equal(t, "committed", fault["AuditOutcome"])
				require.Equal(t, "service.update", fault["AuditOperation"])
				require.Equal(t, "service.update committed; resource release unconfirmed", fault["error"])
				var eventID, attemptID, requestID string
				require.NoError(t, h.App().DB().QueryRow(`SELECT event_id,attempt_id,request_id FROM service_update_audit_events`).Scan(&eventID, &attemptID, &requestID))
				require.Equal(t, eventID, fault["AuditEventID"])
				require.Equal(t, attemptID, fault["AuditAttemptID"])
				require.Equal(t, requestID, fault["AuditRequestID"])
				require.Equal(t, log.RequestID(ctx), requestID)
				require.NotContains(t, captured.String(), "audit persistence unavailable")
				require.NotContains(t, captured.String(), description)
				for field, sentinel := range private {
					require.NotContains(t, fault, field)
					require.NotContains(t, captured.String(), sentinel)
				}
				t.Logf("safe cleanup fault: %s", captured.String())
			} else {
				require.NoError(t, operationErr)
				require.True(t, ok)
				require.Empty(t, captured.String())
				t.Log("CONTROL: native Commit nil=1, persisted business/committed audit=1, failure/unknown=0, API=true/nil, no cleanup fault")
			}
			require.NotContains(t, serviceAuditRows(t, h), description)
		})
	}
}
