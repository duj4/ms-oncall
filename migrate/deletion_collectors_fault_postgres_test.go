package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
)

type deletionReadTrace struct {
	mu                                 sync.Mutex
	queries                            []string
	begins, commits, rollbacks, writes int
	failQuery                          int
	failStream                         bool
}

type deletionReadConnector struct {
	driver.Connector
	trace *deletionReadTrace
}

func (c deletionReadConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return deletionReadConn{Conn: conn, trace: c.trace}, nil
}

type deletionReadConn struct {
	driver.Conn
	trace *deletionReadTrace
}

func (c deletionReadConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.trace.mu.Lock()
	c.trace.begins++
	c.trace.mu.Unlock()
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return deletionReadTx{Tx: tx, trace: c.trace}, nil
}
func (c deletionReadConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.trace.mu.Lock()
	c.trace.queries = append(c.trace.queries, query)
	fail := len(c.trace.queries) == c.trace.failQuery
	stream := c.trace.failStream && strings.Contains(query, "AS facts")
	if stream {
		c.trace.failStream = false
	}
	c.trace.mu.Unlock()
	if fail {
		return nil, errors.New("SYNTHETIC_PRIVATE_QUERY_FAILURE")
	}
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil || !stream {
		return rows, err
	}
	return &deletionFailRows{Rows: rows}, nil
}
func (c deletionReadConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.trace.mu.Lock()
	c.trace.writes++
	c.trace.mu.Unlock()
	return nil, errors.New("unexpected collector write")
}

type deletionReadTx struct {
	driver.Tx
	trace *deletionReadTrace
}

func (tx deletionReadTx) Commit() error {
	tx.trace.mu.Lock()
	tx.trace.commits++
	tx.trace.mu.Unlock()
	return tx.Tx.Commit()
}
func (tx deletionReadTx) Rollback() error {
	tx.trace.mu.Lock()
	tx.trace.rollbacks++
	tx.trace.mu.Unlock()
	return tx.Tx.Rollback()
}

type deletionFailRows struct {
	driver.Rows
	read bool
}

func (rows *deletionFailRows) Next(values []driver.Value) error {
	if rows.read {
		return errors.New("SYNTHETIC_PRIVATE_STREAM_FAILURE")
	}
	rows.read = true
	return rows.Rows.Next(values)
}

func TestPostgresDeletionCollectorsReadOnlyAndFaults(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionCollectorsTest")
	before := deletionSnapshot(t, ctx, db)
	root := ds.Resource{Kind: ds.ResourceService, ID: f.service.String()}
	for _, name := range []string{"success", "query-failure", "stream-failure", "authorization-denied"} {
		t.Run(name, func(t *testing.T) {
			config, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			trace := &deletionReadTrace{}
			if name == "query-failure" {
				trace.failQuery = 4
			}
			if name == "stream-failure" {
				trace.failStream = true
			}
			wrapped := sql.OpenDB(deletionReadConnector{Connector: stdlib.GetConnector(*config), trace: trace})
			wrapped.SetMaxOpenConns(1)
			defer wrapped.Close()
			tx, err := wrapped.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			authorize := authorizeDeletionFixture(root)
			if name == "authorization-denied" {
				authorize = func(context.Context, *sql.Tx, collector.Target) error {
					return errors.New("SYNTHETIC_PRIVATE_AUTHORIZATION_REASON")
				}
			}
			result, err := collector.Collect(ctx, tx, root, collector.Preview, collector.Limits{}, authorize)
			if name == "success" {
				require.NoError(t, err)
				require.Equal(t, ds.DependenciesComplete, result.Collection.Completeness)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
				require.NotEqual(t, ds.DependenciesComplete, result.Collection.Completeness)
				require.Empty(t, result.Collection.Dependencies)
				require.Empty(t, result.Collection.Checked)
				require.Empty(t, result.ScopeFingerprint)
			}
			trace.mu.Lock()
			begins, commits, rollbacks, writes := trace.begins, trace.commits, trace.rollbacks, trace.writes
			queries := append([]string(nil), trace.queries...)
			trace.mu.Unlock()
			require.Equal(t, 1, begins)
			require.Zero(t, commits)
			require.Zero(t, rollbacks)
			require.Zero(t, writes)
			for _, query := range queries {
				u := strings.ToUpper(strings.TrimSpace(query))
				require.True(t, strings.HasPrefix(u, "SELECT ") || strings.HasPrefix(u, "WITH "))
				for _, forbidden := range []string{"FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE", "INSERT ", "DELETE ", "UPDATE ", "SET_CONFIG", "NEXTVAL"} {
					require.NotContains(t, u, forbidden)
				}
			}
			require.NoError(t, tx.Rollback())
		})
	}
	require.Equal(t, before, deletionSnapshot(t, ctx, db))
}
