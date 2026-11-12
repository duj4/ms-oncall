package smoke

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This wrapper observes native PostgreSQL operations. Gates run with no active
// native Rows. The explicit queryHook fault tests can interrupt or corrupt a
// returned page/identity; lock tests use unmodified native PostgreSQL rows.
type sd8Connector struct {
	queryHook       func(context.Context, driver.Conn, string, []driver.NamedValue) (driver.Rows, error, bool)
	beforeExec      func(context.Context, driver.Conn, string, []driver.NamedValue) error
	afterExec       func(context.Context, driver.Conn, string) error
	beforeCommit    func(context.Context, driver.Conn) error
	base            driver.Connector
	beforeDelete    func(context.Context, driver.Conn) error
	afterEntry      func(context.Context, driver.Conn) error
	begins, commits atomic.Int64
	mu              sync.Mutex
	trace           []string
}

func (c *sd8Connector) Driver() driver.Driver { return c.base.Driver() }
func (c *sd8Connector) Connect(ctx context.Context) (driver.Conn, error) {
	native, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &sd8Conn{Conn: native, owner: c}, nil
}

type sd8Conn struct {
	driver.Conn
	owner *sd8Connector
}

func (c *sd8Conn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	c.owner.begins.Add(1)
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
	if err != nil {
		return nil, err
	}
	return &sd8Tx{Tx: tx, owner: c.owner, native: c.Conn, ctx: ctx}, nil
}

type sd8Tx struct {
	native driver.Conn
	ctx    context.Context
	driver.Tx
	owner *sd8Connector
}

func (tx *sd8Tx) Commit() error {
	tx.owner.commits.Add(1)
	if tx.owner.beforeCommit != nil {
		if err := tx.owner.beforeCommit(tx.ctx, tx.native); err != nil {
			return err
		}
	}
	return tx.Tx.Commit()
}
func (c *sd8Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.owner.beforeExec != nil {
		if err := c.owner.beforeExec(ctx, c.Conn, q, args); err != nil {
			return nil, err
		}
	}
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err == nil && c.owner.afterExec != nil {
		err = c.owner.afterExec(ctx, c.Conn, q)
	}
	if err == nil && strings.HasPrefix(q, "SELECT pg_advisory_xact_lock(") && c.owner.afterEntry != nil {
		err = c.owner.afterEntry(ctx, c.Conn)
	}
	return result, err
}
func (c *sd8Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.owner.queryHook != nil {
		if rows, err, handled := c.owner.queryHook(ctx, c.Conn, q, args); handled {
			return rows, err
		}
	}
	if strings.HasPrefix(q, "DELETE FROM users WHERE id=$1 RETURNING") && c.owner.beforeDelete != nil {
		if err := c.owner.beforeDelete(ctx, c.Conn); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(q, "UPDATE rotation_participants SET user_id=") || strings.HasPrefix(q, "DELETE FROM rotation_participants WHERE id=") {
		op := "update"
		if strings.HasPrefix(q, "DELETE") {
			op = "delete"
		}
		entry := fmt.Sprint(op, ":", args[0].Value)
		c.owner.mu.Lock()
		c.owner.trace = append(c.owner.trace, entry)
		c.owner.mu.Unlock()
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *sd8Conn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

func sd8NativePID(ctx context.Context, c driver.Conn) (int, error) {
	rows, err := c.(driver.QueryerContext).QueryContext(ctx, `SELECT pg_backend_pid()`, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	values := make([]driver.Value, 1)
	if err = rows.Next(values); err != nil {
		return 0, err
	}
	pid, ok := values[0].(int64)
	if !ok {
		return 0, io.ErrUnexpectedEOF
	}
	return int(pid), nil
}
func sd8PGConnector(raw string) (*sd8Connector, error) {
	cfg, err := pgx.ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	return &sd8Connector{base: stdlib.GetConnector(*cfg)}, nil
}
