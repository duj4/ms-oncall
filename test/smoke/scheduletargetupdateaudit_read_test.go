package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/test/smoke/harness"
)

// The first row is read from real PG; a controlled driver read error follows.
// No fake rows are supplied, and this is not a server/network fault claim.
type u03ReadConnector struct {
	driver.Connector
	read atomic.Int64
}

func (c *u03ReadConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &u03ReadConn{Conn: conn, c: c}, nil
}

type u03ReadConn struct {
	driver.Conn
	c *u03ReadConnector
}

func (c *u03ReadConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *u03ReadConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *u03ReadConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *u03ReadConn) Prepare(q string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), q)
}
func (c *u03ReadConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	s, err := c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	q = strings.ToLower(strings.Join(strings.Fields(q), " "))
	return &u03ReadStmt{Stmt: s, c: c.c, selected: strings.Contains(q, "from schedule_rules") && strings.Contains(q, "order by created_at, id")}, nil
}

type u03ReadStmt struct {
	driver.Stmt
	c        *u03ReadConnector
	selected bool
}

func (s *u03ReadStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	r, err := s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	if err == nil && s.selected {
		return &u03ReadRows{Rows: r, c: s.c}, nil
	}
	return r, err
}

type u03ReadRows struct {
	driver.Rows
	c *u03ReadConnector
	n int
}

func (r *u03ReadRows) Next(dst []driver.Value) error {
	if r.n == 1 {
		return errors.New("controlled error after one native row")
	}
	err := r.Rows.Next(dst)
	if err == nil {
		r.n++
		r.c.read.Add(1)
	}
	return err
}

func TestScheduleTargetUpdateNativePartialReadBarrier(t *testing.T) {
	h := u03Harness(t)
	root, target := h.UUID("schedule-a"), u03Target(t, h, "user")
	for i := range 3 {
		u03Rule(t, h, root, target, i)
	}
	before := u03IDs(t, h, "schedule_rules")
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	c := &u03ReadConnector{Connector: stdlib.GetConnector(*cfg)}
	db := sql.OpenDB(c)
	defer db.Close()
	a := u03FaultApp(t, db)
	_, err = a.Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
	require.Error(t, err)
	require.EqualValues(t, 1, c.read.Load())
	require.Equal(t, before, u03IDs(t, h, "schedule_rules"))
	require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
	require.Zero(t, u03Count(t, h))
	t.Log("one real PG row then controlled driver read failure: no DELETE, no partial witness, full rule set preserved")
}

func TestScheduleTargetUpdateNativeCommitRejection(t *testing.T) {
	h := u03Harness(t)
	root, target := h.UUID("schedule-a"), u03Target(t, h, "user")
	id := u03Rule(t, h, root, target, 0)
	_, err := h.App().DB().Exec(`CREATE FUNCTION u03_reject_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_DEFERRED';END$$; CREATE CONSTRAINT TRIGGER u03_reject_commit AFTER DELETE ON schedule_rules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION u03_reject_commit()`)
	require.NoError(t, err)
	_, err = u03App(h).Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
	require.Error(t, err)
	require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
	require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
	require.Zero(t, u03Count(t, h))
	var outcome, reason, effects string
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code,effects::text FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget'`).Scan(&outcome, &reason, &effects))
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "commit_rejected", reason)
	require.Equal(t, "[]", effects)
}
